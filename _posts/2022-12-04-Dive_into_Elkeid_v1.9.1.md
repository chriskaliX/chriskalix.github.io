---
layout: post
title:  Elkeid v1.9.1（初步学习版）
description: Dive into Elkeid v1.9.1
summary: Dive into Elkeid v1.9.1
tags: security
minute: 60
---

## 简介

前段时间 Elkeid team 更新了 v1.9.1 版本，各个重要组件均有很多的更新，也解决了之前 issue 中很多的问题。我们还是继续学习一下 Elkeid 源码

## 1. Agent

> Agent 部分略读，可能有部分没有覆盖到

### 1.1. UUID 计算

改动部分主要为：增加了 pdid 的校验

```go
if len(source) > 8 &&
    string(pdid) != "03000200-0400-0500-0006-000700080009" &&
    string(pdid) != "02000100-0300-0400-0005-000600070008" {
    pname, err := fromIDFile("/sys/class/dmi/id/product_name")
    if err == nil && len(pname) != 0 &&
        !bytes.Equal(pname, []byte("--")) &&
        !bytes.Equal(pname, []byte("unknown")) &&
        !bytes.Equal(pname, []byte("To be filled by O.E.M.")) &&
        !bytes.Equal(pname, []byte("OEM not specify")) &&
        !bytes.Equal(bytes.ToLower(pname), []byte("t.b.d")) {
        ID = uuid.NewSHA1(uuid.NameSpaceOID, source).String()
    }
    return
}
```

其中的 pdid 为 `/sys/class/dmi/id/product_uuid` 中读取。这个 ID 好像在哪里见过，我们看一下 osquery 的源码，就能发现如下：

```c++
const std::vector<std::string> kPlaceholderHardwareUUIDList{
    "00000000-0000-0000-0000-000000000000",
    "03000200-0400-0500-0006-000700080009",
    "03020100-0504-0706-0809-0a0b0c0d0e0f",
    "10000000-0000-8000-0040-000000000000",
};
```

都有一个类似的白名单，整理一下每个白名单都对应着啥

|UUID|Description|
|:-:|:-:|
|03000200-0400-0500-0006-000700080009|一些主板厂商的默认设置，比如Gigabyte的，同时serial-number 显示为 To be filled by O.E.M.|
|02000100-0300-0400-0005-000600070008|一些KVM启动的机器会有这个类似的UUID|
|00000000-0000-0000-0000-000000000000|看起来是 BIOS 设置问题|
|03020100-0504-0706-0809-0a0b0c0d0e0f|-|
|10000000-0000-8000-0040-000000000000|-|

还有 `/sys/class/dmi/id/product_name` 这部分的校验，这些我之前没想到过，可能因为我所在公司内部的机器数量较少，基本不会碰到 UUID 冲突的问题。BAD UUID 的case其实还有一些，一些工具会自己维护一份

### 1.2. Agent 自更新

更新的部分主要分为 `Download`、`Decompress` 以及启动部分，在 Elkeid v1.9.1 中三个部分均有小改动

#### Download 变更

> 主要包含 client 变更，resp.Body 限制, io.TeeReader 方式优化

- Client

之前下载超时由一个 subctx 控制，目前是直接采取设置 Client Timeout 的方式，配置如下

```go
client := &http.Client{
    Transport: &http.Transport{
        Dial: (&net.Dialer{
            Timeout:   15 * time.Second,
            KeepAlive: 30 * time.Second,
        }).Dial,
        ForceAttemptHTTP2:     true,
        MaxIdleConns:          100,
        IdleConnTimeout:       90 * time.Second,
        TLSHandshakeTimeout:   10 * time.Second,
        ExpectContinueTimeout: 1 * time.Second,
    },
    Timeout: time.Minute * 10,
}
```

其中 `Transport` 的配置和 `http.DefaultTransport` 相比，应该是只有 Timeout 的部分变短（从 30 -> 15）

- resp.Body 限制

增加了文件最大读取的 size，应该是防止出现意外下载过大文件，导致所有下发升级的机器磁盘堆满，client side 的安全措施（我猜的）

```go
resp.Body = http.MaxBytesReader(nil, resp.Body, 512*1024*1024)
```

- io.TeeReader

对比一下之前的方式，Elkeid v1.7.1:

```go
buf, err = ioutil.ReadAll(resp.Body)
if err != nil {
    continue
}
hasher.Reset()
hasher.Write(buf)
if !bytes.Equal(hasher.Sum(nil), checksum) {
    err = errors.New("checksum doesn't match")
    continue
} else {
    br := bytes.NewBuffer(buf)
    switch config.Type {
    case "tar.gz":
        err = DecompressTarGz(dst, br)
    default:
        err = DecompressDefault(dst, br)
    }
    break
}
```

之前版本，将整个 resp.Body 通过 `ioutil.RealAll` 的方式读取全部至内存，下发的时候会有一个内存上升的问题，如果连续下发多个还有可能会触发 cgroup 被 kill （因为Hades Agent完全按照Elkeid来，之前有类似的情况）。新版本代码如下：

```go
resp.Body = http.MaxBytesReader(nil, resp.Body, 512*1024*1024)
hasher.Reset()
r := io.TeeReader(resp.Body, hasher)
switch config.Type {
case "tar.gz":
    err = DecompressTarGz(r, filepath.Dir(dst))
default:
    f, err = os.OpenFile(dst, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o0700)
    if err == nil {
        _, err = io.Copy(f, r)
        f.Close()
    }
}
resp.Body.Close()
if err == nil {
    if checksum := hex.EncodeToString(hasher.Sum(nil)); checksum != config.Sha256 {
        err = fmt.Errorf("checksum doesn't match: %s vs %s", checksum, config.Sha256)
    } else {
        break
    }
}
```

io.TeeReader 可以看作是一次优化，不再全部 dump 到内存中，简单写了一个粗糙的 Benchmark 模拟，结果如下

```
goos: linux
goarch: amd64
pkg: agent/utils
cpu: Intel(R) Xeon(R) CPU E5-26xx v4
BenchmarkDownloadOld-2                 9         118909617 ns/op        81999175 B/op        138 allocs/op
BenchmarkDownloadNew-2                15          82094187 ns/op           47442 B/op         93 allocs/op
PASS
ok      agent/utils     3.441s
```

- Decompress

新增一个 Limiter, 解压的逻辑部分改动, 不展开说了

```go
zr, err := gzip.NewReader(io.LimitReader(r, 512*1024*1024))
```

### 1.3. sync.Pool 优化

之前磊哥提到过这个问题 - [Go issue-23199](https://github.com/golang/go/issues/23199)，简单描述为sync.Pool 碰到动态增长的大 buffer 会导致内存无法回收，从而导致无限增长的问题。解决方法就是对 []byte 做分批处理，或者是直接丢弃掉这个 []byte 等着被 GC 掉。下面是 Elkeid 的代码

```go
pools = [...]sync.Pool{
    {New: func() any {
        return &proto.EncodedRecord{
            Data: make([]byte, 0, defaultCap),
        }
    }},
    {New: func() any {
        return &proto.EncodedRecord{
            Data: make([]byte, 0, defaultCap*2),
        }
    }}, {New: func() any {
        return &proto.EncodedRecord{
            Data: make([]byte, 0, defaultCap*3),
        }
    }},
    {New: func() any {
        return &proto.EncodedRecord{
            Data: make([]byte, 0, defaultCap*4),
        }
    }},
}
```

顺便看了一眼好像 `zap` 下有个类似的 [issue](https://github.com/uber-go/zap/issues/1130) 

### 1.4. Heartbeat 更新

Cpu/Mem 逻辑问题修正，linux 下新增 `host_serial`、`dns`、`gateway` 等

### 1.5. Plugin

新增插件名称合法性校验，shutdown 标识位

### 1.6. Agent 状态

目前看来暂时只有 running 和 abnormal，应该方便集群主动查询

### 1.7. Main 函数

之前通过 DEBUG 来控制 pprof 的方式，现在变更监听 3 个信号

### 1.8. Deploy 部分更新

- cgroup 挂载重启失效问题修复 (sysvinit)

https://github.com/bytedance/Elkeid/issues/319，将这部分逻辑判断放置 `elkeidctl` 中了。

```go
signal.Notify(sigs, syscall.SIGTERM, syscall.SIGUSR1, syscall.SIGUSR2)
```

相比之前更加灵活了，SIGUSR1 用于 pprof 的启停， SIGUSR2 用于强制触发内存回收

## 2. Collector 插件

> Collector 插件本次更新除了增加了容器、fatjar 等，还重构改进了代码结构，逻辑非常清晰，推荐大家仔细阅读，在这里就先不赘述 engine 调度的逻辑了

### 2.1. 新增资产采集

`app.go` 支持了多种应用的采集，包括如下：

```go
ruleMap = map[string]*AppRule{
    "apache2":         apacheRule,
    "httpd":           apacheRule,
    "nginx":           nginxRule,
    "redis-server":    redisRule,
    "rabbitmq-server": rabbitmqRule,
    "grafana-server":  grafanaRule,
    "mysqld":          mysqlRule,
    "postgres":        postgresqlRule,
    "mongod":          mongodbRule,
    "etcd":            etcdRule,
    "prometheus":      prometheusRule,
    "sqlservr":        sqlserverRule,
    "php-fpm":         phpfpmRule,
    "dockerd":         dockerRule,
    "containerd":      containerdRule,
    "kubelet":         kubeletRule,
}
```

大致的采集逻辑是循环 `/proc/` 目录 pid，从进程的根文件系统 `/proc/<pid>/root` 去读取上述资产。是一个支持区分容器环境的资产采集

### 2.2. Integrity 采集

dpkg / rpm 信息采集，解析还是有一定代码量的，注意里面的 io 限流。跟小黑猪同学沟通，暂时不理解为啥不采集容器内的

### 2.3. Container 采集

> 一些默认的容器运行时套接字，也是 kubernetes 中的 [constants](https://github.com/kubernetes/kubernetes/blob/8a259641532d12f730d0fc6b237d36206d405e52/cmd/kubeadm/app/constants/constants_unix.go)

```go
for _, path := range []string{
    "unix:///run/containerd/containerd.sock",
    "unix:///run/crio/crio.sock",
    "unix:///var/run/cri-dockerd.sock",
} {
```

`dockershim` 这种应该情况不用再覆盖

两种 client 的方式，分别为 `criClient` 以及 `dockerClient`。

### 2.4. Process 采集

Process 采集和之前版本有较大变动，增加了很多如 namespace, status 详细信息，抽象到结构体函数下，代码比之前清晰了许多

### 2.5. Software 采集

Software 主要感兴趣的部分是 Jar 的部分。主要代码在 `findJar` 部分，根据 Jar 包名称获取 name 以及 sversion，通过在 `META-INF/MANIFEST.MF` 中读取 `Implementation-Version:` 来确定 version，这里也是区分容器的

### 2.6. Service 采集

Elkeid 中通过遍历解析获取

```go
var SearchDir = []string{
	"/etc/systemd/system.control", "/run/systemd/system.control", "/run/systemd/transient",
	"/run/systemd/generator.early", "/etc/systemd/system", "/run/systemd/system",
	"/run/systemd/generator", "/usr/local/lib/systemd/system", "/usr/lib/systemd/system", "/run/systemd/generator.late"}
```

在 Osquery 中，好像是 dbus 相关的请求和解析，具体的后面再详细分析

## 3. Baseline

还没看...

## ...

暂时还没写完，只看到 collector 的部分，中间应该也有不对的地方，待我慢慢咀嚼...
