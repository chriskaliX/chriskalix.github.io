---
layout: post
title:  Dive into Elkeid v1.9.1
description: Dive into Elkeid v1.9.1
summary: Dive into Elkeid v1.9.1
tags: security
minute: 60
---

# 简介

前段时间 Elkeid team 更新了 v1.9.1 版本，各个重要组件均有很多的更新，也解决了之前 issue 中很多的问题。作为学习以及 Hades 的借鉴，我们还是继续学习一下 Elkeid 源码，Learn from the best

## Agent

### UUID 计算

改动部分主要为

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

还有 `/sys/class/dmi/id/product_name` 这部分的校验，这些我之前没想到过 :(，可能因为公司内部的机器数量较少，基本不会碰到 UUID 冲突的问题

BAD UUID 的case其实还有一些，一些工具会自己维护一份

### Agent 更新
