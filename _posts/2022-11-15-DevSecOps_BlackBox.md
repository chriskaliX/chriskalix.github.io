---
layout: post
title:  DevSecOps BlackBox
description: DevSecOps BlackBox
summary: DevSecOps BlackBox
tags: security
minute: 20
---

# 简介

黑盒扫描是 DevSecOps 中较为重要的一环，往往也是 SDL 建设初期最先配备，效果最好的安全工具。本文为工作记录的随笔，比较潦草不细节，主要是怕忘记了

# 概要

> 本文将从以下几个部分开始讨论

- 黑盒扫描架构
    - 流量镜像
    - 消息去重
    - 扫描 Payload
    - 企业特性适配
    - API 生命周期
- 资产管理
- 问题管理
    - 脏数据

# 黑盒扫描架构

## 流量镜像

> 流量镜像通过在 Nginx 下加载 Lua 的形式，将数据包提取传输，demo 如下

init_phase - 跳过

access_phase

```lua
local data = {}
data["time"] = ngx.now()
data["scheme"] = ngx.var.scheme
data["uri"]=ngx.var.uri 
data["client_ip"] = ngx.var.remote_addr
data["args"]=ngx.var.args
data["host"]=ngx.var.host

data["method"]= ngx.req.get_method() 
if data["method"] == "POST" then
	if (ngx.req.get_body_file() == nil) then
		data["post_data"] = ngx.req.get_body_data()
	end
end

local headers, err = ngx.req.get_headers()
if err ~= "truncated" then
    -- 防止流量黑洞，在 Iast 扫描添加特殊标识过滤
	if not head["Iast"] then
		data["headers"] = headers
		data["resp_headers"] = ngx.resp.get_headers()
	else
		return
	end
end

-- move to worker if you need
local async_producer = producer:new(broker_list, {producer_type = "async",request_timeout = 10000})
local message = dkjson.encode(data)
local ok, err = async_producer:send("iast", nil, message)
if not ok then
	debug(err)
end
```

body_filter_by_lua_file （敏感信息检测，先不放了）

```lua

```

## 消息去重

根据五元组进行过滤，分别为

- METHOD
- SCHEMA
- HOST (WITH PORT)
- PATH
- PARAMS

用 `Bloom filter` 过滤，理想汽车的 `DevSecOps` 文章里也是这么说的。其实也要考虑到 `API` 应用自身的问题，在接口五元组不变的情况下，内部逻辑仍有可能发生变化从而产生漏洞（例如下游接口变更等），每个接口需要有一个 TTL，所以方法逻辑如下

1. 获取五元组，以及对应的 HASH
2. 缓存这个 Hash，给定 TTL

在接口数量不大的情况下，不用布隆过滤器也可以

## 扫描 Payload

这个其实比较定制化，对于大部分的漏洞扫描，都能在单次请求中完成判断，不需要多个报文上下文的形式。这里分类讨论

因为扫描 Payload 这个部分，大部分情况可能需要自己去做。因为目前能看到的 xray 或者 AWVS 还是接管了整个扫描流程（即报文拆解，Payload 注入，报文拼接，漏洞判断），但是甲方的这种特质场景下，往往需要自己介入大部分流程。

例如报文的解析，如果是 AES 加密需要先做解密，如果有 timestamp 或者 sign 校验需要手动构成等等

看起来像是造轮子，其实轮子也是可以抽象的，按照上面步骤做成 plugin 即可

### SQL Injection

> 不光是 SQL 注入，[stamparm](https://github.com/stamparm) 这个小哥很多的 Payload 很有意思，方便直接提取使用

简单来说，如果根据 SQLMap 的话，SQL 注入可以分为很多种，BEUSTQ

- Boolean
- Error
- Union
- Stack
- Time-based

如果抽象简化一下，可以变成：

1. 基于报错的
	插入 Payload，匹配返回内容
2. 基于布尔的
	可以看一下 SQLMap 源码，有一个页面相似度的检测，记得好像是 `0.96` 认为是相似的，很早以前看过，挺有意思
3. 基于时间的
	这个其实比较简单， Time-based，有可能会有误报多的情况。发送多次即可

### XSS

XSS经典题目之，XSS分类

- Dom-based
- Reflect
- Store

反射通过 chrome driver 或者匹配的形式检索可在单个包的上下文完成。Dom 的有一点特殊，后续可以展开讲（通过 source / sink 的方式，或者避免危险 sink 的方式）[相关文章](https://medium.com/@fath3ad.22/understanding-dom-based-xss-sources-and-sinks-c17ae4bc7455)

Store-based则通过反连平台判断，单个请求的上下文无法判断

### RCE / LFI ...

> 本质上和上述同理

Payload 搜集，单个上下文的判断

## 企业特性适配

> 为什么 xray / awvs 这种无法无缝接入，肯定也是有原因的...

企业内为了保证接口安全，通常会有反重放、加密、混淆等，通常 H5 的请求和 App 的请求等，处理也会不同。相当于在扫描器的前后，我们需要两个 Interface，处理掉解密加密的过程，这里没有什么特殊的地方，重点是需要去做适配

## API 管理 & 生命周期

> API资源本身的集中化管理，对安全来说是非常宝贵的数据

接口生命周期事实上跟黑盒关系不是很大，我们从黑盒安全这个相对狭隘的角度窥测一下。我们要尽可能丰富 API 维度的数据，从 API 的上线时间，调用频次，返回信息打标，请求信息打标。黑盒以及IAST是为数不多的能直接对接口建立完整数据的工具，很多时候如果黑盒仅仅只是拿来扫描，会丧失掉很多有价值的有意义的数据

之前汉堡也发过根据接口的 CVSS 评分，其实可以理解成一个 API 最终对应到了哪些数据操作。这个对数据安全以及后期的越权治理非常重要。方法也很简单，先根据 DB 打标（DB分级），然后根据黑盒的数据获取到全链路的请求 ID，查询最后实际操作的 DB。操作的 DB 越核心，越多，说明这个 API 越敏感。对于企业内大量级的 API，这是至关重要的

# 资产管理

跟上面 API 管理 & 生命周期有所重复了。核心就是：不要只把黑盒作为一个扫描工具

# 问题管理

## 脏数据

- 特殊标识，压测标/扫描标，在 Agent 侧 hook 数据写入丢弃
- 影子库
- ...
