---
layout: post
title: Java 安全小计
description: Java 安全小计
summary: Java 安全小计
tags: security
minute: 60
---

## 写在前面

之前写过一篇 Java [安全学习笔记](https://chriskaliX.github.io/assets/imgs/java_security_old.pdf)，记的比较乱，原先的文字版也由于没有维护找不到了，遂重新记录一下，有很老的漏洞，也有稍微新一点的，结合实际工作中碰到的一些问题，作为学习记录

## 漏洞记录

### Fastjson

> Fastjson 是 Java 很著名的一个漏洞系列，但是时间一长很容易忘记，重新记录作为备忘。这回记录的尽量简单明了一点

#### 1.2.24

Fastjson 漏洞首次出现，也是最经典的 `@type` 字段首次出现，简单的 POC 如下

```java
import com.alibaba.fastjson.JSON;

public class Fastjson_1_2_24 {
    public static class Test {
        private String id;
        Test() {
            System.out.println("I am the test");
        }
        public void setId(String ids){
            System.out.println("setId go");
            this.id=ids;
        }
        public String getId(){
            System.out.println("GetId go");
            return this.id;
        }
    }

    public static void main(String[] args) {
        JSON.parseObject("{\"@type\":\"fastjson.Fastjson_1_2_24$Test\",\"id\":\"123\"}");
    }
}
```

断点打在类初始化，能看到调用堆栈，记录一些关键点

首先json是从左向右解析，LBRACE 就是 `{`

```java
case LBRACE:
    JSONObject object = new JSONObject(lexer.isEnabled(Feature.OrderedField));
    return parseObject(object, fieldName);
```

之后进入长长的 `parseObject`，`parseObject` 可以简单的看为循环的对每一个字段做解析，例如片段，对 key/value 做处理，特殊点就在于

```java
// JSON.DEFAULT_TYPE_KEY = @type
if (key == JSON.DEFAULT_TYPE_KEY && !lexer.isEnabled(Feature.DisableSpecialKeyDetect)) {
    String typeName = lexer.scanSymbol(symbolTable, '"');
    // mark
    Class<?> clazz = TypeUtils.loadClass(typeName, config.getDefaultClassLoader());

    if (clazz == null) {
        object.put(JSON.DEFAULT_TYPE_KEY, typeName);
        continue;
    }

    lexer.nextToken(JSONToken.COMMA);
    if (lexer.token() == JSONToken.RBRACE) {
        lexer.nextToken(JSONToken.COMMA);
        try {
            Object instance = null;
            ObjectDeserializer deserializer = this.config.getDeserializer(clazz);
            if (deserializer instanceof JavaBeanDeserializer) {
                instance = ((JavaBeanDeserializer) deserializer).createInstance(this, clazz);
            }

            if (instance == null) {
                if (clazz == Cloneable.class) {
                    instance = new HashMap();
                } else if ("java.util.Collections$EmptyMap".equals(typeName)) {
                    instance = Collections.emptyMap();
                } else {
                    instance = clazz.newInstance();
                }
            }

            return instance;
        } catch (Exception e) {
            throw new JSONException("create instance error", e);
        }
    }

    ...

    ObjectDeserializer deserializer = config.getDeserializer(clazz);
    return deserializer.deserialze(this, clazz, fieldName);
}
```

一个分界点就是在 loadClass 这个部分，后续会在类加载这部分做文章，后续利用和类加载先不在这儿讨论（RMI/LDAP...）

#### 1.2.47

后续，出现了对这种任意类加载的检查机制，同样在类加载的时候，多了一个 checkAutoType

```java
if (object != null
        && object.getClass().getName().equals(typeName)) {
    clazz = object.getClass();
} else {
    clazz = config.checkAutoType(typeName, null, lexer.getFeatures());
}

// 引入了对应的黑名单机制，顺便还给加了一下密

if (clazz == null) {
    clazz = TypeUtils.getClassFromMapping(typeName);//将typeName作为key从mappings(ConcurrentMap对象)中查找对象,这个相当于从cache取值，刚开始没有存入对象，取出值为null
}

// 这里给入 java.lang.class
if (clazz == null) {
    clazz = deserializers.findClass(typeName);// 将typeName作为key从deserializers(IdentityHashMap)中查找对象
}

if (clazz != null) {
    if (expectClass != null
            && clazz != java.util.HashMap.class
            && !expectClass.isAssignableFrom(clazz)) {
        throw new JSONException("type not match. " + typeName + " -> " + expectClass.getName());
    }

    return clazz;
}

if (!autoTypeSupport) {//判断提取的对象hash值是否在denyHashCodes，也就是黑名单过滤
    long hash = h3;
    for (int i = 3; i < className.length(); ++i) {
        char c = className.charAt(i);
        hash ^= c;
        hash *= PRIME;

        if (Arrays.binarySearch(denyHashCodes, hash) >= 0) {
            throw new JSONException("autoType is not support. " + typeName);
        }

        if (Arrays.binarySearch(acceptHashCodes, hash) >= 0) {
            if (clazz == null) {
                clazz = TypeUtils.loadClass(typeName, defaultClassLoader, false);
            }

            if (expectClass != null && expectClass.isAssignableFrom(clazz)) {
                throw new JSONException("type not match. " + typeName + " -> " + expectClass.getName());
            }

            return clazz;
        }
    }
}

if (clazz == null) {
    clazz = TypeUtils.loadClass(typeName, defaultClassLoader, false);
}

//省略部分代码
return clazz;
```

其实跟之前不一样，需要有两个键值对的方式，就是因为要使用 mapping 缓存机制，在第一次循环的时候把恶意这个类给加载到缓存，在第二次运行到 `getClassFromMapping` 的时候，就直接返回了，绕过了下面的黑名单检查（虽然黑名单检查本身就不对...）

#### 1.2.68

持续最长的一个问题，当然除了 1.2.83 的 Throwable 不算。黑名单的绕过机制，基于 java.lang.AutoCloseable...

### 修复

> 修复是一个大问题，有时候并不是想的那么简单...

因为公司内部有标准的发布系统，根据发布卡点 + 内部排查，版本限制并不是一个大问题，当然也有例外

#### 大数据系统

> 大数据有很多自编写的 UDF，在/离线任务，这些不经过发布系统。还有一些很老的边缘系统，通过 Nginx 直接转发到后端应用，通过梳理 nginx config，统一排查

根据 google/log4jscanner 魔改了一下，做了一个 jar 包的扫描，排除了一下历史上的问题。这个很通用，我们把历史的一些（包括 log4j）的都添加到规则内，对上传的 jar 包做检查

#### safemode

理论上升级到 68 以上，基本没有危害（Throwable 的 83也有问题，不过也有一定条件，还行）。但是，由于 inet4 还是会出网，有段时间收到 CERT 的一个整改，就是因为有人扫 inet 收到 DNS 请求，说有 fastjson 漏洞了，需要整改...其实在线上 DNS 告警中，我们看到了这个，当时不认为有利用价值，CERT 认为有，所以一咬牙我们开始推行 safemode，整个过程中还是会有个别问题... TODO

## 黑白盒检测
