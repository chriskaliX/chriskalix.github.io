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
