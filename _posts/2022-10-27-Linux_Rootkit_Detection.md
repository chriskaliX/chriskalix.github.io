---
layout: post
title:  Linux Rootkit Detection
description: Linux Rootkit Detection
summary: Linux Rootkit Detection
tags: security
minute: 15
---

文章基于 [tyton](https://nbulischeck.github.io/tyton/) 做研究学习

# 简介

之前几篇文章很潦草的介绍了一下内核后门的行为，包括不限于隐藏文件、隐藏进程、网络隐藏、knock式后门等等。Elkeid 中就采用了 tyton 中的一些模块，来做 rootkit 的检测，主要是基于行为。在阿里云的文档中，提供的 Rootkit 检测方案似乎是基于内存取证，这块了解较少，暂时不做深入

# 检测方式 & eBPF 代码编写思路

## Hidden Kernel Module Detection

常见的方式，从 lsmod 或者 /proc/modules 的结果移除的方式。lsmod 本质上就是从一个内核模块链表的遍历打印，我们写一个简单内核模块，通过 list_entry 的方式去遍历获取。简单的隐蔽方式为：从 list 中，将当前模块移除，通常情况下会保留这个 list.pre 的地址，通过 list_add 的方式再将其添加回列表

![](https://nbulischeck.github.io/tyton/images/kset.svg)

在 tyton 中，通过循环便利 mod_kset->list，找出每个 kobj 中的 module，是否能通过 find_module 的形式获取的到。在 eBPF 中，这种两个循环嵌套的方式往往很容易超出指令数(100w)，因为不支持 endless loop，我们需要通过展开的方式。作为初步的解决方法，我们在一次展开后只进行计数，并与用户态进行对比。这个方法目前看来处于一个能用的状态，但是无法获取到是哪个模块隐藏了（其实也可以，稍微改一下内核代码做比对即可）

当然这个检测方法也是相对比较辅助的，因为这种从 kobj 的方式，也可以和擦除链表一样，通过 kobject_del 删除的方式进行规避。用 Elkeid 做了一个简单的测试：

1. Github 上搜索一个 demo: https://github.com/hoyleeson/toolkit (建议稍微改一下，留一个删除的后门)
2. insmod hids_driver.ko，用elkeid_decoder做简单的解码使用
3. 同时安装上 reptile 以及上述 toolkit 中的 kmod_hidden

检出结果如下

```json
{"data_type":"hidden_kernel_module","module_name":"reptile_module"}
{"data_type":"hidden_kernel_module","module_name":"reptile_module"}
```

Hades 中的检出和这个一样，都是基于 tyton 的，这个函数功能对于 kobject_del 的内核模块是不检出的。
大多数的文章和分析基本是停止到这里，我很好奇如果一个内核模块摘除了 list，摘除了 kobject，就完全无法检出了吗？问了一下群友，得到宝贵的文章[2](https://blog.csdn.net/dog250/article/details/106064940)
以及一个用于测试的[例子](https://github.com/sysprog21/lkm-hidden/blob/master/main.c)

我们先看一下隐藏是如何做到的[4](https://blog.csdn.net/dog250/article/details/106023941)，我们遗漏了：
1. /proc/vmallocinfo 中的隐藏，摘除 vmalloc 调用关系链
2. 摘除依赖关系，nf_conntrack holder 隐藏

甚至直接去 cat /proc/vmallocinfo，能看到 reptile_module 的 khook_init 地址

如何找出这些似乎完全隐藏的模块呢？

作者的答案是：扫描modules内存区间，page依然还在，通过暴力检索内存地址内的 module 来发现隐藏的模块。我的理解是，模块加载后总是会开辟内存空间，不论如何从各种链表中擦除自身痕迹，内存不会骗人...

TODO: unfinished here

## IDT/SCT Hook Detection

这个其实比较简单，在 Hades 中的方法和 tracee 一样，通过 /proc/kallsyms 的地址和内核态中 sys_call_table / idt_table 地址进行比对
能够检测出如 `Diamorphine` 这一类 hook 了系统调用的。但是对于 KHOOK 这种框架的，如 Reptile，在 tyton 项目的 issue 里也能看到有人提问，大致意思是当前无法检出 KHOOK 框架的 hook，因为他不修改 syscall 的函数指向，而是在指向的函数开头插入 asm code 来做JUMP

正如 tyton 官网的文档里，对于 Reptile 的 SCT/IDT Hooking 行为，结果是 Evaded

## Netfilter Hook Detection

netfilter 也常被用作蜜罐，也能作为 knock 式后门的一环，这里暂时 pending，在 Reptile 以及 Diamorphine 中都使用了这个作为 knock 的方法

## Network protocol Hook Detection

pending

## Process File Operations Hook Detection

这个可以支持，主要是通过 filp_open 打开 "/proc"，然后比对 fp->f_op->iterate 所指向的是否为 kernel text 区。隐藏 PID 也可以 sys_getdents[3](https://xcellerator.github.io/posts/linux_rootkits_07/)，近期会开始写一下这个，tracee 下是通过 hook security_file_permission，看下是否能做成 trigger 的形式（害怕全量 hook 会有一定影响）

# 其余思路

1. 因为 HIDS 总是先行部署，通过 hook init_module 总能发现 LKM 的加载
2. BPF 程序后门没有在上述的讨论中，其实可观测的方式也有很多，包括不限于 hook，/proc/vmallocinfo 等，且总是依赖一个用户态进程
3. 内存扫描/镜像

# 参考

- https://xcellerator.github.io/posts/linux_rootkits_05/
- https://blog.csdn.net/dog250/article/details/106064940
- https://xcellerator.github.io/posts/linux_rootkits_07/
- https://blog.csdn.net/dog250/article/details/106023941