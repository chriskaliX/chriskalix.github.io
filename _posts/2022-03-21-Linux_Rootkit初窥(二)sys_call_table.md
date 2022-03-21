---
layout: post
title: Linux Rootkit初窥(二)sys_call_table
description: Linux Rootkit初窥(二)sys_call_table
summary: Linux Rootkit初窥(二)sys_call_table
tags: security
minute: 10
---

## 书接上回

先开篇留坑，防止偷懒

## 题外话

今天公司的用户态 HIDS 上抓了一个入侵，很兴奋，很少抓到入侵:

入侵的流程很简单，由于管理疏忽有一个 PHP 的应用存在 RCE，父进程为 php-fpm 的进程执行了 sh 触发了警告，后续就是问题处置

让我更加明白了，用户态的代码可能和内核态的一样重要。对于绝大部分入侵场景来说，大部分都是在用户态层面的对抗。真正内核态的，可能是占较少部分。所以我一直认为，好的数据采集源是成功的50%，另外的50%在分析
