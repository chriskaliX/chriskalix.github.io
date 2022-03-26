---
layout: post
title: Linux Rootkit初窥(二)sys_call_table
description: Linux Rootkit初窥(二)sys_call_table
summary: Linux Rootkit初窥(二)sys_call_table
tags: security
minute: 10
---

## 背景

书接上回，我们对 sys_call_table 继续探究，开篇之前还是先贴一下这个图片。以下代码基于 Kernel Version 4.18

![简书](https://chriskaliX.github.io/assets/imgs/callgraph.jpg)

## 基础知识

首先我们了解一下，sys_call_table 在 Linux Source Code 中是怎么样的。在 `arch/x86/entry/syscall_64.c` 中如下

```C
extern asmlinkage long sys_ni_syscall(const struct pt_regs *);
#define __SYSCALL_64(nr, sym, qual) extern asmlinkage long sym(const struct pt_regs *);
#include <asm/syscalls_64.h>
#undef __SYSCALL_64

#define __SYSCALL_64(nr, sym, qual) [nr] = sym,

asmlinkage const sys_call_ptr_t sys_call_table[__NR_syscall_max+1] = {
    /*
     * Smells like a compiler bug -- it doesn't work
     * when the & below is removed.
     */
    [0 ... __NR_syscall_max] = &sys_ni_syscall,
#include <asm/syscalls_64.h>
};
```

用户态程序调用后进入到 Syscall 陷入中断，在 `sys_call_table` 中寻找对应处理程序。对于 `sys_call_table` 地址的获取在 Kernel Version 2.6 之后做了隐藏，可以参考这个[文章](https://tnichols.org/2015/10/19/Hooking-the-Linux-System-Call-Table/)。

由于不讨论 Rootkit 具体细节（其实我还没看），仅从检测角度来说在 Elkeid 里的代码和 IDT 检测一样

```C
static void analyze_syscalls(void)
{
    int i;
    unsigned long addr;
    struct module *mod;

    if (!sct || !ckt)
        return;

        
    for (i = 0; i < NR_syscalls; i++) {
        const char *mod_name = "-1";
        addr = sct[i];
        
        if (!ckt(addr)) {
            module_list_lock();
            mod = get_module_from_addr(addr);
            if (mod) {
                mod_name = mod->name;
            } else {
                const char* name = find_hidden_module(addr);
                if (IS_ERR_OR_NULL(name)) {
                module_list_unlock();
                continue;
                }

                mod_name = name;
            }
            
            syscall_print(mod_name, i);
            module_list_unlock();
        }
    }
}
```

通过遍历 kobj 判断是否在 kset 里面来判断是否是一个 hidden module。文章暂时属于未完成的状态，后续会有做 Rootkit 的部分在这里补全

## 题外话

今天公司的用户态 HIDS 上抓了一个入侵，很兴奋，很少抓到入侵:

入侵的流程很简单，由于管理疏忽有一个 PHP 的应用存在 RCE，父进程为 php-fpm 的进程执行了 sh 触发了警告，后续就是问题处置

让我更加明白了，用户态的代码可能和内核态的一样重要。对于绝大部分入侵场景来说，大部分都是在用户态层面的对抗。真正内核态的，可能是占较少部分。所以我一直认为，好的数据采集源是成功的50%，另外的50%在分析
