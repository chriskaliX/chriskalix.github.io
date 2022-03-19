---
layout: post
title: Linux Rootkit初窥(一)IDT
description: Linux Rootkit初窥(一)IDT
summary: Linux Rootkit初窥(一)IDT
tags: security
minute: 1
---

## 背景

近期在编写 HIDS 相关项目 - [Hades](https://github.com/chriskaliX/Hades)，对于用户态的后门或者行为，由于使用了 `eBPF` 进行内核态的函数 Hook，我们能够发现大部分的行为。只要 Hook 的够全面，几乎能检测到用户层 `Rootkit` 的一举一动。
目前 `Hades` 项目完成了十余个 hook，覆盖了执行、网络等，后续补全文件侧以及常用的 `uprobes`，对于用户态后门、入侵行为等能有较全的感知。
然而对于 `Rootkit`，由于笔者知识匮乏，除了 hook `do_init_module` 和针对 eBPF 程序加载（[ebpfkit-monitor](https://github.com/Gui774ume/ebpfkit-monitor)）做监测，也不知道如何防范，抓取这样的行为...作为知识的补充，本篇文章涵盖 Rootkit/Linux 基础学习以及一些思考

### 基础知识

> 由于之前对这部分一窍不通，好多的基础知识我们当作实验，稍微的过一遍。从知乎的[回答](https://www.zhihu.com/question/33695415)中我们找到 phrack.org，开始学习。参考 [Handling Interrupt Descriptor Table for fun and profit](http://phrack.org/issues/59/4.html)，很大一部分可能会是翻译，翻译的过程就是学习的过程

首先，Intel CPU 在保护模式，提供四种模式，即 r0 ~ r3 层，用户层的应用程序一般运行在 r3 层，内核态的运行在 r0 层

中断分为可屏蔽和不可屏蔽中断，其中不可屏蔽中断在这里不讨论。中断向量是个0~255之间的数，其中 0~31 是 exceptions 以及不可屏蔽中断， 32~47 是可屏蔽中断，48~255 为软件中断。Linux 下通常使用的是 (0x80) sys_call_table，即用户态通过 syscall 调用到内核函数。同样的，当我们为了获取 `sys_call_table` 地址也可以从 `IDT` 中获取

什么是 `IDT` ?  `IDT` 即 Interrupt Descriptor Table。是一个描述中断即其对应处理函数的线性表，包含四种不同类型的描述/类型。分别是 Task Gate Descriptor（Linux 不使用这种） / Interrupt Gate Descriptor / Trap Gate Descriptor / Call Gate Descriptor

```c
enum {
    GATE_INTERRUPT = 0xE,
    GATE_TRAP = 0xF,
    GATE_CALL = 0xC,
    GATE_TASK = 0x5,
};
```

其中 Interrupt Gate Descriptor 用于中断的处理，需要关注的是 DPL（Descriptor Privilege Level）为0，因此用户态不能访问中断门

为了方便理解，借用一个图(这图很经典，方便了解整个流程)：

![简书](https://chriskaliX.github.io/assets/imgs/callgraph.jpg)

#### in Linux

在 Linux 中，IDT 的定义在 `arch/x86/kernel/idt.c` ，`IDT_ENTRIES` 固定为 256

```c
gate_desc idt_table[IDT_ENTRIES] __page_aligned_bss;
```

其中 `gate_desc` 定义如下

```c
struct gate_struct {
    u16     offset_low;
    u16     segment;
    struct idt_bits bits;
    u16     offset_middle;
#ifdef CONFIG_X86_64
    u32     offset_high;
    u32     reserved;
#endif
} __attribute__((packed));
```

其中 offset_* 代表中断函数的偏移量，bits 为属性符

### 从项目出发

从开始，我们便以字节的 Elkeid 作为参考。Elkeid 主要检查了 4 个，即隐藏内核模块/进程隐藏/IDT劫持/系统调用劫持。我们以 idt rootkit 为关键字，搜索到一些[项目](https://github.com/kaneschutzman/linux-rootkit)。在 [idt.c](https://github.com/kaneschutzman/linux-rootkit/blob/5dcb228a86f67773d6e2b92276e59cf030b52c23/src/idt.c) 中，通过替换 `IDT` 中的函数地址实现 Hook，关键代码如下：

```c
void idt_set_entry(unsigned long addr, int n)
{
    if (cur_idt_table == old_idt_table)
        set_addr_rw(old_idt_table);
    cur_idt_table[n].offset_high = (addr >> 32) & 0xffffffff;
    cur_idt_table[n].offset_middle = (addr >> 16) & 0xffff;
    cur_idt_table[n].offset_low = addr & 0xffff;
    if (cur_idt_table == old_idt_table)
        set_addr_ro(old_idt_table);
}

void idt_substitute(void)
{
    struct desc_ptr idtr;

    memcpy(new_idt_table, cur_idt_table, IDT_SZ);
    idtr.address = (unsigned long)new_idt_table;
    idtr.size = idt_size;
    on_each_cpu(local_load_idt, &idtr, 1);
    cur_idt_table = new_idt_table;
}
```

替换表的形式来完成劫持，其中对 IDTR 寄存器的操作使用 LIDT 指令和 SIDT 指令。另外 `sys_call_table` 的 hook 应该方法也是类似，先在 IDT 表中找到 0x80 中断的位置，再根据特定 function 再 `sys_call_table` 中的偏移...

顺便贴一张 IDTR

![百度](https://gimg2.baidu.com/image_search/src=http%3A%2F%2Fimg.it610.com%2Fimage%2Finfo9%2F3a4a1cf12b0940c3a8115008a28511bd.jpg&refer=http%3A%2F%2Fimg.it610.com&app=2002&size=f9999,10000&q=a80&n=0&g=0n&fmt=auto?sec=1650278847&t=cec7d575642e0f888777f63f0507bee7)

在字节的 `anti_rootkit` 中我们截取 `interrupt` 检查部分，事实上 `sys_call_table` 的检查部分也是一样的

```c
static void analyze_interrupts(void)
{
#ifdef CONFIG_X86
    int i;
    unsigned long addr;
    struct module *mod;

    if (!idt || !ckt)
        return;
    // 遍历所有 entries
    for (i = 0; i < IDT_ENTRIES; i++) {
        const char *mod_name = "-1"; 

        addr = idt[i];
        // ckt 判断是否为内核代码段
        if (!ckt(addr)) {
            module_list_lock();
            // 获取 idt 对应函数的地址
            mod = get_module_from_addr(addr);
            if (mod) {
                mod_name = mod->name;
            } else {
                // 寻找是否为隐藏的内核模块
                // 通过遍历 ksets 下的 mod list，通过于 kobj 一一比对
                // 如果找不到，则为隐藏的内核模块，是可疑的
                const char *name = find_hidden_module(addr);
                if (IS_ERR_OR_NULL(name)) {
                    module_list_unlock();
                    continue;
                }

                mod_name = name;
            }

            interrupts_print(mod_name, i);
            module_list_unlock();
        }
    }
#endif
}
```

这种检测，对函数的 entry 做了足够的检测，但是如何检测 hook 在函数中间的情况呢?

## 最后

其实看的还是比较浅显的，如果每个模块都单独细钻，会耗费较大的时间，后续会慢慢跟进

## 参考

> 有字节群中沈平推荐的两本，可以细细品读，我还没看...

1, The Rootkit Arsenal Escape and Evasion in the Dark Corners of the System by Bill Blunden， 2nd edition，第一版是中译本

2, Rootkits and Bootkits Reversing Modern Malware and Next Generation Threats by Alex Matrosov, Eugene Rodionov, Sergey Bratus，有中译本

3, [nskernel-kernel-play-guide](https://nskernel.gitbook.io/kernel-play-guide/hacking-interrupts-exceptions-and-trap-handlers/hooking-an-idt-handler)
