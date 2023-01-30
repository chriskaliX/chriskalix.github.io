---
layout: post
title:  容器安全(一)Kubernetes Log Audit
description: Kubernetes Log Audit
summary: Kubernetes Log Audit
tags: security
minute: 15
---

## 简介

近两年，公司的容器化推进成果显著，容器化率明显提高。过万虚拟机中，有大部分已经运行在容器环境中，容器安全变得越来越重要...而我也从前面的项目中释放出来，暂时投入到容器安全中...

### 从攻击视角

借用一张 aquasec 的图

![Kubernetes-1](https://chriskaliX.github.io/assets/imgs/kubernetes-1.png)

### 从建设视角

以安全卡点/切面的原则出发，我们粗略的将容器的安全分为

1. 构建（CI/CD，SCA）
2. 容器基础设施（基础环境配置，Dockerfile模板，etcd组件等等）
3. 运行时安全（HIDS，目前暂时是 osquery 和部分自研环境）

按理来说，应该从 CI/CD，基础设施开始搞，但是很惭愧，我先看到 kubernetes log audit，认为相比来说是一个了解整个容器环境和 ROI 相对比较高的一个入手点

## 背景

> 安全容器建设整体落后于 k8s 推进，即 k8s 整体已经推进完毕，安全组后续介入，属于历史问题...

## Learn from the best

> 对于开始一个项目，最好的学习方式一定是先认真学习现有的方案

1. [Falco-rules](https://github.com/falcosecurity/plugins/blob/master/plugins/k8saudit/rules/k8s_audit_rules.yaml)
2. [ElasticSearch-rules](https://www.elastic.co/guide/en/security/current/kubernetes-pod-created-with-hostpid.html)

以 Falco 为例，我们可以通过大致梳理一下规则来了解（毕竟即便要实际运用，里面也有很多配置需要修改...另外我们也需要添加自己的一些审计规则）

## 规则 Details

1. Disallowed K8s User

    K8s 用户白名单。在 Falco 中 allowlist 如下，当然还有 eks 的，国内的应该没有在使用的，可以剔除掉

    ```yaml
    - list: allowed_k8s_users
    items: [
        "minikube", "minikube-user", "kubelet", "kops", "admin", "kube", "kube-proxy", "kube-apiserver-healthcheck",
        "kubernetes-admin",
        vertical_pod_autoscaler_users,
        cluster-autoscaler,
        "system:addon-manager",
        "cloud-controller-manager",
        "system:kube-controller-manager"
        ]
    ```

    这里涉及到目前集群环境的一个大问题（也是很简单的大问题），就是前期搭建容器环境的时候并没有使用任何形式的认证，所有请求全部走 HTTP 到 apiserver。这是一个严重的问题，意味着所有 RBAC 策略全部失效，尤其实际生产环境是个很大的隐患，有单点失效，整个集群受控的风险。

    在这样的环境中，username 大部分为 `system:unsecured`

    [kubernetes官方手册-用户认证](https://kubernetes.io/zh-cn/docs/reference/access-authn-authz/authentication/)中讲述的非常详细，可以自行查看

2. Create Disallowed Pod

    创建不允许的 Pod。这个比较简单，有些场景下，直接创建后门的方式就是拉取一个后门 POD 下来，再做后面的逃逸（或者是直接拉下挖矿的 POD），在公司内部一般都有自己的容器镜像仓库（例如harbor），判断规则即

    ```txt
    requestObject.pod.containers.image 域名解析，是否为本地仓库域名
    ```

3. Create Privileged Pod

    特权容器创建。这个老生常谈的话题了，特权容器下逃逸的方式太多了，挂载目录，加载内核模块等等。非常不幸运的是，在这里默认所有创建都是 privileged... 很痛苦，历史原因大致是因为，想要在容器内使用 systemd，privileged 最为方便，之前安全组的同学可能没有介入到容器安全部分，所以只能在后期推动改进...

    一看到这，还是很恐怖的。apiserver 未授权 + privileged 基本属于一个大型 shell 现场。只要一台机器被打穿，简简单单就能拿下大部分主机，这比早先还全是 KVM 的时候，刺激多了...

    攻击者可以通过 mount 文件系统浏览文件，或者通过 cgroup 去 exploit，具体的可以看一下 [CDK](https://github.com/cdk-team/CDK)

4. Create Sensitive Mount Pod

    挂载敏感目录。逃逸方式的一种，最简单的挂载 /etc/ 这种，有写权限的情况下，写入 ssh 公钥或者添加 cron 定时任务。当然这个其实也需要过滤，有些特殊的 pod 例如 net-exporter 这种，就是需要挂载 /sys 下一些敏感目录，与使用的同学沟通好及时维护白名单即可

5. Create HostNetwork Pod

    创建了 hostNetwork: true 配置的 POD。这会允许当前的 POD 使用当前 Node 节点的 namespace。那么这个 POD 可以访问 Node 上所有的网络，常见的就是后门 POD，启动的时候把 HostNetwork，HostPID都设置为 true，然后 command、args 反弹 shell

6. Create HostPid Pod

    创建了 hostPid: true 的 POD。如果只是开启一个 hostPid 的话，大概率不能 root。这个[文章](https://bishopfox.com/blog/kubernetes-pod-privilege-escalation#Pod2)写的很好，里面也有每个场景对应的 [exploit-case](https://github.com/BishopFox/badPods)，适合前期拿来做规则测试，讲述了每个权限开启的情况下，存在风险。通常情况下有后门的情况，和 privileged 一起用直接从 node 上反弹 shell

7. Create HostIPC Pod

    创建了 hostIPC: true 的 POD。可以查看一些进程间通信和共享内存的（`ipcs` / `/usr/bin/ipcs`）

8. Create NodePort Service

    一般情况下，默认 nodePort 范围是 30000-32767。配置 NodePort 之后可以从集群外部访问到该 service

9. Create/Modify Configmap With Private Credentials

    这个的问题在于使用不当，[Kubernetes-官方文档](https://kubernetes.io/zh-cn/docs/concepts/configuration/configmap/)中很明确的指出了 configmap 只是存非机密数据的，如果是机密的请使用 secret... 规则内容也很简单，就是对 configmap 做增改操作的时候，正则匹配一下configmap的key的名称对比一下。

    falco 自带的估计...不适合所有人，主要是 `aws access key` 和 `password` 关键字，需要自己修改一下匹配列表，做个适应

10. Anonymous Request Allowed

    拒绝匿名请求，做好 RBAC 从你我做起

11. Attach/Exec Pod

    pod 的 subresource 是 exec 或者 attach 的，审计过滤一下 command 命令。例如有些时候运维同学做磁盘这些信息的采集，直接定时跑 df 这些，提前做好沟通，处理过滤掉。

12. EphemeralContainers Created

    创建临时容器。暂时略过这个

13. Create Disallowed Namespace

14. Pod Created in Kube Namespace

    创建了例如 kube-system, kube-public namespace 的容器。具体的危害是啥？直接查阅 [Kubernetes-官方文档](https://kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/)，我引用一下

    > Components that create pods may also be unexpectedly powerful if they can do so inside namespaces like the kube-system namespace, because those pods can gain access to service account secrets or run with elevated permissions if those service accounts are granted access to permissive PodSecurityPolicies.

    另外一个 neargle 师傅的[文章](https://weibo.com/ttarticle/p/show?id=2309404772135813120032) 里也提及到了类似的问题

    路线即 kube-system -> 寻找该命名空间下的 service account -> Cluster Role(admin maybe)

15. Service Account Created in Kube Namespace

16. System ClusterRole Modified/Deleted

    参考一下[官方文档](https://kubernetes.io/zh-cn/docs/reference/access-authn-authz/rbac/)，基础的知识：Role 和 ClusterRole 都是权限累加的规则，只是作用范围不一样。一个是作用于 namespace 一个作用于 Cluster。本身创建可能是正常行为，但是需要 report 上来通知安全组

17. Attach to cluster-admin Role

18. ClusterRole With Wildcard Created

19. ClusterRole With Write Privileges Created

20. ClusterRole With Pod Exec Created

21. K8s Secret Get Unsuccessfully Tried

22. Untrusted Node Successfully Joined the Cluster

23. Untrusted Node Unsuccessfully Tried to Join the Cluster

24. Full K8s Administrative Access

下班了，回去在写
