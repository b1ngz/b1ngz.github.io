---
title: "自动化安全工具平台 - 架构笔记"
layout: post
comments: true
date: 2020-12-24
headerImage: false
blog: true
star: false
author: b1ngz
description:

---



## 0x01. 简介

这篇笔记是这几年我在写自动化安全工具平台过程中，在架构方面的一些想法、思考、尝试和总结，主要内容包括：

- 为什么我要写自动化安全工具平台？
- 平台 1.0 版本架构介绍、所遇到的问题
- 平台 2.0 版本架构介绍、如何解决 1.0 版本所遇到的问题
- 未来的一些想法和计划
- 内容总结



<br/>

---

原文链接 [自动化安全工具平台 - 架构笔记](https://mp.weixin.qq.com/s/OMhS9yFlcpI9KOQduSxq9g)

欢迎关注

  ![mp-weixin](/assets/images/mp-weixin/qrcode.png){: width="300" }



## 0x02. Why

在安全测试和挖洞的过程中，我们会用到许多的安全工具，个人在使用时，遇到了如下一些问题：

- 工具的命令行交互方式用户体验不佳，结果查看和筛选不方便
- 随着工具使用数量增多，需要记住更多的命令和参数，如何有效的打通各工具也成为一个问题
- 手工操作存在重复劳动，如对于每一个根域名，都要进行子域名收集、IP 解析、端口扫描等操作
- 结果持久化存储和管理问题，比如我想查询某个域名有哪些子域名、是什么时候发现的、解析到哪些 IP、开放了哪些端口，如果没有资产管理平台，很难实现这些功能
- 工具开发语言、风格多样化，优化和定制修改成本较高
- 运行速度，对于大量目标，单机运行的速度远远无法满足需求
- 工具间缺少公共功能和模块，如定时任务、结果通知
- ...



因为以上列出和没列出的种种原因，我决定写一个自用的安全工具平台，它需要满足以下条件：

- 提供人性化的 web 管理界面，即能选择的，尽可能不输入，鼠标点击一下能完成的，尽可能不点两下
- 将常用工具封装成任务模块，通过参数配置来控制任务执行，实现底层细节屏蔽，简化操作
- 实行任务模块间的打通，即某个任务的结果可以作为其他任务的输入
- 支持资产管理、任务运行和结果查看等功能
- 分布式，可通过机器扩容来提高扫描速率
- 支持定时模块，实现任务的自动化周期运行
- ...



为了能够实现预期目标，需要有一套良好的架构来支撑，来看一下平台的 1.0 架构



## 0x03. 1.0 版本架构

1.0 版本的架构图如下：

![图片](/assets/images/platform-architecture-1/architecture-1.0.png)

使用到的技术栈和组件信息：

- 前端：Vue，使用基于 Element UI 的开源管理后台模版
- 后端：Python 3.6，API 使用 Django REST framework
- 反向代理：Nginx
- 数据库：PostgreSQL
- 缓存：Redis
- Message Broker：RabbitMQ
- 分布式任务框架：Celery
- 定时任务：Celery beat
- 任务监控：Flower
- 服务部署：Docker + Docker Compose + SSH



对于写过分布式工具的师父来说，整体架构应该还是相对比较简单的。

接着来一起了解一下我是如何选择技术框架和组件的

- 首先最基础的是开发语言，它决定了后续用到的框架和组件生态。当时用的比较多的开发语言是 Java，但对于写自用的工具而言，Java 在开发效率和成本上都比较 "重" ，因为有很多优秀的开源工具是用 Python 写的，所以最终就选择了它
- 第二点是前后端框架选型。后端框架上，因为 Django 进行了很多高阶封装，相比轻量级的 Flask 而言，开发速度上会更快。前端框架上，个人认为前后端分离更易于维护，开发效率更高，因此我没有选择 Django 的 templates，也因偶然的机会看到了基于 Vue 的 Element-UI 组件库，试用后觉得这真是像我这种不擅长前端人的福音，之后通过慢慢的学习，也感受到了 Vue 的简洁和强大
- 第三点是数据库，当时之所以选择了 PostgreSQL，原因有两个，一是想接触一下没有使用过的东西。二是被官网的介绍 - The world's most advanced open source database 所吸引。在之后的使用过程中，遇到了某些 model 字段需要使用到 JSON 类型，当时 Django 2.x 版本只有 Postgresql 支持。不过在 Django 3.1 版本，主流数据库也都支持了 JSONField，因为是 ORM，只要不是使用到了某个数据库特有的 feature，理论上是可以切换的
- 第四点是分布式组件，任务调度框架选择了历史悠久、使用广泛、功能全面的 Celery，任务停止、定时任务、任务监控、任务优先级，该有的一应俱全，不过也正因为它悠久的历史，也导致它代码量过于庞大、配置较为复杂，很多  bug 一两年都没有解决，在使用过程中也遇到了一些稳定性方面的问题，导致最终放弃了它，这部分原因后面会具体解释。还有就是 message broker，之前看过一些 RabbitMQ 的文章，稳定、使用广泛，所以就决定是它了
- 最后一点是服务部署，这几年容器化是一个趋势，因此我将平台上所有的服务都基于 docker / docker compose 搭建，容器化能够保证开发和线上环境的一致性，提升服务部署和扩容速度



了解完技术选型的过程，再来一起看看 1.0 版本在实现和使用过程中，我所遇到的一些问题

- 首先第一点是稳定性，安全工具中很多任务都是网络 IO 型，为了提高任务的执行效率，在运行 Celery worker 时是以 Gevent 协程方式启动，在运行一段时间后，会时常出现 BrokenPipeError 错误后 worker 卡死，不再消费队列任务的情况，只能通过重启解决。根据 Github issues 的记录这个问题在 17 年有人报告过，但直到我写这篇笔记时，该问题仍然没有解决，我自己也曾尝试通过阅读源码定位原因，但因为 Celery 代码量较大，最后也放弃了
- 第二点是可用性，说到这点，就得提一下 19 年 8 月我发过的一条微博，大致内容是，凌晨收到 VPS 厂商的一封邮件，提示我的一台服务器所在物理机故障，需要重启。早上起来一看，运行任务全部失败，查了下原因，发现那台半夜重启的服务器上运行着 RabbitMQ 服务。然后就在一个月后，我在尝试增加 worker 节点数量，因为没有数据库连接池，高并发导致 worker 频繁的与 db 建立连接，使机器 CPU 飙升到 100%。从这两件事情，我开始思考现在架构在可用性方面的问题，例如是否存在单点故障、是否能够支撑水平无限扩展
- 第三点是灵活性和用户体验，实现自动化离不开定时模块，但 1.0 版本的定时任务，无法支持动态创建和修改，需要重启后生效，因此灵活性上需要优化。此外，部分功能前端界面设计的不够友好，管理后台模版功能不够强大，也无法满足极致人性化的要求
- 第四点是服务部署和扩容，部分服务仍依赖手工操作。对于自动化部分，配置没有与代码分离开，配置方面也比较复杂，服务上线效率不高
- 第五点是代码维护成本，因为 1.0 版本是在边学习边实现的过程中完成的，存在着模块间代码高度耦合、重复代码多等问题，导致代码修改和新功能实现上都较困难。
- ...



为了解决上述 1.0 版本所面临的问题，实现稳定、高可用、高度自动化的目标，我走上了 2.0 版本的重构和改造之路





## 0x04. 2.0 版本架构

2.0 版本的架构图如下

![图片](/assets/images/platform-architecture-1/architecture-2.0.png)

使用到的技术栈和组件信息，这里仅列出与 1.0 版本不同的地方

- 前端：使用更为强大的管理后台模板 https://github.com/PanJiaChen/vue-admin-template
- 数据库：PostgreSQL Cluster
- 数据库连接池：PgBouncer
- Message Broker：RabbitMQ Cluster
- 消息监控：RabbitMQ Management Plugin
- 分布式任务框架：Dramatiq
- 定时任务：APScheduler



相比 1.0，新版本改进和优化的地方主要有：

- RabbitMQ 由单节点变为 Cluster 模式，通过 Queue Mirroring 来保证高可用，即某个队列里的消息会在多个节点进行镜像 (mirrored)，即使某个节点异常宕机，消息也不会丢失
- 数据库 Postgresql 由单节点变为 Cluster 模式，通过读写分离，增加 slave 节点来支撑 worker 的水平扩展，保证 DB 的稳定性和可用性
- 使用 PgBouncer 作为数据库连接池，来避免频繁建立、关闭数据库连接，降低机器负载，提升稳定性
- 任务调度框架由 Celery 替换为 Dramatiq，该框架的优点是运行非常稳定、代码结构清晰，但功能上要相比 Celery 少，不过可以通过实现自定义 middleware 来进行扩展
- 基于 APScheduler 和 Dramatiq 实现定时任务功能，支持动态添加和修改定时任务
- 创建新项目，用于服务的自动化部署，提供修改配置文件的方式，来进行上线和扩容，提高部署效率
- 项目重构，将各个任务模块的代码分离，封装公共 utils 函数，提升可维护性
- ...



除了以上的点外，还有一个关于多任务同时运行，资源分配和抢占的问题，想和大家聊一下

前面提到，任务会通过定时模块周期性的运行，即队列中时时刻刻都有任务在运行或等待运行。假如某天我们发现了一个新漏洞，POC 已写好，扫描任务也已创建，但此时资源都已经被其他已运行的任务占用，只能等待其他任务完成或手动停止释放资源。为了能够更好的解决这个问题，需要有机制能够让新任务具备抢占其他正在运行任务的资源的能力，那么如何实现呢？以下是我的思路和做法：

- 队列里的消息/任务需要有优先级之分，即当有空闲资源时，高优先级的任务会优先执行，RabbitMQ 的 Priority Queue 能够很好的支持这一点
- 尽量避免一个任务的执行时间过长，即将一个大任务拆分成多个小任务，如每个小任务能够在几分钟内执行完成，这样可以缩短新建高优先级任务等待资源释放的时间
- 控制并发执行任务数，假设要扫描几十万 IP 的全端口，我会把它拆分成数量更多的子任务，因为我的机器资源有限，我不会将所有子任务都一次性发送到队列中去，而是会先启动一个端口扫描的主任务，在主任务中来控制子任务的发送。这样做不仅可以实现控制子任务的并发执行数、动态调整优先级、停止任务等功能，还可以动态分配资源，让多个不同优先级的任务能同时运行



说了这么多，那么实际效果怎么样呢？以下是 2.0 架构今年的一些使用情况

- 未遇到因框架或组件问题导致的服务中断
- 最长稳定运行时间 180 天 +，也即我有半年时间没有添加新功能，每天按照配置的定时任务稳定运行的最长记录
- 顶峰集群规模：共 84 台服务器，其中 80 台 worker 机器，其余 4 台机器混部 DB、RabbitMQ、Redis 等服务，这个大概跑了两周时间



## 0x05. 想法和计划

虽然 2.0 版本优化和解决了 1.0 版本中的很多问题，但它仍然有很多不足和待改进的地方，例如数据库使用集群模式后，存在多个节点，目前 worker 端连接时，是随机选择其一，一旦某个节点宕机，就会导致部分请求失败，再加上数据库配置是通过 docker env-file 传入，无法实现动态摘除节点，需要重新部署。另外，随机选择也带了另一个问题，不同节点之间的负载存在不均衡的情况。因此，为了能够让平台更加稳定，实现高度自动化目标，还需要对架构进行进一步的优化。以下是目前的一些 ToDo，因为只是初步的想法，有可能不一定会实际去实现，大家可以简单参考一下：

- 基于如 ZooKeeper 或 etcd 实现统一分布式配置中心，解决数据库、RabbitMQ 等配置的动态更新问题
- 基于如 HAProxy 实现 TCP 代理，解决数据库、RabbitMQ 等服务高可用和负载均衡问题
- 继续完善和提高服务自动化部署程度，例如自动化扩容数据库 Slaver 节点、RabbitMQ 节点等
- 完善服务监控和报警功能，如接入 Sentry 等
- ...



## 0x06. 总结

这篇笔记介绍了我在写自动化安全工具平台过程中，在构架方面的一些个人思考和总结，文字比较多，感谢大家耐心看完，希望能够给同样在写自动化工具的人提供一些帮助。另外，因个人能力和水平有限，文中可能会有描述错误或理解不到位的地方，欢迎各位指正和交流。

最后是下篇笔记的预告时间，我会介绍平台上的一些功能和自己的想法，感兴趣的老板可以关注一下



## 0x07. 参考

- Django REST framework https://www.django-rest-framework.org/
- Dramatiq: background tasks  https://dramatiq.io/
- Clustering Guide — RabbitMQ https://www.rabbitmq.com/clustering.html
- Priority Queue Support — RabbitMQ https://www.rabbitmq.com/priority.html
- PostgreSQL High Availability, Load Balancing, and Replication https://www.postgresql.org/docs/11/high-availability.html
- PgBouncer - lightweight connection pooler for PostgreSQL https://www.pgbouncer.org/
- Celery https://docs.celeryproject.org/en/stable/getting-started/introduction.html
- Vue.js https://vuejs.org/
- Element - A Desktop UI Toolkit for Web https://element.eleme.io/




