# 声明

本项目翻译自 [Liz Rice 的 Learning eBPF](https://isovalent.com/books/learning-ebpf/)，该书是本人至今发现少有的比较系统的 eBPF 入门指南。遂在阅读过程中，翻译成中文，方便后人。[原书](./Learning-eBPF%20-%20Full%20book.pdf)亦在仓库中，翻译比较仓促，如有问题，欢迎提交 pr，共同完善。

本项目使用 GPL 协议，转载请注明出处。如有侵权，请提交 issue，本人看到后会第一时间处理。

# 介绍

在云原生社区及更广泛的技术领域中，eBPF 已成为近年来最热门的技术话题之一。在网络、安全、可观察性等领域，新一代[强大的工具和项目](https://ebpf.io/applications)正基于 eBPF 平台构建（并不断涌现）。相比从前，它们提供了更好的性能和精度。诸如 [eBPF 峰会](https://ebpf.io/summit-2022)和[云原生 eBPF 日](https://www.youtube.com/playlist?list=PLDg_GiBbAx-lZtLQtDaoj_eoMfmGzSmxo)等 eBPF 相关会议吸引了成千上万的与会者和观众，截至撰写本文时，[eBPF Slack](http://ebpf.io/slack) 社区已有超过 14,000 名成员。

为何 eBPF 被选为众多基础设施工具的底层技术？它如何实现所承诺的性能提升？eBPF 如何在从性能追踪到网络流量加密等各不相同的技术领域中发挥作用？

本书旨在解答这些问题，通过让读者了解 eBPF 的工作原理，并提供编写 eBPF 代码的入门介绍。

详细内容请查看[目录](./src/SUMMARY.md)

# 相关链接
- 在线阅读：[https://binw666.github.io/learning-ebpf-translation/](https://binw666.github.io/learning-ebpf-translation/)
- GitHub: [https://github.com/binw666/learning-ebpf-translation](https://github.com/binw666/learning-ebpf-translation)
- Gitee: [https://gitee.com/binw666/learning-ebpf-translation](https://gitee.com/binw666/learning-ebpf-translation)
  - 需要注意，Gitee 无法正确显示脚注