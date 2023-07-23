# 第十章 eBPF 编程

到目前为止，在本书中，您已经学到了很多关于 eBPF 的知识，并看到了许多将其用于各种应用的示例。但是如果您想基于 eBPF 实现自己的想法怎么办？本章将讨论您编写自己的 eBPF 代码时的选择。

正如您从阅读本书中了解到的，eBPF 编程由两部分组成：

- 编写在内核中运行的 eBPF 程序
- 编写管理 eBPF 程序并与之交互的用户空间代码

本章中将讨论的大多数库和编程语言要求程序员同时处理两个部分，并意识到处理的内容在哪里。但是，bpftrace 可能是最简单的 eBPF 编程语言，它将这种区别隐藏起来，使得程序员不需要过多关注这一点。

## Bpftrace

正如该项目的 _README_ 页面所述，"`bpftrace` 是一种用于 Linux eBPF 的高级跟踪语言......其灵感来自 awk 和 C，以及 DTrace 和 SystemTap 等前辈跟踪器。

[bpftrace](https://github.com/iovisor/bpftrace) 命令行工具将使用这种高级语言编写的程序转换为 eBPF 内核代码，并在终端中提供一些输出格式化的结果。作为用户，您实际上不需要考虑内核和用户空间之间的划分。

您可以在该项目的文档中找到许多有用的 one-liners 示例，其中包括一个很好的[教程](https://github.com/iovisor/bpftrace/blob/master/docs/tutorial_one_liners.md)，从编写一个简单的 “Hello World” 脚本开始，逐步引导您编写更复杂的脚本，可以跟踪从内核数据结构中读取的数据。

> 提示
>
> 通过 Brendan Gregg 的 [bpftrace 备忘录](https://www.brendangregg.com/BPF/bpftrace-cheat-sheet.html)，您可以了解 bpftrace 提供的各种功能。如需深入了解 `bpftrace` 和 BCC，请参阅他的书[《BPF 性能工具》](https://www.brendangregg.com/bpf-performance-tools-book.html)。

顾名思义，bpftrace 可以附加到跟踪（也称为 perf 相关）事件，包括 kprobes、uprobes 和 tracepoints。例如，您可以使用 `-l` 选项列出一台机器上可用的跟踪点和 kprobes，如下所示：

```bash
$ bpftrace -l "*execve*"
tracepoint:syscalls:sys_enter_execve
tracepoint:syscalls:sys_exit_execve
...
kprobe:do_execve_file
kprobe:do_execve
kprobe:__ia32_sys_execve
kprobe:__x64_sys_execve
...
```

这个示例找到了所有包含 "execve" 的可用附加点。从输出中可以看到，可以附加到名为 `do_execve` 的 kprobe。下面是一个 bpftrace 单行脚本，用于附加到该事件：

```bash
bpftrace -e 'kprobe:do_execve { @[comm] = count(); }'
Attaching 1 probe...
^C
@[node]: 6
@[sh]: 6
@[cpuUsage.sh]: 18
```

`{ @[comm] = count(); }` 部分是附加到该事件的脚本。此示例记录了不同可执行文件触发事件的次数。

bpftrace 的脚本可以协调附加在不同事件上的多个 eBPF 程序。例如，[opensnoop.bt 脚本](https://github.com/iovisor/bpftrace/blob/master/tools/opensnoop.bt)可报告文件被打开的情况。下面是一个摘要：

```bt
tracepoint:syscalls:sys_enter_open,
tracepoint:syscalls:sys_enter_openat
{
	@filename[tid] = args.filename;
}

tracepoint:syscalls:sys_exit_open,
tracepoint:syscalls:sys_exit_openat
/@filename[tid]/
{
	$ret = args.ret;
	$fd = $ret >= 0 ? $ret : -1;
	$errno = $ret >= 0 ? 0 : - $ret;

	printf("%-6d %-16s %4d %3d %s\n", pid, comm, $fd, $errno,
	    str(@filename[tid]));
	delete(@filename[tid]);
}
```

该脚本定义了两个不同的 eBPF 程序，分别连接到两个不同的内核跟踪点，分别位于 `open()` 和 `openat()` 系统调用的入口和出口处。（附加到系统调用入口点意味着该脚本具有与上一章讨论的相同 TOCTOU 漏洞。但这并不妨碍它成为一个有用的工具；只是您不应该依赖它作为安全目的的唯一防线。）这两个系统调用都用于打开文件，并将文件名作为输入参数。无论哪种系统调用入口触发的程序都会缓存该文件名，并将其存储在一个 map 中，其中的键是当前线程 ID。当触发出口跟踪点时，脚本中的 `/@filename[tid]/` 行将从该 map 中检索缓存的文件名。

运行该脚本会产生如下输出：

```bash
./opensnoop.bt
Attaching 6 probes...
Tracing open syscalls... Hit Ctrl-C to end.
PID COMM FD ERR PATH
297388 node 30 0 /home/liz/.vscode-server/data/User/
workspaceStorage/73ace3ed015
297360 node 23 0 /proc/307224/cmdline
297360 node 23 0 /proc/305897/cmdline
297360 node 23 0 /proc/307224/cmdline
```

我刚刚告诉过您有四个 eBPF 程序附加到跟踪点，那么为什么此输出显示有六个探针呢？答案是，该程序的完整版本包含两个针对 BEGIN 和 END 子句的“特殊探针”，用于初始化和清理脚本（与 awk 语言非常相似）。为了简洁起见，我在这里省略了这些子句，但您可以在 [GitHub 的源代码](https://github.com/iovisor/bpftrace/blob/master/tools/opensnoop.bt)中找到它们。

如果您使用 bpftrace，则不需要了解底层程序和 map，但对于那些阅读过本书前面章节的人来说，这些概念现在应该很熟悉。如果您有兴趣查看 bpftrace 程序运行时加载到内核中的程序和 map，您可以使用 bpftool 轻松完成此操作（正如您在第 3 章中看到的那样）。这是我运行 opensnoop.bt 时得到的输出：

```bash
$ bpftool prog list
...
494: tracepoint name sys_enter_open tag 6f08c3c150c4ce6e gpl
        loaded_at 2022-11-18T12:44:05+0000 uid 0
        xlated 128B jited 93B memlock 4096B map_ids 254
495: tracepoint name sys_enter_opena tag 26c093d1d907ce74 gpl
        loaded_at 2022-11-18T12:44:05+0000 uid 0
        xlated 128B jited 93B memlock 4096B map_ids 254
496: tracepoint name sys_exit_open tag 0484b911472301f7 gpl
        loaded_at 2022-11-18T12:44:05+0000 uid 0
        xlated 936B jited 565B memlock 4096B map_ids 254,255
497: tracepoint name sys_exit_openat tag 0484b911472301f7 gpl
        loaded_at 2022-11-18T12:44:05+0000 uid 0
        xlated 936B jited 565B memlock 4096B map_ids 254,255

$ bpftool map list
254: hash flags 0x0
        key 8B value 8B max_entries 4096 memlock 331776B
255: perf_event_array name printf flags 0x0
        key 4B value 4B max_entries 2 memlock 4096B
```

您可以清楚地看到四个跟踪点程序，以及用于缓存文件名的哈希 map 和从内核向用户空间传递输出数据的 `perf_event_array`。

> 提示
>
> bpftrace 实用程序构建在 BCC 之上，您在本书的其他地方见过它，我将在本章后面介绍它。 `bpftrace` 脚本被转换为 BCC 程序，然后使用 LLVM/Clang 工具链在运行时进行编译。

如果您想要使用基于 eBPF 的性能测量的命令行工具，[bpftrace](https://github.com/iovisor/bpftrace) 很可能能够满足您的需求。但是，尽管 bpftrace 可以作为使用 eBPF 进行跟踪的强大工具，但它并没有完全展现 eBPF 所提供的全部可能性。

要发挥 eBPF 的全部潜力，您需要直接为内核编写 eBPF 程序，并处理用户空间部分。这两个方面通常可以使用完全不同的编程语言来编写。让我们从运行在内核中的 eBPF 代码的选择开始。

## 内核中 eBPF 的语言选择

eBPF 程序可直接以 eBPF 字节码编写（有关示例，请查看 Cloudflare 的博客文章[“eBPF, Sockets, Hop Distance and manually writing eBPF assembly”](https://blog.cloudflare.com/epbf_sockets_hop_distance/)），但在实践中，大多数程序都是由 C 或 Rust 编译成字节码的。这些语言的编译器支持将 eBPF 字节码作为目标输出。

> 提示
>
> eBPF 字节码并非适用于所有编译语言。如果该语言涉及运行时组件（如 Go 或 Java 虚拟机），则很可能与 eBPF 校验器不兼容。例如，很难想象内存垃圾回收如何能与验证器对内存安全使用的检查协同工作。同样，eBPF 程序必须是单线程的，因此语言中的任何并发功能都无法使用。

虽然 [XDPLua](https://victornogueirario.github.io/xdplua/) 并不是真正的 eBPF，但这是一个有趣的项目，它提出了在 Lua 脚本中编写 XDP 程序，直接在内核中运行。然而，该项目的初步研究表明，eBPF 可能更具性能，而且随着每个内核发布中 eBPF 的功能变得越来越强大（例如，现在可以实现循环），除非某些人偏好使用 Lua 脚本编写代码，否则并不清楚是否有很大的优势。

我敢打赌，大多数选择用 Rust 编写 eBPF 内核代码的人也会选择用同样的语言编写用户空间代码，因为共享数据结构无需重写。但这并不是强制性的，您可以将 eBPF 代码与您选择的任何用户空间语言混合使用。

选择用 C 语言编写内核代码的程序员也可以选择用 C 语言编写用户空间代码（在本书中您已经看到了很多这样的例子）。但 C 语言是一种相当低级的语言，需要程序员自己处理很多细节，特别是内存管理。虽然有些人对这样做很适应，但很多人更愿意用另一种更高级的语言编写用户空间代码。无论您喜欢哪种语言，您都希望有一个提供 eBPF 支持的库，这样您就不必直接编写第 3 章中提到的系统调用接口。在本章的其余部分，我们将讨论各种语言中最流行的 eBPF 库选项。

## BCC Python/Lua/C++

在第二章中，我给您展示的第一个 “Hello World” 示例是使用 BCC 库编写的 Python 程序。该项目使用相同的库（以及我稍后会介绍的基于 libbpf 的新实现）实现了许多有用的性能测量工具。

除了介绍如何使用所提供的 BCC 工具来衡量性能的[文档](https://github.com/iovisor/bcc/blob/master/docs/tutorial.md)外，BCC 还包括[参考指南](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md)和 [Python 编程教程](https://github.com/iovisor/bcc/blob/master/docs/tutorial_bcc_python_developer.md)，以帮助您在此框架内开发自己的 eBPF 工具。

第 5 章讨论了 BCC 的可移植性方法，即在运行时编译 eBPF 代码，确保其与目标机器的内核数据结构兼容。在 BCC 中，内核侧 eBPF 程序代码定义为字符串（或 BCC 读取为字符串的文件内容）。该字符串会传递给 Clang 进行编译，但在此之前，BCC 会对字符串进行一些预处理。这样，它就能为程序员提供方便的快捷方式，其中一些您在本书中已经看到过。例如，下面是 _chapter2/hello_map.py_ 示例代码中的一些相关行：

```python
# 这是一个Python程序，将在用户空间中运行。
#!/usr/bin/python3
from bcc import BPF
# program 字符串包含要编译并加载到内核中的 eBPF 程序。
program = """
// BPF_RINGBUF_OUTPUT 是一个 BCC 宏，用于定义一个名为 output 的环形缓冲区。它是程序字符串的一部分，因此我们很自然地认为它是从内核的角度来定义缓冲区的。先别这么想，我们先看 b["output"].open_ring_buffer(print_event) 的注释。
BPF_RINGBUF_OUTPUT(output, 1);
...
int hello(void *ctx) {
    ...
    // 这行代码看起来像是在一个名为"output"的对象上调用了一个"ringbuf_output()"方法。但是等一下——在C语言中，对象的方法根本不存在！这里 BCC 做了一些重要的工作，将这些方法展开成底层的BPF辅助函数（https://github.com/iovisor/bcc/blob/14c5f99750cca211cbc620910ac574bb43f58d1d/src/cc/frontends/clang/b_frontend_action.cc#L959），在这种情况下是"bpf_ringbuf_output()"。
    output.ringbuf_output(&data, sizeof(data), 0);

    return 0;
}
"""
# 在这里，程序字符串被改写成 Clang 可以编译的 BPF C 代码。这一行还会将生成的程序加载到内核中。
b = BPF(text=program)
...
# 在代码中没有其他地方定义了名为 output 的环形缓冲区，但在 Python 用户空间代码中却可以访问它。BCC 在预处理BPF_RINGBUF_OUTPUT(output, 1); 这一行时，执行了双重任务，因为它同时为用户空间和内核部分定义了环形缓冲区。
b["output"].open_ring_buffer(print_event)
...
```

正如本例所示，BCC 本质上为 BPF 编程提供了自己的类 C 语言。它为程序员提供了便利，可以处理内核和用户空间的共享结构定义等问题，并提供方便的快捷方式来封装 BPF 辅助函数。这意味着，如果您是 eBPF 编程领域的新手，尤其是已经熟练掌握 Python 的人，BCC 是一种容易上手的方法。

> 提示
>
> 如果您想探索 BCC 编程，[这本针对 Python 程序员的教程](https://github.com/iovisor/bcc/blob/master/docs/tutorial_bcc_python_developer.md)是一个很好的方法，它可以让您了解 BCC 的更多特性和功能，而本书的篇幅有限，不再过多介绍。

文档并没有说得很清楚，但 BCC 除了支持 Python 作为 eBPF 工具用户空间部分的语言外，还支持用 Lua 和 C++ 编写工具。在提供的[示例](https://github.com/iovisor/bcc/tree/master/examples)中有 _lua_ 和 _cpp_ 目录，如果您想尝试这种方法，可以在此基础上编写自己的代码。

BCC 对于程序员来说可能很方便，但是由于将编译器工具链与实用程序一起分发的效率很低（在第 5 章中更深入地讨论），如果您希望编写要分发的生产质量工具，我建议考虑本章中讨论的其他一些库。

## C 和 Libbpf

您已经在本书中看到了很多用 C 语言编写的 eBPF 程序的例子，这些程序使用 LLVM 工具链编译成 eBPF 字节码。您还看到了为支持 BTF 和 CO-RE 而添加的扩展。许多 C 程序员也熟悉另一种主要的 C 编译器 GCC，他们会很高兴听到 [GCC 从第 10 版](https://ebpf.io/infrastructure/#gcc-compiler)开始也支持以 eBPF 为目标进行编译；不过，与 LLVM 提供的功能相比仍有一些差距。

正如第 5 章所述，CO-RE 和 _libbpf_ 提供了一种可移植的 eBPF 编程方法，无需在提供每个 eBPF 工具的同时提供编译器工具链。BCC 项目正是利用了这一点，除了原有的 BCC 性能跟踪工具集外，现在还重写了这些工具的版本，以利用 _libbpf_。人们普遍认为，基于 _libbpf_ 重写的 BCC 工具版本是更好的选择，因为它们的内存占用更少（例如，Brendan Gregg [观察](https://github.com/iovisor/bcc/pull/2778#issuecomment-594202408)到基于 _libbpf_ 的 opensnoop 版本需要大约 9 MB，而基于 Python 的版本则需要 80 MB。），而且在编译过程中不会出现启动延迟。

如果您擅长使用 C 语言编程，那么使用 _libbpf_ 将非常有意义。在本书中，您已经看到了很多这样的例子。

要想用 C 语言编写自己的 _libbpf_ 程序，最好从 [_libbpf-bootstrap_](https://github.com/libbpf/libbpf-bootstrap) 开始（既然您已经读过这本书了！）。请阅读 Andrii Nakryiko 的[博文](https://nakryiko.com/posts/libbpf-bootstrap/)，了解这个项目背后的动机。

此外，还有一个名为 _[libxdp](https://github.com/xdp-project/xdp-tools)_ 的库，它建立在 _libbpf_ 的基础上，使 XDP 程序的开发和管理变得更容易。这也是 xdp-tools 的一部分，其中还有我最喜欢的 eBPF 编程学习资源之一：[XDP 教程](https://github.com/xdp-project/xdp-tutorial)。（在 ["eBPF 和 Cilium Office Hours "直播节目的第 13 集](https://www.youtube.com/watch?v=YUI78vC4qSQ)中，观看我如何处理一些 XDP 教程示例。）

但 C 语言是一种颇具挑战性的低级语言。C 语言程序员必须负责内存管理和缓冲区处理等工作，因此编写的代码很容易出现安全漏洞，更不用说因指针处理不当而导致崩溃了。eBPF 校验器在内核方面提供了帮助，但对用户空间代码却没有同等的保护。

好消息是，还有一些适用于其他编程语言的库与 _libbpf_ 进行接口交互，或者提供类似的重定位功能，以便编写可移植的 eBPF 程序。以下是其中一些最受欢迎的库。

### Go

Go 语言已广泛应用于基础设施和云原生工具，因此用它来编写 eBPF 代码也是理所当然的。

> 提示
>
> [Michael Kashin 的这篇文章](https://networkop.co.uk/post/2021-03-ebpf-intro/)从另一个角度比较了 Go 的不同 eBPF 库。

### Gobpf

[Gobpf](https://github.com/iovisor/gobpf) 项目可能是第一个真正意义上的 Golang 实现，它与 BCC 并列为 Iovisor 的一部分。不过，它已经有一段时间没有得到积极维护了，在我写这篇文章的时候，还有人在[讨论是否要废弃它](https://github.com/iovisor/gobpf/issues/304)，所以在选择库的时候请记住这一点。

### Ebpf-go

作为 Cilium 项目的一部分，[eBPF Go 库](https://github.com/cilium/ebpf)被广泛使用（我在 GitHub 上找到了约 10,000 个引用，该项目有近 4,000 个星）。它为管理和加载 eBPF 程序和 map 提供了便捷的功能，包括 CO-RE 支持，所有这些都是纯 Go 语言实现的。

有了这个库，您就可以选择将 eBPF 程序编译成字节码，并使用一个名为 [bpf2go](https://pkg.go.dev/github.com/cilium/ebpf/cmd/bpf2go) 的工具将字节码嵌入 Go 源代码。作为编译步骤的一部分，您需要使用 LLVM/Clang 编译器来生成该代码。一旦 Go 代码编译完成，您就可以发布包含 eBPF 字节码的单一 Go 二进制文件，它可移植到不同的内核，除 Linux 内核本身外没有任何依赖项。

_cilium/ebpf_ 库还支持加载和管理以独立 ELF 文件（如本书中的 \*_.bpf.o_ 示例）形式构建的 eBPF 程序。

在撰写本文时，_cilium/ebpf_ 库支持用于跟踪的 perf 事件，包括相对较新的 fentry 事件，以及大量网络程序类型（如 XDP 和 cgroup 套接字附件）。

在 [cilium/ebpf 项目下的示例目录](https://github.com/cilium/ebpf/tree/main/examples)中，您将看到内核程序的 C 代码与 Go 中相应的用户空间代码位于同一目录中：

- C 文件以 `// +build ignore` 开头，它会告诉 Go 编译器忽略它们。在撰写本文时，我们正在进行更新，以便改用更新的 `//go:build` 类型的编译标记。

- 用户空间文件包括如下一行，它告诉 Go 编译器在 C 文件上调用 bpf2go 工具：

  ```go
  //go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf <C filename> -- -I../headers
  ```

  在软件包上运行 `go:generate`，只需一步就能重建 eBPF 程序并重新生成框架。

与第 5 章中介绍的 `bpftool gen skeleton` 很相似，`bpf2go` 会生成用于操作 eBPF 对象的框架代码，从而最大限度地减少需要自己编写的用户空间代码（只不过它生成的是 Go 代码而不是 C 代码）。输出文件还包括包含字节码的 _.o_ 对象文件。

事实上，`bpf2go` 会生成两个版本的字节码 _.o_ 文件，分别用于大端和小端架构。同时也会生成两个相应的 _.go_ 文件，并在编译时使用目标平台的正确版本。例如，在 [cilium/ebpf 的 kprobe 示例](https://github.com/cilium/ebpf/tree/main/examples/kprobe)中，自动生成的文件是：

- 包含 eBPF 字节码的 _bpf_bpfeb.o_ 和 _bpf_bpfel.o_ ELF 文件
- _bpf_bpfeb.go_ 和 _bpf_bpfel.go_ 文件定义了与字节码中定义 的 map、程序和链接相对应的 Go 结构体和函数。

您可以将自动生成的 Go 代码中定义的对象与生成它的 C 代码联系起来。以下是该 kprobe 示例的 C 代码中定义的对象：

```c
struct bpf_map_def SEC("maps") kprobe_map = {
...
};

SEC("kprobe/sys_execve")
int kprobe_execve() {
...
}
```

自动生成的 Go 代码包括代表所有 map 和程序的结构体（在本例中，map 和程序只有一个）：

```c
type bpfMaps struct {
    KprobeMap *ebpf.Map `ebpf:"kprobe_map"`
}
type bpfPrograms struct {
    KprobeExecve *ebpf.Program `ebpf:"kprobe_execve"`
}
```

KprobeMap 和 KprobeExecve 两个名称来自 C 代码中使用的 map 和程序名称。这些对象被组合到一个 `bpfObjects` 结构体中，代表加载到内核中的所有内容：

```go
type bpfObjects struct {
    bpfPrograms
    bpfMaps
}
```

然后，您就可以在用户空间 Go 代码中使用这些对象定义和相关的自动生成函数。为了让您了解这可能涉及的内容，下面是基于同一 kprobe 示例中主函数的摘录（为简洁起见，省略了错误处理）：

```go
objs := bpfObjects{}
// 将以字节码形式嵌入的所有 BPF 对象加载到我刚才展示的由自动生成代码定义的 bpfObjects 中。
loadBpfObjects(&objs, nil)
defer objs.Close()
// 将程序附加到 sys_execve kprobe。
kp, _ := link.Kprobe("sys_execve", objs.KprobeExecve, nil)
defer kp.Close()
// 设置计时器，以便代码每秒轮询一次 map。
ticker := time.NewTicker(1 * time.Second)
defer ticker.Stop()

for range ticker.C {
    var value uint64
    // 从地图中读取一个项目。
    objs.KprobeMap.Lookup(mapKey, &value)
    log.Printf("%s called %d times\n", fn, value)
}
```

在 cilium/ebpf 目录中还有其他几个示例，您可以用来参考和启发。

### Libbpfgo

Aqua Security 的 [libbpfgo 项目](https://github.com/aquasecurity/libbpfgo)在 _libbpf_ 的 C 代码基础上实现了 Go 封装，提供了加载和附加程序的实用工具，并使用通道（channel）等 Go 本地特性来接收事件。由于它基于 _libbpf_ 构建，因此支持 CORE。

下面是从 _libbpfgo_ 的 _README_ 中摘录的示例，它提供了一个很好的高层次视图，让我们了解这个库的功能：

```go
// 从目标文件读取 eBPF 字节码。
bpfModule := bpf.NewModuleFromFile(bpfObjectPath)
// 将字节码加载到内核中。
bpfModule.BPFLoadObject()

// 操作 eBPF map 中的条目。
mymap, _ := bpfModule.GetMap("mymap")
mymap.Update(key, value)

// Go 程序员会喜欢在通道上接收来自环形缓冲区或 perf 缓冲区的数据，这是一种专为处理异步事件而设计的语言特性。
rb, _ := bpfModule.InitRingBuffer("events", eventsChannel, buffSize)
rb.Start()
e := <-eventsChannel
```

该库是为 Aqua 的 [Tracee](https://github.com/aquasecurity/tracee) 安全项目创建的，也被其他项目所使用，如 Polar Signals 的 [Parca](https://github.com/parca-dev/parca-agent)，该项目提供基于 eBPF 的 CPU 性能分析。对于这个项目的方法，唯一的关注点是 _libbpf_ C 代码和 Go 之间的 CGo 边界，这可能会导致性能和其他问题。（Dave Cheney 2016 年发表的文章[“CGO 不是 Go”](https://dave.cheney.net/2016/01/18/cgo-is-not-go)很好地概述了与 CGo 边界相关的问题。）

虽然近十年来 Go 一直是许多基础设施编码的既定语言，但最近越来越多的开发人员更喜欢使用 Rust。

## Rust

Rust 越来越多地被用于构建基础架构工具。Rust 允许使用 C 语言的低级访问，但具有内存安全的额外优势。事实上，Linus Torvalds 已于 [2022 年确认](https://lwn.net/Articles/908347/)，Linux 内核本身将开始采用 Rust 代码，最近发布的 [6.1 版本也已初步支持 Rust](https://lwn.net/Articles/910762/)。

正如我在本章前面所讨论的，Rust 可以编译成 eBPF 字节码，这意味着（在正确的库支持下）可以用 Rust 编写 eBPF 工具的用户空间和内核代码。

Rust eBPF 开发有几个选项：_libbpf-rs_、_Redbpf_ 和 Aya。

### Libbpf-rs

[Libbpf-rs](https://docs.rs/libbpf-rs/latest/libbpf_rs/) 是 libbpf 项目的一部分，它为 libbpf C 代码提供了一个 Rust 封装，这样您就可以用 Rust 编写 eBPF 代码的用户空间部分。从该项目[示例](https://github.com/libbpf/libbpf-rs/tree/master/examples)中可以看出，eBPF 程序本身是用 C 语言编写的。

> 提示
>
> [_libbpf-bootstrap_](https://github.com/libbpf/libbpf-bootstrap) 项目中还有更多使用 Rust 语言的示例，如果您想尝试使用该 crate 构建自己的代码，这些示例可以帮助您快速入门。

这个 crate 有助于将 eBPF 程序整合到基于 Rust 的项目中，但它并不能满足许多人想用 Rust 编写内核代码的愿望。让我们看看其他一些能实现这一愿望的项目。

### Redbpf

[Redbpf](https://github.com/foniod/redbpf) 是一组与 libbpf 进行接口交互的 Rust crates，作为 foniod 的一部分开发，foniod 是一个基于 eBPF 的安全监控代理。

Redbpf 是在 Rust 能够编译为 eBPF 字节码之前开发的，因此它使用了[多步编译过程](https://blog.redsift.com/labs/oxidised-ebpf-ii-taming-llvm/)，包括从 Rust 编译为 LLVM 位码（bitcode），然后使用 LLVM 工具链生成 ELF 格式的 eBPF 字节码。Redbpf 支持多种程序类型，包括 tracepoints、kprobes 和 uprobes、XDP、TC 以及一些套接字事件。

随着 Rust 编译器 rustc 获得了直接生成 eBPF 字节码的能力，一个名为 Aya 的项目利用了这一能力。在撰写本文时，根据 [ebpf.io 上的社区网站](https://ebpf.io/infrastructure/#ebpf-libraries)，Aya 被认为是 "新兴 "项目，而 Redbpf 则被列为主要项目，但我个人的观点是，势头似乎正朝着 Aya 的方向发展。

### Aya

[Aya](https://aya-rs.dev/book/) 是直接在 Rust 的系统调用级别构建的，所以它不依赖 _libbpf_（或者 BCC 或 LLVM 工具链）。但它确实支持 BTF 格式，与 _libbpf_ 一样支持重定位（如第 5 章所述），因此它提供了与 CO-RE 相同的能力，一次编译即可在其他内核上运行。在撰写本文时，它比 _Redbpf_ 支持更广泛的 eBPF 程序类型，包括跟踪/perf 相关事件、XDP 和 TC、cgroups 和 LSM 附加。

正如我提到的，Rust 编译器也支持[编译成 eBPF 字节码](https://github.com/rust-lang/rust/pull/79608)，因此这种语言可用于内核和用户空间的 eBPF 编程。

> 提示
>
> 在 Rust 中可以原生编写内核和用户空间代码，而无需中间依赖 LLVM，这吸引了 Rust 程序员们的目光。GitHub 上有一个关于 [lockc 项目](https://github.com/lockc-project/lockc)（基于 eBPF 的项目，使用 LSM 钩子增强容器工作负载的安全性）开发者为何决定将其项目从 libbpf-rs 移植到 Aya 的有趣[讨论](https://github.com/lockc-project/lockc/issues/49#issuecomment-971809300)。

该项目包含 [aya-tool](https://aya-rs.dev/book/aya/aya-tool/)，一个实用工具，用于生成与内核数据结构匹配的 Rust 结构定义，这样您就不必自己编写它们。

Aya 项目非常强调开发者体验，让新人能够轻松上手。考虑到这一点，[“Aya book”](https://aya-rs.dev/book/)是一本非常可读的介绍，其中包含一些很好的示例代码，并附有有用的解释注释。

为了让您简单了解 Rust 中的 eBPF 代码，下面摘录了 Aya 允许所有流量的基本 XDP 示例：

```rust
// 这一行定义了节名称，相当于 C 中的 SEC("xdp/myapp")。
#[xdp(name="myapp")]
pub fn myapp(ctx: XdpContext) -> u32 {
    // 名为 myapp 的 eBPF 程序会调用 try_myapp 函数来处理 XDP 收到的网络数据包。
    match unsafe { try_myapp(ctx) } {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}
// try_myapp 函数记录接收到数据包的事实，并始终返回 XDP_PASS 值，告诉内核照常处理数据包。
unsafe fn try_myapp(ctx: XdpContext) -> Result<u32, u32> {
    info!(&ctx, "received a packet");
    Ok(xdp_action::XDP_PASS)
}
```

正如我们在本书中看到的基于 C 语言的例子一样，eBPF 程序被编译成 ELF 对象文件。不同的是，Aya 使用 Rust 编译器而不是 Clang 来创建该文件。

Aya 还为将 eBPF 程序加载到内核并附加到事件的用户空间活动生成了代码。下面是同一基本示例中用户空间方面的几行关键代码：

```rust
// 从编译器生成的 ELF 目标文件中读取 eBPF 字节码。
let mut bpf = Bpf::load(include_bytes_aligned!(
"../../target/bpfel-unknown-none/release/myapp"
))?;
// 在字节码中找到名为 myapp 的程序。
let program: &mut Xdp = bpf.program_mut("myapp").unwrap().try_into()?;
// 将其加载到内核中。
program.load()?;
// 将其附加到指定网络接口上的 XDP 事件。
program.attach(&opt.iface, XdpFlags::default())
```

如果您是一名 Rust 程序员，我强烈建议您更详细地了解 "Aya book"中的[其他示例](https://aya-rs.dev/book/start/)。Kong 也发表了一篇不错的[博文](https://konghq.com/blog/engineering/writing-an-ebpf-xdp-load-balancer-in-rust)，介绍如何使用 Aya 编写 XDP 负载均衡器。

> 提示
>
> Aya 维护者 Dave Tucker 和 Alessandro Decina 与我一起参加了[“eBPF 和 Cilium Office Hours”直播的第 25 集](https://www.youtube.com/watch?v=TQ0ou-eFLAk)，他们在其中演示并介绍了 Aya 的 eBPF 编程。

### Rust-bcc

[Rust-bcc](https://github.com/rust-bpf/rust-bcc) 模仿 BCC 项目 Python 绑定提供了的 Rust 绑定，以及一些 BCC 跟踪[工具](https://github.com/rust-bpf/bpf-tools)的 Rust 实现。

## 测试 BPF 程序

有一条 `bpf()` 命令 [`BPF_PROG_RUN`](https://docs.kernel.org/bpf/bpf_prog_run.html)，允许从用户空间运行 eBPF 程序进行测试。

`BPF_PROG_RUN`（目前）仅适用于 BPF 程序类型的一个子集，这些子集大多与网络有关。

您还可以通过一些内置的统计信息来了解 eBPF 程序的性能。运行以下命令启用它：

```bash
$ sysctl -w kernel.bpf_stats_enabled=1
```

这将在 `bpftool` 的输出中显示有关程序的额外信息，如下所示：

```bash
$ bpftool prog list
...
2179: raw_tracepoint name raw_tp_exec tag 7f6d182e48b7ed38 gpl
		# 下一行是粗体
        run_time_ns 316876 run_cnt 4
        loaded_at 2023-01-09T11:07:31+0000 uid 0
        xlated 216B jited 264B memlock 4096B map_ids 780,777
        btf_id 953
        pids hello(19173)
```

额外的统计数据以粗体显示，这里显示该程序运行了四次，总共花费了大约 300 微秒。

> 提示
>
> 从 Quentin Monnet 在 FOSDEM 2020 上发表的题为 ["调试 BPF 程序的工具和机制"](https://archive.fosdem.org/2020/schedule/event/debugging_bpf/) 的演讲中了解更多信息。

## 多个 eBPF 程序

eBPF 程序是附加到内核事件的函数。许多应用程序需要跟踪多个事件来实现其目标。我在本章初期介绍过 bpftrace 版本，您会看到它将 BPF 程序附加到四个不同的系统调用跟踪点上：

- `syscall_enter_open`
- `syscall_exit_open`
- `syscall_enter_openat`
- `syscall_exit_openat`

这些是内核处理 `open()` 和 `openat()` 系统调用的入口点和出口点。这两个系统调用可用于打开文件，opensnoop 工具会跟踪这两个系统调用。

但为什么需要同时跟踪这些系统调用的入口和出口呢？使用入口点是因为系统调用参数在入口点可用，这些参数包括文件名和传递给 `open[at]` 系统调用的任何标志（flag）。但在这个阶段，要知道文件是否会被成功打开还为时过早。这就解释了为什么有必要在退出点也附加 eBPF 程序。

如果您看一下 [_libbpf-tools_ 版本的 opensnoop](https://github.com/iovisor/bcc/blob/master/libbpf-tools/opensnoop.c)，就会发现只有一个用户空间程序，它会将所有四个 eBPF 程序加载到内核中，并将它们附加到各自的事件中。eBPF 程序本身基本上是独立的，但它们使用 eBPF map 来相互协调。

一个复杂的应用程序可能需要在很长一段时间内动态地添加和移除 eBPF 程序。对于任何给定的应用程序，甚至可能没有固定数量的 eBPF 程序。例如，Cilium 将 eBPF 程序附加到每个虚拟网络接口，在 Kubernetes 环境中，这些接口会随着正在运行的 Pod 数量的变化而动态增减。

本章中的大多数库都会自动处理多种 eBPF 程序。例如，_libbpf_ 和 _ebpf-go_ 生成框架代码，通过一次函数调用，就可从对象文件或缓冲区读入字节码，加载所有程序和 map。它们还能生成更细粒度的函数，以便您可以单独操作程序和 map。

## 总结

绝大多数使用基于 eBPF 的工具的人都不需要自己编写 eBPF 代码，但如果您确实发现自己想要自己实现一些东西，您有很多选择。这是一个不断变化的领域，所以当您读到这篇文章时，很有可能已经有了新的语言库和框架，或者大家已经对我在本章中强调的某些库达成了共识。您可以在 [ebpf.io 重要项目列表的基础设施页面](https://ebpf.io/infrastructure/)找到围绕 eBPF 的主要语言项目的最新列表。

要快速收集跟踪信息，`bpftrace` 是一个非常有价值的选项。

为了获得更大的灵活性和控制力，如果您熟悉 Python，并且不关心运行时发生的编译步骤，BCC 是构建 eBPF 工具的快速方法。

如果您编写的 eBPF 代码需要在不同内核版本之间广泛分发和移植，那么您可能需要利用 CO-RE。在撰写本文时，支持 CO-RE 的用户空间框架包括 C 语言的 _libbpf_、Go 语言的 _cilium/ebpf_ 和 _libbpfgo_ 以及 Rust 语言的 Aya。

如需更多建议，我强烈建议您加入 eBPF Slack 并在那里讨论您的问题。您可能会在该社区中找到许多这些语言库的维护者。

## 练习

如果您想尝试本章讨论的一个或多个库，"Hello World" 总是一个很好的开始：

1. 使用您选择的一个或多个库，编写一个 "Hello World" 示例程序，输出一条简单的跟踪信息。
2. 使用 `llvm-objdump` 将生成的字节码与第 3 章中的 "Hello World" 示例进行比较。您会发现很多相似之处！
3. 正如第 4 章所述，可以使用 `strace -e bpf` 来查看何时进行 `bpf()` 系统调用。在您的 "Hello World" 程序上试试看，看看它的行为是否符合您的预期。
