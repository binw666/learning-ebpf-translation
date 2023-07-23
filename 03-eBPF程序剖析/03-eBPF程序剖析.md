# 第 3 章 eBPF 程序剖析

在前一章中，您看到了使用 BCC 框架编写的一个简单的 eBPF“Hello World”程序。在本章中，有一个完全用 C 编写的“Hello World”程序的示例版本，这样您可以看到 BCC 在幕后处理的一些细节。

本章还向您展示了 eBPF 程序从源代码到执行所经历的阶段，如图 3-1 所示。

![Alt text](figure-3-1.png)

图 3-1. C（或 Rust）源代码被编译为 eBPF 字节码，该字节码可以被 JIT（即时） 编译或解释为本机机器代码指令

eBPF 程序是一组 eBPF 字节码指令。可以直接用编写 eBPF 字节码的方式编写 eBPF 代码，就像可以用汇编语言编程一样。通常，人们更容易处理高级编程语言，至少在撰写本文时，我可以说绝大多数 eBPF 代码是用 C 语言编写的，然后编译为 eBPF 字节码。（越来越多的 eBPF 程序也开始使用 Rust 编写，因为 Rust 编译器支持将 eBPF 字节码作为目标。）

从概念上讲，该字节码在内核中的 eBPF 虚拟机中运行。

## eBPF 虚拟机

eBPF 虚拟机（就像任何虚拟机一样）是计算机的软件实现。它接收以 eBPF 字节码指令形式表示的程序，并将其转换为在 CPU 上运行的本机机器指令。

在早期的 eBPF 实现中，字节码指令是在内核中解释执行的，也就是说，每次运行 eBPF 程序时，内核都会检查指令并将其转换为机器码，然后执行它们。出于性能原因以及为了避免 eBPF 解释器中出现一些 Spectre 相关的漏洞，解释执行已在很大程度上被 JIT（即时）编译替代。编译意味着当程序加载到内核时，从字节码到本机机器指令的转换只发生一次。

eBPF 字节码由一组指令组成，这些指令作用于（虚拟的）eBPF 寄存器。eBPF 指令集和寄存器模型的设计旨在与常见的 CPU 架构相匹配，以便将字节码编译或解释为机器码的步骤相对简单。

### eBPF 寄存器

eBPF 虚拟机使用 10 个通用寄存器，编号为 0 到 9。此外，寄存器 10 被用作栈帧指针（只能读取，不能写入）。当执行 BPF 程序时，值会存储在这些寄存器中以跟踪状态。

重要的是要理解，在 eBPF 虚拟机中，这些 eBPF 寄存器是通过软件实现的。您可以在 Linux 内核源代码的[ include/uapi/linux/bpf.h 头文件 ](https://oreil.ly/_ZhU2)中看到它们从`BPF_REG_0`到`BPF_REG_10`的枚举。

在 eBPF 程序开始执行之前，上下文参数被加载到寄存器 1 中。函数的返回值存储在寄存器 0 中。

eBPF 代码在调用函数之前，该函数的参数被放置在寄存器 1 到寄存器 5 中（如果参数少于五个，则不会使用所有寄存器）。

### eBPF 指令

同样的[ linux/bpf.h 头文件 ](https://oreil.ly/_ZhU2)定义了一个名为 `bpf_insn` 的结构，它代表一条 BPF 指令：

```c
struct bpf_insn {
    // 每个指令都有一个操作码，它定义了指令要执行的操作：例如给寄存器的内容增加一个值，或者跳转到程序中的另一个指令。（有一些指令的操作被指令中其他字段的值“修改”。例如，内核 5.12 中引入了一组[原子指令](https://github.com/iovisor/bpf-docs/blob/1df94e131d6dfc4add68890c481b178ef1ae7c57/eBPF.md#atomic-instructions)，其中包括在 imm 字段中指定的算术运算（ADD、AND、OR、XOR）。）Iovisor项目的[“非官方eBPF规范”](https://github.com/iovisor/bpf-docs/blob/master/eBPF.md)中列出了有效指令的列表。
	__u8	code;		/* opcode */
    // 不同的操作可能涉及最多两个寄存器。
	__u8	dst_reg:4;	/* dest register */
	__u8	src_reg:4;	/* source register */
    // 根据操作的不同，可能会有一个偏移值和/或一个“立即数”整数值。
	__s16	off;		/* signed offset */
	__s32	imm;		/* signed immediate constant */
};
```

`bpf_insn` 结构体的长度为 64 位（或 8 字节）。然而，有时一条指令可能需要多于 8 字节的空间。如果您想将寄存器设置为 64 位值，您无法将 64 位的值与操作码和寄存器信息一起挤进结构体中。在这些情况下，指令使用总长度为 16 字节的*宽指令编码*。您将在本章中看到这方面的示例。

当加载到内核中时，eBPF 程序的字节码由一系列 `bpf_insn` 结构体表示。验证器对这些信息进行多次检查，以确保代码的运行安全。您将在第 6 章中了解更多关于验证过程的内容。

大多数不同的操作码可以归类为以下几类：

- 将值加载到寄存器中（可以是立即数、从内存或其他寄存器读取的值）
- 将寄存器中的值存储到内存中
- 执行算术运算，例如，将值添加到寄存器的内容
- 如果满足特定条件，则跳转到不同的指令

> 提示
> 如果您想了解 eBPF 架构的概述，我推荐阅读 Cilium 项目文档中包含的[BPF 和 XDP 参考指南](https://docs.cilium.io/en/stable/bpf/)。如果您想获取更多详细信息，[内核文档](https://docs.kernel.org/bpf/instruction-set.html)清楚地描述了 eBPF 指令和编码。

让我们使用另一个简单的 eBPF 程序示例，并跟随它从 C 源代码到 eBPF 字节码再到机器码指令的过程。

> 提示
> 如果您想自己构建和运行这段代码，您可以在[github.com/lizrice/learning-ebpf](https://github.com/lizrice/learning-ebpf)上找到代码以及设置环境的说明。本章的代码位于`chapter3`目录中。
> 本章中的示例是使用名为 libbpf 的库，用 C 语言编写的。您将在第 5 章中了解有关该库的更多信息。

## 用于网络接口的 eBPF “Hello World”

在前一章中的示例中，通过系统调用的 kprobe 触发了“Hello World”的跟踪输出；而这一次，我将展示一个 eBPF 程序，当网络数据包到达时触发，它将输出一行跟踪信息。

数据包处理是 eBPF 的一个非常常见的应用领域。在第 8 章中，我会更详细地介绍这个内容，但是现在，了解一个 eBPF 程序的基本思想可能是有帮助的，这个程序会被到达网络接口的每个数据包触发。该程序可以检查甚至修改数据包的内容，并对内核对该数据包应该执行的操作做出决策（或判断）。这个判断可以告诉内核继续按照通常的方式处理它，丢弃它或将其重定向到其他地方。

在这个简单的例子中，程序不对网络数据包进行任何处理；它只是在每次接收到网络数据包时，将 Hello World 和一个计数器写入跟踪管道。

该示例程序位于`chapter3/hello.bpf.c`文件中。将 eBPF 程序放置在以`bpf.c`结尾的文件名中是一种常见的约定，以区分其与可能位于相同源代码目录中的用户空间 C 代码。以下是整个程序的内容:

```c
// 该示例首先包含了一些头文件。如果您对C编程不熟悉，每个程序都必须包含定义程序将使用的任何结构体或函数的头文件。从这些头文件的名称可以猜到它们与BPF有关。
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
// 该示例展示了eBPF程序如何使用全局变量。每次程序运行时，该计数器都会递增。
int counter = 0;
// 宏SEC()定义了一个名为xdp的节(section)，您将能够在编译后的目标文件中看到它。我将在第5章中详细介绍节名称的用法，但目前您可以简单地认为它定义了一个eXpress Data Path（XDP）类型的eBPF程序。
SEC("xdp")
// 在这里，您可以看到实际的eBPF程序。在eBPF中，程序名就是函数名，因此这个程序被称为hello。它使用了一个辅助函数bpf_printk来输出一串文本，递增了全局变量counter，然后返回值XDP_PASS。这是给内核的判决，表明内核应该正常处理这个网络数据包。
int hello(struct xdp_md *ctx) {
    bpf_printk("Hello World %d", counter);
    counter++;
    return XDP_PASS;
}
// 最后，还有另一个SEC()宏，用于定义许可证字符串，这是eBPF程序的关键要求之一。内核中的一些BPF辅助函数被定义为“仅限GPL”。如果您想使用其中任何函数，您的BPF代码必须声明为具有与GPL兼容的许可证。验证器（我们将在第6章中讨论）将拒绝不与程序使用的函数兼容的声明许可证。某些eBPF程序类型，包括那些使用BPF LSM的程序类型（您将在第9章中了解到），也[要求与GPL兼容](https://docs.kernel.org/bpf/bpf_licensing.html#using-bpf-programs-in-the-linux-kernel)。
char LICENSE[] SEC("license") = "Dual BSD/GPL";
```

> 提示
> 您可能会想知道为什么上一章中使用了`bpf_trace_printk()`，而这个版本使用了`bpf_printk()`。简而言之，是 BCC 版本使用了`bpf_trace_printk()`，而 libbpf 版本使用了`bpf_printk()`，但这两个函数都是对内核函数`bpf_trace_printk()`的封装。Andrii Nakryiko 在[他的博客](https://nakryiko.com/posts/bpf-tips-printk/)上对此进行了很好的解释。

这是一个示例 eBPF 程序，它附加到网络接口的 XDP 挂钩点上。您可以认为 XDP 事件是在网络数据包到达（物理或虚拟）网络接口入站时触发的。

> 提示
> 一些网络适配器支持将 XDP 程序卸载至网络适配器本身上，以便能够在网络适配器上执行。这意味着每个到达的网络数据包都可以在适配器上进行处理，而不需要接触到计算机的 CPU。XDP 程序可以检查甚至修改每个网络数据包，因此在进行 DDoS 保护、防火墙或负载均衡等高性能任务时非常有用。您将在第 8 章中了解更多相关内容。

您已经看到了 C 源代码，下一步是将其编译为内核可以理解的目标文件。

## 编译 eBPF 目标文件

我们的 eBPF 源代码需要编译成 eBPF 虚拟机能理解的机器指令：eBPF 字节码。如果您指定了`-target bpf`，[LLVM 项目](https://llvm.org)中的 Clang 编译器将会执行此操作。以下是一个 Makefile 的摘录，用于进行编译：

```makefile
hello.bpf.o: %.o: %.c
	clang \
	    -target bpf \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-g \
	    -O2 -c $< -o $@
```

这将从 hello.bpf.c 的源代码生成一个名为 hello.bpf.o 的目标文件。这里的`-g`标志是可选的，但它会生成调试信息，以便在检查目标文件时可以同时看到源代码和字节码。（需要使用`-g`标志来生成 BTF 信息，这些信息是 CO-RE eBPF 程序所需要的，我将在第五章介绍。）让我们检查一下这个目标文件，以更好地了解其中包含的 eBPF 代码。

## 检查 eBPF 目标文件

文件实用程序通常用于确定文件的内容：

```bash
$ file hello.bpf.o
hello.bpf.o: ELF 64-bit LSB relocatable, eBPF, version 1 (SYSV), with debug_info, not stripped
```

这表明它是一个 ELF（Executable and Linkable Format，可执行和可链接格式）文件，包含 eBPF 代码，适用于具有 LSB（最低有效位）架构的 64 位平台。如果在编译步骤中使用了`-g`标志，它将包含调试信息。

您可以使用 llvm-objdump 进一步检查该对象，查看 eBPF 指令：

```c
$ llvm-objdump -S hello.bpf.o
```

即使您不熟悉反汇编，该命令的输出也不太难理解：

```bash
# 第一行进一步确认 hello.bpf.o 是一个带有 eBPF 代码的 64 位 ELF 文件（有些工具使用BPF术语，有些使用eBPF术语，没有特别的原因；正如我之前所说，这些术语现在实际上是可互换）。
hello.bpf.o:    file format elf64-bpf
# 接下来是标记为 xdp 节的反汇编，与C源代码中的SEC()定义相匹配。
Disassembly of section xdp:
# 这个节是一个名为 hello 的函数。
0000000000000000 <hello>:
# 对应于源代码行 bpf_printk("Hello World %d", counter");，eBPF 字节码指令有五行，
;     bpf_printk("Hello World %d", counter);
       0:       18 06 00 00 00 00 00 00 00 00 00 00 00 00 00 00 r6 = 0 ll
       2:       61 63 00 00 00 00 00 00 r3 = *(u32 *)(r6 + 0)
       3:       18 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 r1 = 0 ll
       5:       b7 02 00 00 0f 00 00 00 r2 = 15
       6:       85 00 00 00 06 00 00 00 call 6
# 三行 eBPF 字节码指令递增计数器变量。
;     counter++;
       7:       61 61 00 00 00 00 00 00 r1 = *(u32 *)(r6 + 0)
       8:       07 01 00 00 01 00 00 00 r1 += 1
       9:       63 16 00 00 00 00 00 00 *(u32 *)(r6 + 0) = r1
# 另外两行字节码是由源代码 return XDP_PASS; 生成的。
;     return XDP_PASS;
      10:       b7 00 00 00 02 00 00 00 r0 = 2
      11:       95 00 00 00 00 00 00 00 exit
```

除非您特别想这样做，否则没有必要确切了解每行字节码与源代码的关系。编译器负责生成字节码，这样您就不必考虑它！但让我们稍微详细地检查一下输出，以便您可以了解该输出与本章前面学到的 eBPF 指令和寄存器之间的关系。

在每行字节码的左侧，您可以看到该指令在内存中相对于 hello 所在位置的偏移量。正如本章前面所述，eBPF 指令通常是 8 字节长，而在 64 位平台上，每个内存位置可以容纳 8 字节，因此偏移量通常每个指令递增一次。然而，该程序中的第一条指令恰好是一个需要 16 字节的宽指令编码，以便将寄存器 6 设置为一个 64 位值 0。这使得第二行输出中的指令位于偏移量为 2 的位置。之后又有一个 16 字节的指令，将寄存器 1 设置为一个 64 位值 0。之后，剩下的指令每行都占据 8 个字节，因此偏移量递增 1。

每行的第一个字节是操作码，它告诉内核要执行的操作是什么，在指令行的右侧是人类可读的指令解释。截至撰写本文时，Iovisor 项目提供了最完整的 eBPF 操作码[文档](https://github.com/iovisor/bpf-docs/blob/master/eBPF.md)，但官方的 [Linux 内核文档](https://docs.kernel.org/bpf/instruction-set.html)正在迎头赶上，并且 eBPF 基金会正在制定与特定操作系统无关的[标准文档](https://github.com/ietf-wg-bpf/ebpf-docs)。

例如，我们来看一下偏移量为 5 的指令，如下所示：

```bash
5:       b7 02 00 00 0f 00 00 00 r2 = 15
```

对于这个指令，它的操作码是`0xb7`，并且根据文档的说明，对应的伪代码是 `dst = imm`，可以理解为“将目标设置为立即数”。第二个字节（0x02）定义了目标，表示“寄存器 2”。这里的“立即”（或字面）数是 0x0f，即十进制的 15。因此，我们可以理解这个指令告诉内核“将寄存器 2 设置为值 15”。这与指令右侧的输出相符：`r2 = 15`。

偏移量 10 处的指令类似：

```bash
10:       b7 00 00 00 02 00 00 00 r0 = 2
```

这行代码同样使用了`0xb7`作为操作码，这次是将寄存器 0 的值设置为 2。当一个 eBPF 程序运行结束时，寄存器 0 中保存了返回值，而 XDP_PASS 的值为 2。这与源代码中的逻辑一致，始终返回 XDP_PASS。

现在您知道 hello.bpf.o 包含字节码形式的 eBPF 程序。下一步是将其加载到内核中。

## 将程序加载到内核中

在这个例子中，我们将使用一个名为 bpftool 的实用工具来加载和管理 eBPF 程序。另外，您也可以以编程方式加载程序，在本书的后面部分您会看到这方面的例子。

> 提示
> 某些 Linux 发行版提供了包含 bpftool 的软件包，或者您可以[从源代码编译它](https://github.com/libbpf/bpftool)。您可以在[Quentin Monnet 的博客](https://qmonnet.github.io/whirl-offload/2021/09/23/bpftool-features-thread/)中找到有关安装或构建此工具的更多详细信息，也可以在[Cilium 网站](https://docs.cilium.io/en/latest/bpf/#bpftool)上找到更多文档和用法。

下面是一个使用 bpftool 将程序加载到内核的例子。注意，您可能需要 root 权限（或使用 sudo）来获得 bpftool 所需的 BPF 权限。

```bash
$ bpftool prog load hello.bpf.o /sys/fs/bpf/hello
```

这将从我们编译的目标文件中加载 eBPF 程序，并将其“固定”在位置`/sys/fs/bpf/hello`上。（通常情况下，这是可选的，eBPF 程序可以加载到内核中而不必固定到文件位置上，但对于 bpftool 来说是不可选的，它始终必须将加载的程序固定下来。这个原因在“BPF 程序和 Map 引用”一节中有进一步的解释。）该命令没有输出响应表示成功，您也可以使用`ls`确认程序已就位：

```bash
$ ls /sys/fs/bpf
hello
```

eBPF 程序已成功加载。让我们使用 bpftool 工具了解有关该程序及其在内核中的状态的更多信息。

## 检查加载的程序

bpftool 实用程序可以列出加载到内核中的所有程序。如果您自己尝试，可能会在此输出中看到几个预先存在的 eBPF 程序，但为了清晰起见，我将只显示与我们的“Hello World”示例相关的行：

```bash
$ bpftool prog list
...
540: xdp name hello tag d35b94b4c0c10efb gpl
    loaded_at 2022-08-02T17:39:47+0000 uid 0
    xlated 96B jited 148B memlock 4096B map_ids 165,166
    btf_id 254
```

该程序被分配了 ID 540。这个标识是在加载程序时为每个程序分配的一个数字。通过知道该 ID，您可以要求 bpftool 显示有关此程序的更多信息。这次，让我们以美化的 JSON 格式获取输出，以便字段名称和值都可以看到：

```bash
$ bpftool prog show id 540 --pretty
{
    "id": 540,
    "type": "xdp",
    "name": "hello",
    "tag": "d35b94b4c0c10efb",
    "gpl_compatible": true,
    "loaded_at": 1659461987,
    "uid": 0,
    "bytes_xlated": 96,
    "jited": true,
    "bytes_jited": 148,
    "bytes_memlock": 4096,
    "map_ids": [165,166
    ],
    "btf_id": 254
}
```

根据字段名称，很多内容很容易理解：

- 程序 ID 是 540
- type 字段告诉我们这个程序可以通过 XDP 事件附加到网络接口上。还有其他类型的 BPF 程序可以附加到不同类型的事件上，我们将在第 7 章中详细讨论这一点。
- 程序的名称是 hello，这是源代码中的函数名。
- 标签（tag）是该程序的另一个标识符，稍后我将详细介绍。
- 程序采用 GPL 兼容许可证。
- 有一个时间戳显示程序加载的时间。
- 用户 ID 0（即 root）加载了该程序。
- 这个程序中有 96 个字节的翻译后的 eBPF 字节码，我很快就会给您展示。
- 这个程序已经进行了即时编译，并且编译结果是 148 个字节的机器码。我很快就会解释这部分内容。
- `bytes_memlock` 字段告诉我们，这个程序保留了 4,096 字节的内存，不会被分页。
- 这个程序引用了 ID 为 165 和 166 的 BPF Map。这可能令人惊讶，因为源代码中没有明显的对 Map 的引用。在本章的后面部分，您将看到在 eBPF 程序中如何使用 Map 语法来处理全局数据。
- 您将在第 5 章学习有关 BTF 的内容，现在只需要知道`btf_id`表示此程序有一个 BTF 信息块。只有在使用`-g`标志进行编译时，才会将此信息包含在目标文件中。

### BPF 程序标签（tag）

标签（tag）是所有程序指令的 SHA（Secure Hashing Algorithm，安全哈希算法）散列值，可以用作程序的另一个标识符。ID 可能在每次加载或卸载程序时发生变化，但标签将保持不变。bpftool 实用程序可以通过 ID、名称、标签或固定路径来引用 BPF 程序，因此在此示例中，以下所有内容将提供相同的输出：

- `bpftool prog show id 540`
- `bpftool prog show name hello`
- `bpftool prog show tag d35b94b4c0c10efb`
- `bpftool prog show pinned /sys/fs/bpf/hello`

您可以有多个相同名称程序，甚至可以有多个相同标签的程序实例，但 ID 和固定路径将始终是唯一的。

### 翻译后的字节码

`bytes_xlated`字段告诉我们有多少字节的“翻译后”eBPF 代码。这是通过验证器后的 eBPF 字节码（并且可能被内核修改，我将在本书后面讨论原因）。

让我们使用 bpftool 来显示“Hello World”代码的翻译版本：

```bash
$ bpftool prog dump xlated name hello
int hello(struct xdp_md * ctx):
; bpf_printk("Hello World %d", counter);
    0: (18) r6 = map[id:165][0]+0
    2: (61) r3 = *(u32 *)(r6 +0)
    3: (18) r1 = map[id:166][0]+0
    5: (b7) r2 = 15
    6: (85) call bpf_trace_printk#-78032
; counter++;
    7: (61) r1 = *(u32 *)(r6 +0)
    8: (07) r1 += 1
    9: (63) *(u32 *)(r6 +0) = r1
; return XDP_PASS;
    10: (b7) r0 = 2
    11: (95) exit
```

这看起来与您之前在 llvm-objdump 的输出中看到的反汇编代码非常相似。偏移地址是相同的，指令看起来也很相似——例如，我们可以看到偏移地址为 5 的指令是`r2=15`。

### JIT 编译的机器代码

翻译后的字节码相当低级，但它还不是完全的机器代码。 eBPF 使用 JIT 编译器将 eBPF 字节码转换为在目标 CPU 上本地运行的机器代码。 `bytes_jited` 字段显示，在此转换后，程序的长度为 108 字节。

> 提示
> 为了获得更高的性能，通常会对 eBPF 程序进行即时编译(JIT)。另一种选择是在运行时解释 eBPF 字节码。eBPF 指令集和寄存器的设计与本机机器指令相当接近，使得解释相对简单且相对快速，但编译后的程序将更快，并且大多数架构现在都支持 JIT。（启用 JIT 编译需要在内核中启用`CONFIG_BPF_JIT`配置选项，并且可以通过`net.core.bpf_jit_enable sysctl`设置在运行时启用或禁用 JIT 编译。关于不同芯片架构上的 JIT 支持的更多信息，请参阅[文档](https://docs.cilium.io/en/stable/bpf/#jit)。）

`bpftool`实用程序可以生成 eBPF 程序的 JIT 化代码的汇编语言转储。如果您对汇编语言不熟悉，不用担心，这些代码可能看起来完全无法理解！我只是为了说明从源代码到可执行的机器指令之间的所有转换过程。以下是命令及其输出的示例：

```bash
$ bpftool prog dump jited name hello
int hello(struct xdp_md * ctx):
bpf_prog_d35b94b4c0c10efb_hello:
; bpf_printk("Hello World %d", counter);
    0: hint #34
    4: stp x29, x30, [sp, #-16]!
    8: mov x29, sp
    c: stp x19, x20, [sp, #-16]!
    10: stp x21, x22, [sp, #-16]!
    14: stp x25, x26, [sp, #-16]!
    18: mov x25, sp
    1c: mov x26, #0
    20: hint #36
    24: sub sp, sp, #0
    28: mov x19, #-140733193388033
    2c: movk x19, #2190, lsl #16
    30: movk x19, #49152
    34: mov x10, #0
    38: ldr w2, [x19, x10]
    3c: mov x0, #-205419695833089
    40: movk x0, #709, lsl #16
    44: movk x0, #5904
    48: mov x1, #15
    4c: mov x10, #-6992
    50: movk x10, #29844, lsl #16
    54: movk x10, #56832, lsl #32
    58: blr x10
    5c: add x7, x0, #0
; counter++;
    60: mov x10, #0
    64: ldr w0, [x19, x10]
    68: add x0, x0, #1
    6c: mov x10, #0
    70: str w0, [x19, x10]
; return XDP_PASS;
    74: mov x7, #2
    78: mov sp, sp
    7c: ldp x25, x26, [sp], #16
    80: ldp x21, x22, [sp], #16
    84: ldp x19, x20, [sp], #16
    88: ldp x29, x30, [sp], #16
    8c: add x0, x7, #0
    90: ret
```

> 提示
> 某些预打包的 bpftool 发行版可能尚未包含转储 JIT 输出的支持。如果出现这种情况，您会看到“错误：无 libbfd 支持”。您可以按照[https://github.com/libbpf/bpftool](https://github.com/libbpf/bpftool)上的说明自行构建 bpftool。

您已经看到了“Hello World”程序已经被加载到内核中，但是此时它尚未与事件关联，因此没有任何东西会触发它运行。它需要被附加到一个事件上。

## 附加到事件

程序的类型必须与其附加的事件类型匹配；您将在第 7 章中学到更多相关内容。在这种情况下，它是一个 XDP 程序，您可以使用 bpftool 将示例 eBPF 程序附加到网络接口上的 XDP 事件，如下所示：

```bash
$ bpftool net attach xdp id 540 dev eth0
```

> 提示
> 在撰写本文时，bpftool 工具还不支持附加所有类型的程序，但它最近已经扩展为自动附加 k(ret)probe、u(ret)probe 和 tracepoint。

在这个示例中，我使用了程序的 ID 540，但您也可以使用名称（前提是它是唯一的）或标签来标识被附加的程序。在这个例子中，我将程序附加到了网络接口`eth0`。

您可以使用 bpftool 查看所有网络附加的 eBPF 程序：

```bash
$ bpftool net list
xdp:
eth0(2) driver id 540

tc:

flow_dissector:
```

ID 为 540 的程序已经附加到`eth0`接口的 XDP 事件上。这个输出还提供了关于网络堆栈中其他潜在事件的一些线索，您可以将 eBPF 程序附加到这些事件上，例如`tc`和`flow_dissector`。更多内容请参阅第 7 章。

您还可以使用`ip link`命令检查网络接口，输出结果类似于以下内容（为了清晰起见，删除了一些细节）:

```bash
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT
group default qlen 1000
    ...
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 xdp qdisc fq_codel state UP
mode DEFAULT group default qlen 1000
    ...
    prog/xdp id 540 tag 9d0e949f89f1a82c jited
    ...
```

在这个例子中有两个接口：回环接口 lo，用于将流量发送给本机上的进程；以及 eth0 接口，用于连接本机与外部世界。这个输出还显示，eth0 接口有一个 JIT 编译的 eBPF 程序，其 ID 为`540`，标签为`9d0e949f89f1a82c`，附加到了它的 XDP 钩子上。

> 提示
> 您也可以使用`ip link`命令将 XDP 程序附加到网络接口或将其从接口中分离。我在本章的末尾包含了一个相关练习，并且在第 7 章中还有更多示例。

在此阶段，每次接收到网络数据包时，hello eBPF 程序都会生成跟踪输出。您可以通过运行`cat /sys/kernel/debug/tracing/trace_pipe`来检查。这将显示类似以下内容的大量输出：

```bash
<idle>-0    [003] d.s.. 655370.944105: bpf_trace_printk: Hello World 4531
<idle>-0    [003] d.s.. 655370.944587: bpf_trace_printk: Hello World 4532
<idle>-0    [003] d.s.. 655370.944896: bpf_trace_printk: Hello World 4533
```

如果您记不住跟踪管道的位置，可以使用`bpftool prog tracelog`命令获得相同的输出。

与您在第 2 章中看到的输出相比，这次每个事件都没有与之相关联的命令或进程 ID；相反，您会在每行跟踪的开头看到`<idle>-0`。在第 2 章中，每个系统调用事件的触发是因为在用户空间执行命令的进程调用了系统调用 API。该进程 ID 和命令是执行 eBPF 程序的上下文的一部分。但是在这个示例中，XDP 事件是由网络数据包的到达触发的。这个数据包没有与之相关联的用户空间进程——在触发 hello eBPF 程序时，系统除了将数据包接收到内存中之外，对数据包没有做任何处理，也不知道数据包的内容或目的地。

正如预期的那样，您可以看到计数器的值每次递增 1。在源代码中，counter 是一个全局变量。让我们看看在 eBPF 中如何使用 Map 来实现这个功能。

## 全局变量

正如您在上一章中学到的那样，eBPF Map 是一种数据结构，可以在 eBPF 程序或用户空间中进行访问。由于同一个 Map 可以被同一个程序的多次运行重复访问，它可以用于在一个执行和下一个执行之间保存状态。多个程序也可以访问同一个 Map。由于这些特性，Map 的语法可以被用作全局变量。

> 提示
> 在 2019 年添加对[全局变量](https://lore.kernel.org/bpf/20190228231829.11993-7-daniel@iogearbox.net/t/#u)的支持之前，eBPF 程序员必须显式编写 Map 来执行相同的任务。

在前面，您看到 bpftool 显示了这个示例程序使用了两个具有标识符 165 和 166 的 Map。（如果您自己尝试，可能会看到不同的标识符，因为标识符在 Map 在内核中创建时分配。）让我们来探索一下这些 Map 中的内容。

bpftool 实用程序可以显示加载到内核中的 Map。为了清晰起见，我只展示与示例“Hello World”程序相关的条目 165 和 166：

```bash
$ bpftool map list
165: array name hello.bss   flags 0x400
    key 4B value 4B max_entries 1 memlock 4096B
    btf_id 254
166: array name hello.rodata flags 0x80
    key 4B value 15B max_entries 1 memlock 4096B
    btf_id 254 frozen
```

从 C 程序编译的目标文件中的 bss （这里，bss 代表 block started by symbol）节通常保存全局变量，您可以使用 bpftool 检查其内容，如下所示：

```bash
$ bpftool map dump name hello.bss
[{
        "value": {
            ".bss": [{
                    "counter": 11127
                }
            ]
        }
    }
]
```

我还可以使用 `bpftool map dump id 165` 来检索相同的信息。如果我再次运行这些命令中的任何一个，就会看到计数器增加了，因为每接收到一个网络数据包，程序都会运行一次。

正如您将在第 5 章中了解到的那样，如果存在 BTF 信息，bpftool 可以对映射中的字段名称（在这里是变量名 counter）进行漂亮的打印，而只有在使用 -g 标志进行编译时才会包含该信息。如果在编译过程中省略了该标志，您将看到类似于以下内容的输出：

```bash
$ bpftool map dump name hello.bss
key: 00 00 00 00 value: 19 01 00 00
Found 1 element
```

没有 BTF 信息，bpftool 无法知道源代码中使用的变量名称。由于这个 Map 中只有一个项目，因此可以推断出，十六进制值 19 01 00 00 必定是 counter 的当前值（十进制为 281，因为字节的顺序最低有效位）。

您在这里看到 eBPF 程序使用 Map 的语法来读取和写入全局变量。正如您通过检查其他 Map 所看到的那样，地图也用于保存静态数据。

另一个命名为 hello.rodata 的 Map ，暗示了这可能是与我们的 hello 程序相关的只读数据。您可以转储该 Map 的内容，会看到它保存了用于跟踪的字符串：

```bash
$ bpftool map dump name hello.rodata
[{
        "value": {
            ".rodata": [{
                "hello.____fmt": "Hello World %d"
                }
            ]
        }
    }
]
```

如果您没有使用 -g 标志编译目标文件，您将看到如下所示的输出：

```bash
$ bpftool map dump id 166
key: 00 00 00 00    value: 48 65 6c 6c 6f 20 57 6f  72 6c 64 20 25 64 00
Found 1 element
```

该 Map 中有一个键值对，该值包含以 0 结尾的 12 个字节的数据。这些字节是字符串“Hello World %d”的 ASCII 表示形式，您可能不会感到惊讶。

现在我们已经完成了该程序及其 Map 的检查，是时候清理它了。我们首先将其与触发它的事件分离。

## 分离程序（Detaching the Program）

您可以像这样将程序从网络接口上分离：

```bash
$ bpftool net detach xdp dev eth0
```

如果该命令运行成功，则没有任何输出，但您可以通过 `bpftool net list` 命令的输出缺少 XDP 条目来确认程序已不再附加：

```bash
$ bpftool net list
xdp:

tc:

flow_dissector:
```

然而，该程序仍然被加载到内核中：

```bash
$ bpftool prog show name hello
395: xdp name hello tag 9d0e949f89f1a82c gpl
    loaded_at 2022-12-19T18:20:32+0000 uid 0
    xlated 48B jited 108B memlock 4096B map_ids 4
```

## 卸载程序

没有 `bpftool prog load` 的相反操作（至少在撰写本文时没有），但您可以通过删除固定的伪文件来从内核中移除该程序：

```bash
$ rm /sys/fs/bpf/hello
$ bpftool prog show name hello
```

该 bpftool 命令没有输出，因为程序不再被加载到内核中。

## BPF 到 BPF 调用（BPF to BPF Calls）

在上一章中，您看到了尾部调用的示例，并且我提到现在还可以在 eBPF 程序内部调用函数。让我们来看一个简单的例子，它可以像尾部调用示例一样附加到 sys_enter 跟踪点，但这次它将跟踪系统调用的操作码。您可以在 `chapter3/hello-func.bpf.c` 中找到代码。

出于说明目的，我编写了一个非常简单的函数，该函数从跟踪点参数中提取系统调用操作码：

```c
static __attribute((noinline)) int get_opcode(struct bpf_raw_tracepoint_args *ctx) {
    return ctx->args[1];
}
```

如果有选择的话，编译器可能会将这个非常简单的函数内联，因为我只会在一个地方调用它。由于这会破坏这个示例的目的，我添加了`__attribute((noinline))`来强制编译器执行。在正常情况下，您应该省略这个属性并允许编译器根据需要进行优化。

调用该函数的 eBPF 函数如下所示：

```c
SEC("raw_tp")
int hello(struct bpf_raw_tracepoint_args *ctx) {
    int opcode = get_opcode(ctx);
    bpf_printk("Syscall: %d", opcode);
    return 0;
}
```

将其编译为 eBPF 目标文件后，您可以使用 bpftool 将其加载到内核中并确认它已加载：

```bash
$ bpftool prog load hello-func.bpf.o /sys/fs/bpf/hello
$ bpftool prog list name hello
893: raw_tracepoint name hello tag 3d9eb0c23d4ab186 gpl
    loaded_at 2023-01-05T18:57:31+0000 uid 0
    xlated 80B  jited 208B   memlock 4096B   map_ids 204
    btf_id 302
```

这个练习有趣的部分是检查 eBPF 字节码以查看`get_opcode()`函数：

```bash
$ bpftool prog dump xlated name hello
int hello(struct bpf_raw_tracepoint_args * ctx):
# 在这里您可以看到 hello() eBPF 程序调用 get_opcode()。偏移量 0 处的 eBPF 指令是 0x85，在指令集文档中对应于“函数调用”。执行不会执行位于偏移量 1 处的下一条指令，而是向前跳转 7 个指令 (pc+7)，这意味着偏移量 8 处的指令。
; int opcode = get_opcode(ctx);
    0: (85) call pc+7#bpf_prog_cbacc90865b1b9a5_get_opcode
; bpf_printk("Syscall: %d", opcode);
    1: (18) r1 = map[id:193][0]+0
    3: (b7) r2 = 12
    4: (bf) r3 = r0
    5: (85) call bpf_trace_printk#-73584
; return 0;
    6: (b7) r0 = 0
    7: (95) exit
# 这是 get_opcode() 的字节码，正如您所希望的那样，第一条指令位于偏移量 8 处。
int get_opcode(struct bpf_raw_tracepoint_args * ctx):
; return ctx->args[1];
    8: (79) r0 = *(u64 *)(r1 +8)
; return ctx->args[1];
    9: (95) exit
```

函数调用指令需要将当前状态放入 eBPF 虚拟机的堆栈中，以便当被调用函数退出时，可以在调用函数中继续执行。由于栈大小限制为 512 字节，因此 BPF 到 BPF 的调用不能嵌套太深。

> 提示
> 有关尾部调用和 BPF 到 BPF 调用的更多详细信息，请参阅 Jakub Sitnicki 在 Cloudflare 博客上发表的一篇精彩文章：[“Assembly within! BPF tail calls on x86 and ARM”](https://blog.cloudflare.com/assembly-within-bpf-tail-calls-on-x86-and-arm/)。

# 总结

在本章中，您看到了一些示例的 C 源代码是如何转换为 eBPF 字节码，并编译成机器代码以便在内核中执行的。您还学习了如何使用 bpftool 来检查加载到内核中的程序和 Map，并附加到 XDP 事件上。

此外，您还看到了由不同类型的事件触发的 eBPF 程序的示例。XDP 事件是在网络接口上到达数据包时触发的，而 kprobe 和 tracepoint 事件是通过命中内核代码中的某个特定点来触发的。我将在第 7 章中讨论其他 eBPF 程序类型。

您还了解了如何使用 Map 来实现 eBPF 程序的全局变量，并且了解了 BPF 到 BPF 函数的调用。

在下一章中，我将进一步详细介绍在 bpftool（或任何其他用户空间代码）加载程序并将其附加到事件时，在系统调用级别发生的事情。

## 练习

如果您想进一步探索 BPF 项目，可以尝试以下一些操作：

1. 尝试使用如下所示的 ip link 命令来附加和分离 XDP 程序：
   ```bash
   $ ip link set dev eth0 xdp obj hello.bpf.o sec xdp
   $ ip link set dev eth0 xdp off
   ```
2. 运行第 2 章中的任何 BCC 示例。程序运行时，使用第二个终端窗口通过 bpftool 检查加载的程序。这是我通过运行 hello-map.py 示例所看到的：
   ```bash
   $ bpftool prog show name hello
   197: kprobe name hello tag ba73a317e9480a37 gpl
       loaded_at 2022-08-22T08:46:22+0000 uid 0
       xlated 296B jited 328B memlock 4096B map_ids 65
       btf_id 179
       pids hello-map.py(2785)
   ```
   您还可以使用 `bpftool prog dump` 命令来查看这些程序的字节码和机器代码。
3. 在 chapter2 目录下运行`hello-tail.py`，当它运行时，看看它加载的程序。您会看到每个尾部调用程序都被单独列出，就像这样：
   ```bash
   $ bpftool prog list
   ...
   120: raw_tracepoint name hello tag b6bfd0e76e7f9aac gpl
       loaded_at 2023-01-05T14:35:32+0000 uid 0
       xlated 160B jited 272B memlock 4096B map_ids 29
       btf_id 124
       pids hello-tail.py(3590)
   121: raw_tracepoint name ignore_opcode tag a04f5eef06a7f555 gpl
       loaded_at 2023-01-05T14:35:32+0000 uid 0
       xlated 16B jited 72B memlock 4096B
       btf_id 124
       pids hello-tail.py(3590)
   122: raw_tracepoint name hello_exec tag 931f578bd09da154 gpl
       loaded_at 2023-01-05T14:35:32+0000 uid 0
       xlated 112B jited 168B memlock 4096B
       btf_id 124
       pids hello-tail.py(3590)
   123: raw_tracepoint name hello_timer tag 6c3378ebb7d3a617 gpl
       loaded_at 2023-01-05T14:35:32+0000 uid 0
       xlated 336B jited 356B memlock 4096B
       btf_id 124
       pids hello-tail.py(3590)
   ```
   您还可以使用 `bpftool prog dump xlated` 来查看字节码指令，并将它们与您在“BPF 到 BPF 调用”中看到的内容进行比较。
4. _请谨慎对待此问题，最好只是思考为什么会发生这种情况，而不是尝试实际操作！_ 如果您从 XDP 程序返回一个 0 值，这对应于 XDP_ABORTED，它告诉内核中止对该数据包的任何进一步处理。这可能有些违反直觉，因为在 C 中，0 通常表示成功，但事实就是如此。因此，如果您尝试修改程序返回 0，并将其附加到虚拟机的 eth0 接口，所有的网络数据包都将被丢弃。如果您正在使用 SSH 连接到该机器，这将是非常不幸的，并且您可能需要重新启动机器以恢复访问！
   您可以在容器内运行该程序，以便将 XDP 程序附加到虚拟以太网接口，该接口仅影响该容器而不影响整个虚拟机。 [https://github.com/lizrice/lb-from-scratch](https://github.com/lizrice/lb-from-scratch) 上有一个执行此操作的示例。
