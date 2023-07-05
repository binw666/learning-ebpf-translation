# 第2章 eBPF的Hello World
在上一章中，我讨论了为什么eBPF如此强大，但如果你还没有对运行eBPF程序有一个具体的理解，那也没关系。在本章中，我将使用一个简单的“Hello World”示例来帮助你更好地理解它。

正如你在阅读本书时会了解到的，有几种不同的库和框架可用于编写eBPF应用程序。作为热身，我将向你展示从编程角度来看可能最易于理解的方法：使用[BCC Python框架](https://github.com/iovisor/bcc)。这提供了一种非常简单的方式来编写基本的eBPF程序。出于我将在第5章中介绍的原因，对于分发给其他用户的生产应用程序，这不一定是我推荐的方法，但对于初学者来说非常棒。

> 提示
> 如果你想自己试试这段代码，可以在 [https:// github.com/lizrice/learning-ebpf](https://github.com/lizrice/learning-ebpf) 的chapter2目录下找到。
> 你可以在[https://github.com/iovisor/bcc](https://github.com/iovisor/bcc) 找到BCC项目，安装BCC的说明在 [https://github.com/iovisor/bcc/blob/master/INSTALL.md](https://github.com/iovisor/bcc/blob/master/INSTALL.md) 。

## BCC的Hello World
下面是`hello.py`的全部源代码，这是一个使用BCC的Python库编写的eBPF "Hello World "应用程序：

```python
#!/usr/bin/python3  
from bcc import BPF

program = r"""
int hello(void *ctx) {
    bpf_trace_printk("Hello World!");
    return 0;
}
"""

b = BPF(text=program)
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")

b.trace_print()
```

这段代码包括两部分：在内核中运行的eBPF程序和将eBPF程序加载到内核并读取其生成的跟踪信息的用户空间代码。正如你在图2-1中所看到的那样，`hello.py`是这个应用程序的用户空间部分，而`hello()`是在内核中运行的eBPF程序。

![Alt text](figure-2-1.png)

图2-1. "Hello World"的用户空间和内核部分

让我们深入研究源代码的每一行以更好地理解它。

第一行告诉你这是Python代码，可以运行它的程序是Python解释器（/usr/bin/python）。

eBPF程序本身是用C编写的，就是这部分：

```c
int hello(void *ctx) {
    bpf_trace_printk("Hello World!");
    return 0;
}
```

eBPF 程序所做的只是使用辅助函数 `bpf_trace_printk()` 来写入消息。辅助函数是“extended” BPF 与其 “classic” 前身的另一个区别。它们是 eBPF 程序可以调用来与系统交互的一组函数；我将在第 5 章中进一步讨论它们。现在你可以将其看作打印一行文本。

整个eBPF程序在Python代码中被定义为一个名为program的字符串。该 C 程序需要先进行编译才能执行，但 BCC 会为您处理好。 （你将在下一章中看到如何自己编译 eBPF 程序）你所需要做的就是在创建 BPF 对象时将此字符串作为参数传递，如下行所示：

```python
b = BPF(text=program)
```

eBPF 程序需要附加到一个事件，在这个例子中，我选择附加到系统调用 `execve`，这是用于执行程序的系统调用。无论何时，任何东西或任何人在这台机器上启动一个新的程序执行，这将调用`execve()`，这将触发eBPF程序。虽然“execve()”名称是Linux中的标准接口，但在内核中实现它的函数名称取决于芯片架构，但BCC给了我们一个方便的方法来查询我们运行的机器的函数名称：

```python
syscall = b.get_syscall_fnname("execve")
```

现在，`syscall`代表我要使用`kprobe`附加到的内核函数的名称（在第1章中已经介绍了`kprobe`的概念）。你可以像这样将`hello`函数附加到该事件上：

```python
b.attach_kprobe(event=syscall, fn_name="hello")
```

此时，eBPF 程序被加载到内核中并附加到一个事件，因此每当机器上启动新的可执行文件时，该程序就会被触发。 Python 代码中剩下要做的就是读取内核输出的跟踪信息并将其输出到屏幕上：


```python
b.trace_print()
```

这个`trace_print()`函数将无限循环显示所有跟踪信息（直到你停止程序，也许使用`Ctrl+C`）。