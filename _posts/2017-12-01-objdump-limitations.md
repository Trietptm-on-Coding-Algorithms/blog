---
title: 基于Objdump的反汇编器存在的限制
tags: [RE]
layout: post
categories: crack
---

objdump总是会期望处理一个被gcc很好地编译生成的可执行文件，然而通常情况下的程序文件，有些可能就是直接由代码汇编，有些却使用了一些技巧来对抗反汇编。接下来就大致介绍一下objdump存在的一些缺陷

## objdump过于依赖节区头(section headers)

一个ELF可执行文件"通常"包含正确的节区头。而对系统的程序加载器而言，有没有节区头根本无关紧要，关键是获取程序的程序头(program headers)。
故而，最常见的反汇编技巧就是丢弃/处理掉ELF文件的节区头，或是覆写掉，伪造大小等等。
一旦处理过后，objdump就会拒绝进行反汇编。

## objdump不会跟踪执行流

不跟踪代码执行流，objdump可以很轻易地被玩弄，仅仅反汇编了少许行就停下。这意味着objdump无法识别函数，也无法识别误认作"数据"中的代码

另一种常见的技巧是插入垃圾指令并跳过这些指令以对齐执行流中的汇编代码。
例如：当一个指令跳转到下一条指令的中间，而objdump不会从跳转的目的地址进行汇编，而是从下一条指令继续反汇编，也就使得垃圾指令被"组合"成一条新的指令。

``` asm
start:
	jmp label+1
label: 	
	DB 0x90
	mov eax, 0xf001
```

对应的objdump反汇编代码如下

``` asm
08048080 <start>:
  8048080: 	e9 01 00 00 00 	jmp 8048086 <label+0x1>
08048085 <label>:
  8048085: 	90 		nop
  8048086: 	b8 01 f0 00 00 	mov eax,0xf001
```

但是如果将`0x90`改成`0xe9`，那么objdump就不会优先考虑jmp的目的地址处的代码，而是将`0xe9`作为下一条指令的一部分进行反汇编。

```
start:
	jmp label+1
label: 	
	DB 0xE9
	mov eax, 0xf001
```

对应的objdump反汇编代码如下

```
08048080 <start>:
  8048080: 	e9 01 00 00 00 	jmp 8048086 <label+0x1>
08048085 <label>:
  8048085: 	e9 b8 01 f0 00 	jmp 8f48242 <__bss_start+0xeff1b6>
```

也就是`e9 b8 01 f0 00 	jmp 8f48242 <__bss_start+0xeff1b6>`



