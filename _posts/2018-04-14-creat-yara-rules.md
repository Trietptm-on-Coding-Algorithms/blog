---
title:  编写YARA规则检测恶意软件
tags: [RE, malware]
layout: post
categories: 
- tutorials
- translations
---

## 简介

我们都知道, 黑掉漏洞百出的代码比修补代码有趣得多. 但只会入侵的黑客并不一定能满足雇主的需求. 一些公司就希望安全研究人员能够基于他们收集和发现的恶意软件样本或泄露数据进行补丁. 

本文适合人群: 新手和爱好者

### 阅读本文需要的知识

其实并不需要太多知识要求, 当你对恶意软件分析和逆向工程理解越深, 你就越有独特的方式捕获恶意软件. 不过这并不妨碍你写出惊人的yara规则出来. 我所见过的大部分规则都相当基础. 大部分看上去就像5分钟就能写好的python脚本. 编写规则, yara规则本身十分简单, 真正的技巧和细节都在分析部分 . 

* 熟悉GNU Linux
* 熟悉C语言语法(不作要求, 但十分有用)
* 正则表达式 (同上, 不作要求, 但很有用)

### 声明

我是自学yara规则, 学校并没有教我这些. 我学习yara大约有30个小时, 花费了我一个周末的时间. 

## 大纲

我将介绍以下内容:

1. 规则标识符
2. Yara关键字
3. 字符串
    1. 十六进制值
    2. 文本字符串
    3. 字符串修饰符
    4. 正则表达式
    5. 字符串集
    6. 匿名字符串
4. 条件
    1. 布尔值
    2. 字符串实例计数
    3. 字符串偏移或虚拟地址
    4. 匹配长度
    5. 文件大小
    6. 可执行程序入口点
    7. 访问指定位置的数据
    8. 对多字符串应用同一条件
    9. 迭代字符串出现次数
5. 引用其他规则
6. Yara要点
    1. 全局规则
    2. 私有规则
    3. 规则标签
    4. 元数据
    5. 使用模块
    6. 未定义值
    7. 外部变量/参数值
    8. 文件包含

让我们现在开始吧.

---

Yara与C语言语法十分相像, 以下是一个简单的规则, 这个规则没有进行任何操作:

``` c
rule HelloRule 
{
condition:
false
}
```

## 规则标识符

规则标识符是上面简单规则示例中跟在`rule`后的词,  比如单词"dummy"也可以是一个规则标识符, 标识符命名有如下要求:

*  是由英文字母或数字组成的字符串
*  可以使用下划线字符
*  第一个字符不能是数字
*  对大小写敏感
*  不能超出128个字符长度


## Yara关键字

下面这些词不能用作规则标识符, 因为这些单词在yara语言里有特定用处

> all, and, any, ascii, at, condition, contains entrypoint, false, filesize, fullword, for, global, in import, include, int8,  nt16, int32, int8be, int16be int32be, matches, meta, nocase, not, or, of private, rule, strings, them, true, uint8, uint16 uint32,  int8be, uint16be, uint32be, wide

通常yara有两部分: **字符串定义**和**条件**


``` c
rule HelloRule2    // This is an example
{
    strings:
        $my_text_string = "text here"
        $my_hex_string = { E2 34 A1 C8 23 FB }

    condition:
        $my_text_string or $my_hex_string
}
```

当发现有规则里定义的任意字符串, 规则就会生效. 如你所见, 你还可以在规则里添加注释. 

## 十六进制字符串

### 通配符

十六进制字符串可以用通配符表示, 通配符符号用"?"表示

``` c
rule GambitWildcard
{
    strings:
       $hex_string = { EF 44 ?? D8 A? FB }

    condition:
       $hex_string
}
```

这个规则可以匹配下面的两个字符串

```
EF 44 01 D8 AA FB
EF 44 AA D8 AB FB
```

### 不定长通配符

不定长的字符串可以用下面这个方法表示

``` c
rule MarioJump
{
        strings:
           $hex_string = { F4 23 [4-6] 62 B4 }

        condition:
           $hex_string
}
```

这个规则可以匹配下面的两个字符串

```
F4 23 01 02 03 04 62 B4
F4 23 AA BB CC DD EE FF 62 B4
```

当然无限长的字符串也是可以的. 

``` c
rule BuzzLightyear
{
        strings:
           $hex_string = { F4 23 [-] 62 B4 }

        condition:
           $hex_string
}
```

这个规则可以匹配下面的两个字符串

```
F4 23 AA FF 62 B4
F4 23 AA AA AA AA AA...FF FF 62 B4
```

### 有条件的字符串

你可以创建一个字符串应对多种情况

``` c
rule WorriedRabbit
{
    strings:
       $hex_string = { BA 21 ( DA BC | C6 ) A5 }

    condition:
       $hex_string
}
```

这个规则可以匹配下面的两个字符串

```
BA 21 DA BC A5
BA 21 C6 A5
```

### 混合

当然, 你也可以将上面这几种方法结合起来. 

``` c
rule WorriedGabmitLightyearJump
{
    strings:
       $hex_string = { BA ?? ( DA [2-4] | C6 ) A5 }

    condition:
       $hex_string
}
```

这个规则可以匹配下面的三个字符串

```
BA 01 DA 01 02 03 04 A5
BA AA C6 A5
BA FF DA 01 02 A5
```

## 文本字符串

除开使用十六进制字符串, 我们也还可以使用文本字符串

``` c
rule KimPossible
{
    strings:
        $alert_string = "Whats the Sitch"

    condition:
       $alert_string
}
```

你也可以像C语言那样使用如下的转义符:

``` c
\" 双引号
\\ 反斜杠
\t 水平制表符
\n 换行符
\xdd 以十六进制表示的任何字节
```


## 修饰符

### 不区分大小写的字符串

Yara默认对大小写敏感, 但你可以使用修饰符将其关闭

``` c
rule ThickSkin
{
    strings:
        $strong_string = "Iron" nocase

    condition:
        $strong_string
}
```

### 宽字符串

`wide`修饰符可以用来搜寻以2字节表示1字符这种方式编码的字符串, 这种宽字符串在许多二进制文件中都有出现. 如果字符串"FatTony"以2字节表示1字符的方式编码并在二进制文件中出现, 我们就可以使用`wide`修饰符将其捕获. 因为"FatTony"也可能是"fattony", 我们也可以添加`nocase`修饰符以免错过. 


``` c
rule FatTony
{
    strings:
        $fat_villain = "FatTony" wide nocase

    condition:
        $fat_villain
}
```

[!]重要提示: 请记住, 该修饰符只是将字符串中字符的ASCII码和\x00交错起来组成宽字符, 它并不支持包含非英文字符的UTF-16字符串. 要想对既有ASCII字符和宽字符的字符串进行搜索, 请使用如下命令: 

``` c
rule ASCIIFatTony
{
    strings:
        $fat_villain = "FatTony" wide ascii nocase

    condition:
        $fat_villain
}
```

字符串默认是ASCII编码, 所以如果你想单独用`ascii`搜索"FatTony", 你并不需要添加`ascii`修饰符

``` c
rule ASCIIFatTony
{
    strings:
        $fat_villain = "FatTony"

    condition:
        $fat_villain
}
```

如果你想在不使用`wide`和`nocase`修饰符的情况下进行搜索, 上述这个规则可以生效. 


### Fullwords修饰符

该修饰符可用于匹配那些前后没有附加其他字符的单词(全词匹配). 

``` c
rule ShadyDomain
{
    strings:
        $shady_domain = "faceebook" fullword

    condition:
       $shady_domain
}
```

这个规则可以匹配下面的三个字符串

```
www.faceebook.com
www.myportal.faceebook.com
https://secure.faceebook.com
```

但这个规则**不能**匹配以下的字符串:

```
www.myfaceebook.com
thefaceebook.com
```

两者区别在于匹配的全词前后可以附加特殊字符, 不能是普通字符. 

## 正则表达式

yara允许使用正则表达式, 不过要用正斜杠而非双引号括起来使用(像Perl编程那样)

``` c
rule RegularShow
{
    strings:
        $re1 = /md5: [0-9a-fA-F]{32}/
        $re2 = /state: (on|off)/

    condition:
        $re1 and $re2
}
```

该规则将捕获任何状态下找到的所有md5字符串.

你也可以在正则表达式中使用文本修饰符, 如**nocase**,**ascii**,**wide**和**fullword**. 

### 元字符

元字符是一个字符对计算机程序有特定含义(而非字面含义)的字符. 在正则表达式中, 有以下含义: 

```
** 引用下一个元字符
^ 匹配文件的开头
$ 匹配文件的末尾
| 多选
() 分组
[] 方括号字符类
```

也可以使用以下量词:

```
* 匹配0次或多次
+ 匹配1次或多次
? 匹配0次或1次
{n} 只匹配n次
{n, } 至少匹配n次
{ ,m} 至多匹配m次
{n,m} 匹配n到m次
```

也可以使用以下的转义符:

```
\t 水平制表符 (HT, TAB)
\n 换行符 (LF, NL)
\r 回车符 (CR)
\f 换页符 (FF)
\a 响铃
\xNN 十六进制代码为NN的字符
```

也可以使用以下字符类:

```
\w 匹配单词字符 (单词可由字母数字加"_"组成)
\W 匹配非单词字符
\s 匹配空白符
\S 匹配非空白字符
\d 匹配一个十进制数字字符
\D 匹配一个非数字字符
\b 匹配单词边界
\B 匹配非单词边界
```

### 字符串集

如果你想要中列表中选择一定数量的字符串, 你可以执行以下操作: 

```
rule MigosPresent
{
    strings:
        $m1 = "Quavo"
        $m2 = "Offset"
        $m3 = "Takeoff"

    condition:
        2 of ($m1,$m2,$m3)
}
```

如果`$m1`, `$m2`和`$m3`任意存在两个, 那么就满足上述规则中的条件. 

你还可以使用通配符来表示一个字符集. 像如下这样使用通配符`*`

```
rule MigosPresent
{
    strings:
        $m1 = "Quavo"
        $m2 = "Offset"
        $m3 = "Takeoff"

    condition:
        2 of ($m*)
}
```


要表示`strings`中的所有变量, 你可以使用关键字`them`

``` 
rule ThreeRappersPresent
{
    strings:
        $m1 = "Quavo"
        $m2 = "Offset"
        $m3 = "Takeoff"
        $q1 = "Cardi B"

    condition:
        3 of them // equivalent to 3 of ($*)
}
```

你可以使用任何返回数值的表达式. 以下是使用关键字`any`和`all`的一个示例

```
rule Squad
{
    strings:
        $m1 = "Quavo"
        $m2 = "Offset"
        $m3 = "Takeoff"
        $q1 = "Cardi B"

    condition:
        3 of them // equivalent to 3 of ($*)
        all of them
        any of ($*) and 2 of ($*)    // Fancy way of using any in a rule that requires 3.
}
```

### 带有of和for...of的匿名字符串

如果你没有专门引用字符串的事件, 你可以仅使用`$`来将它们全部引用. 

```
rule AnonymousStrings
{
    strings:
        $ = "dummy1"
        $ = "dummy2"

    condition:
        1 of them
}
```

## 条件

Yara允许通过and, or, 和not等相关运算符来表示布尔表达式, 算术运算符(+,-,*,%)和位运算符(&, |, <<, >>, ~, ^)也可用于数值表达式中. 

### 布尔运算

字符串标识符也可在条件中充当布尔变量, 其值取决于文件中相关字符串是否存在. 

```
rule Example
{
    strings:
        $hero1a = "Batman"
        $hero1b = "Robin"
        $hero2a = "Edward"
        $hero2b = "Alphonse"

    condition:
        ($hero1a or $hero1b) and ($hero2a or $hero2b)
}
```

### 计数字符串实例

有时我们不仅需要知道某个字符串是否存在, 还需要知道字符串在文件或进程内存中出现的次数. 每个字符串的出现次数由一个变量表示, 变量名是用`#`代替`$`的字符串标识符. 例如:

```
rule Ransomware
{
    strings:
        $a = "encrypted"
        $b = "btc"

    condition:
        #a == 2 and #b > 2
}
```

这个规则会匹配任何包含两个字符串`$a`以及出现至少两次字符串`$b`的文件或进程.

### 字符串偏移(虚拟地址)

在大多数情况下, 当在条件中使用字符串标识符, 我们都只需知道关联的字符串是否在文件或进程内存内就行了. 但有时我们还是需要知道该字符串是否在文件的某个特定偏移处, 或是在进程地址空间的某个虚拟地址处. 在这种情况下, 我们就需要操作符`at`.

```
rule Offset
{
    strings:
        $a = "encrypted"
        $b = "btc"

    condition:
        $a at 100 and $b at 200
}
```

如果在文件的偏移100处(或者在一个正在运行的进程中, 位于虚拟地址100位置)发现了字符串`$a`, 我们的规则就能捕获到该字符串. 当然字符串`$b`也要在偏移200位置上才行. 你也可以使用十六进制表示而不一定要十进制.

```
rule Offset
{
    strings:
        $a = "encrypted"
        $b = "btc"

    condition:
        $a at 0x64 and $b at 0xC8
}
```

`at`操作符指定到一个具体的偏移量, 而你可以使用操作符`in`来指定字符串的位置范围. 

```
rule InExample
{
    strings:
        $a = "encrypted"
        $b = "btc"

    condition:
        $a in (0..100) and $b in (100..filesize)
}
```

字符串`$a`必须在偏移0-100之间才能找到, 而`$b`则必须是在偏移100到文件末尾位置(才能找到).

你也可以使用`@a[i]`来取得字符串`$a`第`i`个字符的偏移量或虚拟地址. 字符串索引以`1`开头 , 故第1个字符是`@a[1]`, 第2个是`@[a2]`并依此类推, 而不是以`@a[0]`开始. 如果你提供的索引值大过字符串总共出现的次数. 那结果就将是值`NaN`(Not a Number, 非数字). 

### 匹配长度

对于包含跳转的许多正则表达式和十六进制字符串, 匹配长度用一个变量表示. 如果你有一个正则表达式`/fo*/`, 可以匹配字符串`fo`, `foo`和`fooo`, 那么各个的匹配长度都是不同的. 

在字符串标识符前加一个`!`得到匹配长度, 你就可以将匹配长度作为你条件的一部分. 跟你获取偏移时使用字符`@`类似, `!a[1]`是第一个匹配到的字符串`$a`的长度, 而`!a[2]`就是第二个匹配到的字符串的长度, 依此类推. `!a`是`!a[1]`的缩写. 

```
rule Hak5
{
    strings:
        $re1 = /hack*/    // Will catch on hacker, hacked, hack, hack*

    condition:
        !re1[1] == 4 and !re1[2] > 6
}
```
该规则可以匹配如下字符串:

```
We hack things. We are hackers.
```

第一个`hack`是`re1[1]`且其长度等于4. 第二个`hack`长度则至少为6

### 文件大小

字符串标识符并不是唯一可以在条件中出现的变量(实际上, 可以不定义任何字符串来编写一个规则), 还可以使用其他变量. `filesize`就保存着正在扫描的文件的大小. 大小以字节为单位. 

```
rule FileSizeExample
{
    condition:
       filesize > 200KB
}
```

我们可以使用后缀`KB`将文件大小设置为`200KB`, 它会自动将常量的值乘上1024, 后缀`MB`会可以将值乘以`2^20`. 这两个后缀都只能用于十进制常量

[!]重要提示: `filesize`仅在规则应用于文件的时候生效. 如果应用于正在运行的进程, 那么它会永远都匹配不了.

### 可执行程序入口点

如果我们正扫描的文件是一个PE或ELF文件, 那么变量`entry_point`会存有可执行文件的入口点偏移值. 而如果我们正扫描一个运行的进程, 那么`entry_point`会存有可执行文件入口点的虚拟地址. 变量`entry_point`的经典用法是用于搜索入口点的一些pattern, 以检测壳或简单的感染病毒. 目前使用`entry_point`的方式是通过导入PE和/或ELF的库并使用它们各自的功能. Yara的`entrypoint`函数自第3版开始就已经过时了. 以下是它在第3版之前的样子. 

```
rule EntryPointExample1
{
    strings:
        $a = { E8 00 00 00 00 }

    condition:
       $a at entrypoint
}

rule EntryPointExample2
{
    strings:
        $a = { 9C 50 66 A1 ?? ?? ?? 00 66 A9 ?? ?? 58 0F 85 }

    condition:
       $a in (entrypoint..entrypoint + 10)
}
```


[!]重要提示: 再次强调, 不要使用yara的`entrypoint`, 请在导入PE或ELF文件后使用对应的`pe.entry_point`和`elf.entry_point`

### 访问指定位置的数据

如果你想从特定偏移位置读取数据, 并将其存为一个变量. 那么你可以使用以下任何一个方式: 

``` c
int8(<offset or virtual address>)
int16(<offset or virtual address>)
int32(<offset or virtual address>)

uint8(<offset or virtual address>)
uint16(<offset or virtual address>)
uint32(<offset or virtual address>)

int8be(<offset or virtual address>)
int16be(<offset or virtual address>)
int32be(<offset or virtual address>)

uint8be(<offset or virtual address>)
uint16be(<offset or virtual address>)
uint32be(<offset or virtual address>)
```

数据存储默认以小端序, 如果你想要读取大端序的整形数, 请使用下面几个以`be`结尾的对应函数. 

参数`<offset or virtual address>`可以是任何一个返回无符号整数的表达式, 包括可以是`uintXX`函数的返回值. 

```
rule IsPE
{
  condition:
     // MZ signature at offset 0 and ...
     uint16(0) == 0x5A4D and
     // ... PE signature at offset stored in MZ header at 0x3C
     uint32(uint32(0x3C)) == 0x00004550
}
```

### for…of: 对许多字符串应用同一个条件

要用for循环来检查一组字符串是否满足特定条件, 请使用如下语法:

```
for num of string_set : ( boolean_expression )
```

对每个`string_set`的字符串, 都会计算`boolean_expression`的值, 并且这些值必须至少有1个为真. 

当然你也可以使用其他关键字, 如`all`或`any`代替`num`来使用. 

```
for any of ($a,$b,$c) : ( $ at elf.entry_point  )
```

`$`表示集合中的所有字符串. 本例中, 它是字符串`$a`, `$b`和`$c`.

你也可以使用符号`#`和`@`来引用每一个字符串的出现次数和首字符偏移量. 

```
for all of them : ( # > 3 )
for all of ($a*) : ( @ > @b )
```

### 迭代字符串出现次数

如果你想对偏移迭代并测试条件. 你可以如下操作:

```
rule Three_Peat
{
    strings:
        $a = "dummy1"
        $b = "dummy2"

    condition:
        for all i in (1,2,3) : ( @a[i] + 10 == @b[i] )
}
```

这个规则说的是, `$b`出现前三个的字符串应当分别隔`$a`出现的前三个的字符串10个字节远. 另外一种写法如下:

```
for all i in (1..3) : ( @a[i] + 10 == @b[i] )
```

我们也可以使用表达式. 在本例中, 我们迭代每一次出现的`$a`(记住, `#a`代表`$a`的出现次数). 该规则指定, 每一次`$a`都应当出现在文件的前100个字节内. 

```
for all i in (1..#a) : ( @a[i] < 100 )
```

你也可以指定字符串的某一次出现需要满足条件(而非全部).

```
for any i in (1..#a) : ( @a[i] < 100 )
for 2 i in (1..#a) : ( @a[i] < 100 )
``` 

### 引用其他规则

就像C语言中引用函数那样. 函数, 或是这里说的规则, 都必须在使用前进行定义. 

```
rule Rule1
{
    strings:
        $a = "dummy1"

    condition:
        $a
}

rule Rule2
{
    strings:
        $a = "dummy2"

    condition:
        $a and Rule1
}
```

## Yara要点

### 全局规则

Yara允许用户在所有规则中进行约束. 如果你希望所有规则都忽略掉那些超出特定大小限制的文件, 那么你可以对规则进行必要的修改, 或是编写一条像以下这样的全局规则:

```
global rule SizeLimit
{
    condition:
        filesize < 2MB
}
```

你可以根据需要定义各种全局规则. 这些规则会在其他规则之前运行. 

### 私有规则

私有规则在匹配时没有任何输出. 当和其它规则成对引用时, 这样就可以使输出更为清楚. 比如为了判断文件是否恶意, 有这样一条私有规则, 要求文件必须是ELF文件. 一旦满足这个要求, 随后就会执行下一条规则. 但我们在输出里想看的并不是该文件它是不是ELF, 我们只想知道文件是否恶意, 那么私有规则就派上用场了.  要想创建一条私有规则, 只需要在`rule`前添加一个`private`即可. 

```
private rule PrivateRule
{
    ...
}
```

### 规则标签

如果你只想查看`ruleName`类型的规则输出, 你可以对你的规则打上标签

```
rule TagsExample1 : Foo Bar Baz
{
    ...
}

rule TagsExample2 : Bar
{
    ...
}
```

### 元数据

Yara允许在规则中存储一些额外数据. 

```
rule MetadataExample
{
    meta:
        my_identifier_1 = "Some string data"
        my_identifier_2 = 24
        my_identifier_3 = true

    strings:
        $my_text_string = "text here"
        $my_hex_string = { E2 34 A1 C8 23 FB }

    condition:
        $my_text_string or $my_hex_string
}
```

### 使用模块

一些模块由YARA官方发布, 比如`PE`和`Cukoo`模块. 这些模块就如python那样导入即可, 不过在导入时模块名需要添加双引号

```
import "pe"
import "cuckoo"
```

一旦模块成功导入, 你就可以在函数前加模块名, 来使用这些功能. 

```
pe.entry_point == 0x1000
cuckoo.http_request(/someregexp/)
```

### 未定义的值

一些值在运行时保留为`undefined`. 如果以下规则在ELF文件上执行并找到对应的字符串, 那么它的结果相当于`TRUE & Undefined`.

```
import "pe"

rule Test
{
  strings:
      $a = "some string"

  condition:
      $a and pe.entry_point == 0x1000
}
```

所以在用的时候要注意咯!

### 外部变量

外部变量允许你定义一些, 依赖于`第三方`提供值的规则. 

```
rule ExternalVariable1
{
    condition:
       ext_var == 10
}
```

`ext_var`是一个外部变量, 它在运行时会分配有一个值, (见命令行的`-d`选项以及yara-python中`compile`和`match`方法的参数). 外部变量可以是`int`, `str`或`boolean`类型

外部变量可以和操作符`contains`和`matches`一起使用. `contains`在字符串包含特定子串的情况下返回`true`. 而`matches`在字符串匹配给定的正则表达式时返回`true`.

```
rule ExternalVariable2
{
    condition:
        string_ext_var contains "text"
}

rule ExternalVariable3
{
    condition:
        string_ext_var matches /[a-z]+/
}
```

你也可以将`matches`操作符和正则表达式一起使用

```
rule ExternalVariableExample5
{
    condition:
        /* case insensitive single-line mode */
        string_ext_var matches /[a-z]+/is
}
```

`/[a-z]+/is`中的`i`表示匹配时不区分大小写. `s`表示是在单行(single line)模式

记住, 你必须在运行时定义好所有的外部变量. 你可以使用`-d`参数来指定. 

### 文件包含

当然在yara里你可以使用类似C语言的导入方式(#include, 不过yara里并不使用#, 并且包含的文件需要加双引号)来包含其他文件. 你可以在包含时使用相对路径, 绝对路径. 如果是windows系统, 还可以是驱动设备的路径. 

```
include "Migos.yar"
include "../CardiB.yar"
include "/home/user/yara/IsRapper.yar"
include "c:\\yara\\includes\\oldRappers.yar"
include "c://yara/includes/oldRappers.yar"
```


## 总结

好吧. 现在你应该知道如何写一些Yara规则了. 
这里有一些恶意软件的仓库, 规则和工具, 可以让你来生成yara规则. 如果你安装了`yarGem`, 你只需要将它指向到恶意软件, 它就会为该恶意软件生成一个签名. 如果你想捕捉一个恶意软件家族, 你最好是将规则推广到整个家族去. 

资源: 

* [Yara-Rules/rules](https://github.com/Yara-Rules/rules)
* [How to Write Simple but Sound Yara Rules - BSK Consulting GmbH](https://www.bsk-consulting.de/2015/02/16/write-simple-sound-yara-rules/)
* [yara-resource.png]()
* [descs/worm_w32_downadup_al.shtml](https://www.f-secure.com/v-descs/worm_w32_downadup_al.shtml)
* [https://www.f-secure.com/v-descs/worm_w32_downadup.shtml](https://www.f-secure.com/v-descs/worm_w32_downadup.shtml)
* [https://support.microsoft.com/en-us/help/962007/virus-alert-about-the-win32-conficker-worm](https://support.microsoft.com/en-us/help/962007/virus-alert-about-the-win32-conficker-worm)
* [https://www.f-secure.com/v-descs/worm_w32_downadup_a.shtml](https://www.f-secure.com/v-descs/worm_w32_downadup_a.shtml)
* [https://www.f-secure.com/v-descs/worm_w32_downadup_gen.shtml](https://www.f-secure.com/v-descs/worm_w32_downadup_gen.shtml)
* [https://www.f-secure.com/v-descs/worm_w32_downaduprun_a.shtml](https://www.f-secure.com/v-descs/worm_w32_downaduprun_a.shtml)

Yara: 

* [How to test yara rule?](https://www.experts-exchange.com/questions/29042297/How-to-test-yara-rule.html)
* [https://www.securityartwork.es/2013/10/11/yara-101/](https://www.securityartwork.es/2013/10/11/yara-101/)
* [https://stixproject.github.io/documentation/idioms/yara-test-mechanism/](https://stixproject.github.io/documentation/idioms/yara-test-mechanism/)
* [Neo23x0/yarGen](https://github.com/Neo23x0/yarGen)
* [radare/radare2/blob/master/doc/yara.md](https://github.com/radare/radare2/blob/master/doc/yara.md)
* [How to Write Simple but Sound Yara Rules - BSK Consulting GmbH](https://www.bsk-consulting.de/2015/02/16/write-simple-sound-yara-rules/)
* [How to Write Simple but Sound Yara Rules - Part 2 - BSK Consulting GmbH](https://www.bsk-consulting.de/2015/10/17/how-to-write-simple-but-sound-yara-rules-part-2/)
* [How to Write Simple but Sound Yara Rules – Part 3 - BSK Consulting GmbH](https://www.bsk-consulting.de/2016/04/15/how-to-write-simple-but-sound-yara-rules-part-3/)

xxd:

* [https://www.systutorials.com/docs/linux/man/1-xxd](https://www.systutorials.com/docs/linux/man/1-xxd/)

比较命令

`awk ‘FNR==NR{a[$1];next}($1 in a){print}’ malcourse.strings zoo.conficker.strings > same-strings`

恶意软件仓库

* [Malshare/MalShare-Toolkit](https://github.com/Malshare/MalShare-Toolkit)
* [http://malshare.com/about.php](http://malshare.com/about.php)