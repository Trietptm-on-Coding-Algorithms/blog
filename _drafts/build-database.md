
一个查询操作包含有一系列内容来获取/修改数据. 前端包括

* tokenizer
* parser
* code generator

前端的输入只是一个SQL查询. 而对应的输出则是sqlite虚拟机字节码(其本质是一个可以对数据库操作的编译程序)

后端包括如下

* virtual machine
* B-tree
* pager
* os interface

virtual machine 取前端产生的字节码作为指令, 随后对一个或多个表或者索引执行对应操作. 这些表和索引都保存在B树里. 