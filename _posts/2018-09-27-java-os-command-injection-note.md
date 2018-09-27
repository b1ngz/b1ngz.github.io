---
title: "Java OS 命令注入学习笔记"
layout: post
date: 2018-09-27 23:20
headerImage: false
tag:
- Java
- Injection
- OS Command Injection
blog: true
star: false
author: b1ngz
description: Java OS Command Injection Note
---

# 0x01 简介

- Java 执行系统命令的方法
- 易导致命令注入的危险写法以及如何避免

# 0x02 注意点

首先要注意的是，通过 Java 来执行系统命令时，并不是通过 shell 来执行 (Linux下)，因此如果需要用到如 pipeline (`|`)、`;`、`&&`、`||` 等 shell 特性时，需要创建 shell 来执行命令，如：

```shell
/bin/sh -c "ls -lh; pwd"
```

具体可参考 https://alvinalexander.com/java/java-exec-system-command-pipeline-pipe

# 0x03 执行方式

## ProcessBuilder

[java.lang.ProcessBuilder](https://docs.oracle.com/javase/7/docs/api/java/lang/ProcessBuilder.html) 中 `start() ` 方法可以执行系统命令，命令和参数可以通过构造方法的 String List 或 String 数组来传入

- `ProcessBuilder(List<String> command)`

- `ProcessBuilder(String... command)`

如执行 `ls -lh /home/www`  的例子

```java
String[] cmdList = new String[]{"ls", "-lh", "/home/www"};
ProcessBuilder builder = new ProcessBuilder(cmdList);
builder.redirectErrorStream(true);
Process process = builder.start();
```

因为 Java 中执行命令不是通过 shell，若没有手动创建 shell 来执行命令，命令非完全可控时，正常的情况下是无法使用 `;`、`&&` 等来实现命令注入的，例如

命令的某个参数可控

```java
// String dir = "xx";
String[] cmdList = new String[]{"ls", "-lh", dir};
ProcessBuilder builder = new ProcessBuilder(cmdList);
builder.redirectErrorStream(true);
Process process = builder.start();
printOutput(process.getInputStream());
```

`dir` 参数用户可控，如想通过传入 `/home/www;id`， 来执行 id 命令，是无法成功的，程序的输出为

 ```shell
ls: /home/www;id: No such file or directory
 ```

再看一个例子

```java
// String cmd = "xx";
ProcessBuilder builder = new ProcessBuilder(cmd);
builder.redirectErrorStream(true);
Process process = builder.start();
printOutput(process.getInputStream());
```

`cmd` 参数用户可控，那是否就可以执行任意命令了呢？

答案是可执行没有参数的命令，如 `ls`、`pwd`，如执行 `curl example.com` 则会失败，会提示如下错误

```shell
java.io.IOException: Cannot run program "curl example.com": error=2, No such file or directory
```

原因为这里 `cmd` 的值表示的是执行命令的文件路径，因此无法使用参数

前面说到是在正常情况下，但一些特殊情况下，如果执行的命令的某个参数存在解析问题，即存在参数注入，也会导致命令执行，如 [CVE-2018-3785](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-3785)、[CVE–2017–1000117](https://cert.360.cn/warning/detail?id=9ba8d91f9f69c50cae5050196f39bb0c)

前面所说的是在非 shell 环境下执行命令的情况，那如果手动创建了 shell 来执行命令，则很有可能会存在命令注入，例如：

```java
// String dir = "xxxx";
String[] cmdList = new String[]{"sh", "-c", "ls -lh " + dir};
ProcessBuilder builder = new ProcessBuilder(cmdList);
builder.redirectErrorStream(true);
Process process = builder.start();
printOutput(process.getInputStream());
```

`dir` 参数用户可控，如果传入如 `&& pwd`，则可以成功执行 `pwd` 命令

再来看一种情况

```java
String[] cmdList = new String[]{"sh", "-c", "echo test", dir};
ProcessBuilder builder = new ProcessBuilder(cmdList);
builder.redirectErrorStream(true);
Process process = builder.start();
printOutput(process.getInputStream());
```

这种情况下，dir 传入 `pwd` 或 `;pwd` 都无法执行，因为只有 `echo test` 会作为 `-c ` 选项的参数值

因此，在大多数情况下，要想通过 `ProcessBuilder` 来执行任意命令，需要代码中创建 shell 来执行命令，并且参数可控或存在拼接

## Runtime

`java.lang.Runtime` 中 `exec()` 函数同样可以执行系统命令，命令参数支持 String 和 String 数组两种方式，同时支持设置环境变量、子进程工作目录 (working directory) 参数，具体方法包括：

- `exec(String command)`
- `exec(String[] cmdarray)`
- `exec(String command, String[] envp)`
- `exec(String command, String[] envp, File dir)`
	 `	exec(String[] cmdarray, String[] envp)`	
- `exec(String[] cmdarray, String[] envp, File dir)`

这里来看一下 `exec(String command)` 函数，根据源码可知，其内部会调用 `exec(String command, String[] envp, File dir)`，方法代码如下

```java
public Process exec(String command, String[] envp, File dir)
        throws IOException {
        if (command.length() == 0)
            throw new IllegalArgumentException("Empty command");

        StringTokenizer st = new StringTokenizer(command);
        String[] cmdarray = new String[st.countTokens()];
        for (int i = 0; st.hasMoreTokens(); i++)
            cmdarray[i] = st.nextToken();
        return exec(cmdarray, envp, dir);
    }
```

可以看到，传入的字符串命令会先经过 `StringTokenizer` 进行处理，即使用分隔符，包括空格，`\t\n\r\f`  对字符串进行分隔后，再调用 `exec(String[] cmdarray, String[] envp, File dir)`，代码如下

```java
public Process exec(String[] cmdarray, String[] envp, File dir)
    throws IOException {
    return new ProcessBuilder(cmdarray)
        .environment(envp)
        .directory(dir)
        .start();
}
```

即最后是通过 `ProcessBuilder` 来执行的，那么如果直接调用参数为 String 数组的 `exec()` 函数，则和  `ProcessBuilder`  存在同样的问题

而直接传入 String 时，会先经过 `StringTokenizer` 的分隔处理，然后在使用 `ProcessBuilder`，因此这里需要弄清 `StringTokenizer` 是如何分割字符串命令的

先来看一下Runtime 执行系统命令的代码示例：

```java
// String cmd = "xx";
Process process = Runtime.getRuntime().exec(cmd);
process.waitFor();
printOutput(process.getInputStream());
printOutput(process.getErrorStream());
```

`cmd` 输入和对应 `StringTokenizer`  分隔后的值

- `ls -lh; id` => `["ls", "-lh;", "id"]` 无法执行，输出

  > ls: illegal option -- ;
  > usage: ls [-ABCFGHLOPRSTUWabcdefghiklmnopqrstuwx1][file ...][file ...]

- `ls -lh;id` => `["ls", "-lh;id"]` 无法执行，输出

  > ls: illegal option -- ;
  > usage: ls [-ABCFGHLOPRSTUWabcdefghiklmnopqrstuwx1][file ...][file ...]

- `sh -c 'ls -lh;id'` => `["sh", "-c", "'ls", "-lh;id'"]`  两边有单引号，无法执行，输出

  > -lh;id': -c: line 0: unexpected EOF while looking for matching `''
  > -lh;id': -c: line 1: syntax error: unexpected end of file

- `sh -c "ls;id"` => `["sh", "-c", "\"ls;id\"]` 注意两边的双引号，无法执行，输出

  > sh: ls;id: command not found

- `sh -c ls;id` => `["sh", "-c", "ls;id"]`，`id` 命令可成功执行

因此，简单总结一下：

- 如果参数完全可控，则可以执行任意命令

- 若没有手动创建 shell 执行命令，没有存在参数注入，则无法实现命令注入

- 手动创建 shell 执行命令，可执行`-c` 的参数值的命令，但值内不能有空格、`\t\n\r\f` 分隔符，否则会被分割

  ```java
  // 相当于执行 sh -c curl，example.com 参数会被忽略
  String cmd = "sh -c curl example.com";
  // \t 也是分割符之一
  String cmd = "sh -c curl\texample.com";
  // 使用 ${IFS} (对应内部字段分隔符) 来代替空格，成功执行
  String cmd = "sh -c curl${IFS}example.com";
  ```






# 0x04 修复方案

- 应尽量避免使用 `Runtime` 和 `ProcessBuilder` 来执行系统命令，可搜索系统是否提供 API 来完成同样的功能，如执行删除文件 `rm /home/www/log.txt` 的命令，可以使用 `File.delete()` 等函数来代替

- 无法避免执行命令时，应当尽可能避免创建 shell 来执行系统命令，优先使用 `Runtime` 和 `ProcessBuilder` 的 字符串数组`String[] cmdarray` 的 方法，可一定程度上降低命令注入的产生

- 最后，可考虑使用白名单的方式，限制可执行的命令和允许的参数值，或限制用户输入的所允许字符，如只允许字母数组、下划线

  ```java
  private static final Pattern FILTER_PATTERN = Pattern.compile("[0-9A-Za-z_]+");
  if (!FILTER_PATTERN.matcher(input).matches()) {
    // Handle error
  }
  ```


# 0x05 参考

- https://www.owasp.org/index.php/Command_injection_in_Java
- https://docs.oracle.com/javase/7/docs/api/java/lang/Runtime.html

- [IDS07-J. Sanitize untrusted data passed to the Runtime.exec() method](https://wiki.sei.cmu.edu/confluence/display/java/IDS07-J.+Sanitize+untrusted+data+passed+to+the+Runtime.exec%28%29+method)
