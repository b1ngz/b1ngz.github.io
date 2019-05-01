---
title: "Java Dynamic Proxy"
layout: post
date: 2019-04-30 11:11
headerImage: false
tag:
- Java
- Reflection
- Proxy
blog: true
star: false
author: b1ngz
description: Java 动态代理
---

# 简介

Proxy 是设计模式中的一种。当需要在已存在的 class 上添加或修改功能时，可以通过创建 proxy object 来实现

通常 proxy object 和被代理对象拥有相同的方法，并且拥有被代理对象的引用，可以调用其方法

代理模式[应用场景](https://javax0.wordpress.com/2016/01/20/java-dynamic-proxy)包括

- 在方法执行前后打印和记录日志
- 认证、参数检查
- lazy instantiation (Hibernate, Mybatis)
- AOP (transaction)
- mocking 
- ...

代理有两种实现方式

- 静态代理：在编译时期，创建代理对象
- 动态代理：在运行时期，动态创建

对于重复性工作，如打印日志，静态代理需要为每个 class 都创建 proxy class，过程繁琐和低效，而动态代理通过使用反射在运行时生成 bytecode 的方式来实现，更加方便和强大



# 过程

因为 JDK 自带的 Dynamic proxy 只能够代理 interfaces，因此被代理对象需要实现一个或多个接口，具体可参考 https://stackoverflow.com/a/10664208

先来看一些概念：

- `proxy interface`  proxy class 实现的接口
- `proxy class ` 运行时创建的代理 class，并实现一个或多个 `proxy interface`
- `proxy instance`  proxy class 的实例
- `InvocationHandler`  每个 proxy instance 都有一个关联的 invocation handler，当调用 proxy 对象的方法时，会统一封装，并转发到 `invoke()` 方法

`InvocationHandler`  接口的定义如下

```java
package java.lang.reflect;

public interface InvocationHandler {
    public Object invoke(Object proxy, Method method, Object[] args)
        throws Throwable;
}
```

只定义了一个方法 `invoke()`，参数含义如下

- `Object proxy`  生成的代理对象
- `Method method`  调用的方法，类型为 `java.lang.reflect.Method ` 
- `Object[] args`  调用方法的参数，array of objects



**简单来说就是，调用 proxy object 上的方法，最终都会转换成对关联 `InvocationHandler` 的 `invoke()` 方法的调用**



可以使用 `java.lang.reflect.Proxy` 的静态方法 `newProxyInstance` 来创建 Proxy object

```java
public static Object newProxyInstance(ClassLoader loader,
                                          Class<?>[] interfaces,
                                          InvocationHandler h)
        throws IllegalArgumentException
    {
    ...
    }
```

参数说明

- `loader`  定义 proxy class 的 ClassLoader
- `interfaces`  需要代理的接口
- `h` 关联的 InvocationHandler



# 例子

使用动态代理打印方法的执行耗时

定义代理接口

```java
public interface Foo {
    String doSomething();
}
```

实现接口

```java
public class FooImpl implements Foo {
    @Override
    public String doSomething() {
        return "finished";
    }
}
```

定义 `InvocationHandler`，`target` 为被代理对象的引用，在方法执行完后打印耗时

```java
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;

public class TimingInvocationHandler implements InvocationHandler {
    private Object target;

    public TimingInvocationHandler(Object target) {
        this.target = target;
    }

    public Object invoke(Object proxy, Method method, Object[] args)
            throws Throwable {
        long start = System.nanoTime();
        Object result = method.invoke(target, args);
        long elapsed = System.nanoTime() - start;

        System.out.println(String.format("Executing %s finished in %d ns",
                method.getName(),
                elapsed));

        return result;
    }
}
```

测试

```java
import org.junit.Test;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;

public class DynamicProxyTest {
    @Test
    public void test() {
        ClassLoader cl = DynamicProxyTest.class.getClassLoader();
        Class[] interfaces = new Class[]{Foo.class};
        FooImpl fooImpl = new FooImpl();
        InvocationHandler timingInvocationHandler = new TimingInvocationHandler(fooImpl);
        Foo foo = (Foo) Proxy.newProxyInstance(cl, interfaces, timingInvocationHandler);
        foo.doSomething();
    }
}
```

执行完会打印类似

```
Executing doSomething finished in 23148 ns
```

# 细节

生成 proxy class 的一些属性和细节

- public, final, and not abstract.
- 类名不确定，以 `$Proxy` 开头
- 继承 `java.lang.reflect.Proxy`，且 `Proxy` 实现了  `java.io.Serializable` 接口，因此 proxy instance 是可以序列化的
- 按照 `Proxy.newProxyInstance()` 传入 interfaces 参数中的接口顺序来实现接口
- 在 proxy class 上调用 `getInterfaces`，`getMethods`，`getMethod` 方法，会返回实现的接口中定义的方法，顺序和创建时的参数保持一致
- 当调用 proxy instance 同名、同 parameter signature 方法时，`invoke()` 方法的 `Method` 参数会是最早定义这个方法的 interface 的方法，无论实际调用的方法是什么
- 当 `Foo` 为实现的代理接口之一时，` proxy instanceof Foo`  返 true，并且可以转换 `(Foo) proxy  `
- `Proxy.getInvocationHandler` 静态方法会返回 proxy object 关联的 invocation handler
- ...



# 参考 

- [Dynamic Proxy Classes](<https://docs.oracle.com/javase/8/docs/technotes/guides/reflection/proxy.html>)
- [java-dynamic-proxy](<https://javax0.wordpress.com/2016/01/20/java-dynamic-proxy/>)

- [What are Dynamic Proxy classes and why would I use one?](https://stackoverflow.com/questions/933993/what-are-dynamic-proxy-classes-and-why-would-i-use-one)
