---
title: "Java Reflection"
layout: post
date: 2019-04-28 11:11
headerImage: false
tag:
- Java
- 反射
- Reflection
blog: true
star: false
author: b1ngz
description: Java Reflection
---

# 简介

反射 (Reflection) 是 Java 语言中的一种特性，能够让程序在**运行时**，获取 class 的相关信息（如内部定义的方法、字段、实现的接口等）、创建 class 实例、调用方法、修改属性等，且这些操作可以在事先（如编译期）不知道类信息的情况下实现

[**使用场景**](https://softwareengineering.stackexchange.com/a/125173)

- 实例化任意 classes，如依赖注入框架在运行时，动态创建用户定义的类 (Bean)
- object 和其他数据格式的相互转换，如根据 getters 和 setters 方法，将 object 转换为 JSON。类库在转换时，并不知道类有哪些字段和方法，而是通过反射来获取相关信息
- 代理 class (proxy / wrapping class)
  - 如某个资源需要 lazy loding，可以使用反射创建一个代理对象，仅当实际用到的时候才进行加载
  - mock 库使用反射创建一个代理对象，完成类方法的 mocking

[**缺点**](https://softwareengineering.stackexchange.com/a/101217)  

- 性能：反射需要动态解析 class，JVM 无法进行优化，运行速度相比非反射的要慢
- 暴露类的内部结构：反射可以访问 private 变量和方法，违背了抽象原则。若代码中使用反射来调用第三方库，当库版本更新，内部结构发生变化，程序可能会运行失败
- 因为可以动态修改属性值，无法保证 type safety，会导致运行时抛出异常



# 细节

[ java.lang.Class](https://docs.oracle.com/javase/8/docs/api/java/lang/Class.html) 是所有 Reflection API 的入口类

对于每个 object，JVM 都会实例化一个`Class` 实例，来提供运行时获取 object 属性、创建 objects 的能力

**获取 Class 实例的几种方式**

- Object.getClass()  
  - `"foo".getClass()`
- The .class Syntax
  - `String.class`
- Class.forName()  需要完整的类名( fully-qualified name of a class )
  - `Class.forName("java.lang.Runtime")`



**Class 相关方法**

- `Class<? super T> getSuperclass();`  返回父类 
- `Constructor<?>[] getConstructors()` 返回所有 **public** 构造方法，包括从父类继承的
- `Constructor<?>[] getDeclaredConstructors()` 返回**当前类中定义**的所有构造方法
- `Method[] getMethods()`  返回所有 **public** 方法，包括从父类继承的
- `Method[] getDeclaredMethods()`  返回**当前类中定义**的所有方法
- `Class<?>[] getInterfaces()` Class 是类时，返回类实现的接口；Class 是接口时，返回继承的接口
- `Annotation[] getAnnotations()` 获取 Annotation
- `TypeVariable<Class<T>>[] getTypeParameters()` 返回 generic type variables
- `int getModifiers()`  获取修饰符
- ...



Class 相关方法调用后的返回值类型在  `java.lang.reflect`  包中定义，如

- `java.lang.reflect.Constructor`  构造方法
  - 可调用 `newInstance(Object ... initargs)` 来实例化对象 ，`initargs` 为构造方法的参数
- `java.lang.reflect.Method` 方法
  - 可调用 `invoke(Object obj, Object... args)` 来执行方法，即在 `obj` 上调用该方法，`args` 为方法参数
- `java.lang.reflect.Field`  字段
  - 调用 `get(Object obj)` 来获取 obj 对应字段的值
  - 调用 `set(Object obj, Object value)`，来设置 obj 对应字段值
- `java.lang.reflect.Modifier`  修饰符
- ...

对于私有方法、属性等，在调用和修改时，需要先调用 `setAccessible(true)` 来关闭 access checks，否则会失败



# 示例

```java
import org.junit.Test;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;


public class ReflectionTest {
    @Test
    public void testGetConstructs() {
        // 获取所有 public 构造方法
        Constructor[] constructors = HashMap.class.getConstructors();
        for (Constructor constructor : constructors) {
            System.out.println(constructor);
        }
        /**
         * 输出
         * public java.util.HashMap(int)
         * public java.util.HashMap()
         * public java.util.HashMap(java.util.Map)
         * public java.util.HashMap(int,float)
         */
    }

    @Test
    public void testNewInstance() throws Exception {
        // 使用 public java.util.HashMap(int) 构造方法来创建实例
        Constructor<HashMap> constructor = HashMap.class.getConstructor(new Class[]{int.class});
        Map map = constructor.newInstance(new Object[]{10});
        System.out.println(map.size());
    }

    @Test
    public void testGetDeclaredMethods() {
        // 获取当前类定义的所有方法
        Method[] methods = HashMap.class.getDeclaredMethods();
        for (Method method : methods) {
            System.out.println(method);
        }
        /**
         * public java.lang.Object java.util.HashMap.remove(java.lang.Object)
         * public boolean java.util.HashMap.remove(java.lang.Object,java.lang.Object)
         * ...
         * void java.util.HashMap.afterNodeRemoval(java.util.HashMap$Node)
         * void java.util.HashMap.internalWriteEntries(java.io.ObjectOutputStream) throws java.io.IOException
         */
    }

    @Test
    public void testInvokeMethod() throws Exception {
        Map<String, String> map = new HashMap<>();
        String key = "key";
        map.put(key, "any");
        Method method = HashMap.class.getMethod("get", Object.class);
        String value = (String) method.invoke(map, new Object[]{key});
        System.out.println(value);
    }

    @Test
    public void testInvokePrivateMethod() throws Exception {
        Constructor<Runtime> constructor = Runtime.class.getDeclaredConstructor(null);
        constructor.setAccessible(true);
        Runtime runtime = constructor.newInstance();
        System.out.println(runtime);
    }
}
```



# 参考

- [Trail: The Reflection API](<https://docs.oracle.com/javase/tutorial/reflect/index.html>)
- [Classes](https://docs.oracle.com/javase/tutorial/reflect/class/index.html)
- [Members](https://docs.oracle.com/javase/tutorial/reflect/member/index.html)
- [Arrays and Enumerated Types](https://docs.oracle.com/javase/tutorial/reflect/special/index.html)
