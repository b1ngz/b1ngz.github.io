---
title: "Java SQL 注入学习笔记"
layout: post
date: 2018-09-26 18:00
headerImage: false
tag:
- Java
- SQL Injection
blog: true
star: false
author: b1ngz
description: Java SQL Injection Note
---

# 0x01 简介

文章主要内容包括：

- Java 持久层技术/框架简单介绍
- 不同场景/框架下易导致 SQL 注入的写法
- 如何避免和修复 SQL 注入

# 0x02 JDBC

## 介绍

JDBC：

- 全称 Java Database Connectivity 

- 是 Java 访问数据库的 API，不依赖于特定数据库 ( database-independent )

- 所有 Java 持久层技术都基于 JDBC

更多请参考 http://www.oracle.com/technetwork/java/javase/jdbc/index.html

## 说明

直接使用 JDBC 的场景，如果代码中存在拼接 SQL 语句，那么很有可能会产生注入，如

```java
// concat sql
String sql = "SELECT * FROM users WHERE name ='"+ name + "'";
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery(sql);
```

安全的写法是使用 **参数化查询 ( parameterized queries )**，即 SQL 语句中使用参数绑定( ? 占位符 ) 和 `PreparedStatement`，如

```java
// use ? to bind variables
String sql = "SELECT * FROM users WHERE name= ? ";
PreparedStatement ps = connection.prepareStatement(sql);
// 参数 index 从 1 开始
ps.setString(1, name);
```

还有一些情况，比如 order by、column name，不能使用参数绑定，此时需要手工过滤，如通常 order by 的字段名是有限的，因此可以使用白名单的方式来限制参数值



这里需要注意的是，使用了 `PreparedStatement` **并不意味着不会产生注入**，如果在使用 `PreparedStatement` 之前，存在拼接 sql 语句，那么仍然会导致注入，如

```java
// 拼接 sql
String sql = "SELECT * FROM users WHERE name ='"+ name + "'";
PreparedStatement ps = connection.prepareStatement(sql);
```



看到这里，大家肯定会好奇 `PreparedStatement` 是如何防止 SQL 注入的，来了解一下

正常情况下，用户的输入是作为参数值的，而在 SQL 注入中，用户的输入是作为 SQL 指令的一部分，会被数据库进行编译/解释执行。当使用了 `PreparedStatement`，带占位符 ( ? ) 的 sql 语句只会被编译一次，之后执行只是将占位符替换为用户输入，并不会再次编译/解释，因此从根本上防止了 SQL 注入问题。

更详细和准确的回答，请参考：

- [How does a PreparedStatement avoid or prevent SQL injection?](https://stackoverflow.com/a/34126564/6467552)

- [How to Fix SQL Injection Using Java PreparedStatement & CallableStatement](https://software-security.sans.org/developer-how-to/fix-sql-injection-in-java-using-prepared-callable-statement)



# 0x03 Mybatis

## 介绍

- 首个 class persistence framework
- 介于 JDBC (raw SQL) 和 Hibernate (ORM)
- 简化绝大部分 JDBC 代码、手工设置参数和获取结果
- 灵活，使用者能够完全控制 SQL，支持高级映射

更多请参考 http://www.mybatis.org/

## 说明

在 MyBatis 中，使用 XML 文件 或 Annotation 来进行配置和映射，将 interfaces 和 Java POJOs (Plain Old Java Objects) 映射到 database records

**XML 例子**

Mapper Interface

```java
@Mapper
public interface UserMapper {
    User getById(int id);
}
```

XML 配置文件

```xml
<select id="getById" resultType="org.example.User">
	SELECT * FROM user WHERE id = #{id}
</select>
```

**Annotation 例子**

```java
@Mapper
public interface UserMapper {
    @Select("SELECT * FROM user WHERE id= #{id}")
    User getById(@Param("id") int id);
}
```

可以看到，使用者需要自己编写 SQL 语句，因此当使用不当时，会导致注入问题

与使用 JDBC 不同的是，MyBatis 使用 `#{}` 和 `${}` 来进行参数值替换

使用 `#{}` 语法时，MyBatis 会自动生成 `PreparedStatement` ，使用参数绑定 (`?`) 的方式来设置值，上述两个例子等价的 JDBC 查询代码如下：

```java
String sql = "SELECT * FROM users WHERE id = ?";
PreparedStatement ps = connection.prepareStatement(sql);
ps.setInt(1, id);
```

因此  `#{}`  可以有效防止 SQL 注入，详细可参考 http://www.mybatis.org/mybatis-3/sqlmap-xml.html  **String Substitution** 部分



而使用 `${}` 语法时，MyBatis 会直接注入原始字符串，即相当于拼接字符串，因而会导致 SQL 注入，如

```xml
<select id="getByName" resultType="org.example.User">
	SELECT * FROM user WHERE name = '${name}' limit 1
</select>
```

name 值为 `' or '1'='1`，实际执行的语句为 

```sql
SELECT * FROM user WHERE name = '' or '1'='1' limit 1 
```



因此建议尽量使用 `#{}`，但有些时候，如 order by 语句，使用 `#{}` 会导致出错，如

```sql
ORDER BY #{sortBy}
```

sortBy 参数值为 `name` ，替换后会成为

```sql
ORDER BY "name"
```

即以字符串 "name" 来排序，而非按照 name 字段排序，详细可参考 https://stackoverflow.com/a/32996866/6467552。

这种情况就需要使用 `${}` 

```sql
ORDER BY ${sortBy}
```

使用了 `${}`后，使用者需要自行过滤输入，方法有：

- 代码层使用白名单的方式，限制 `sortBy` 允许的值，如只能为 `name`, `email` 字段，异常情况则设置为默认值 `name`

- 在 XML 配置文件中，使用 `if` 标签来进行判断

  Mapper 接口方法

  ```java
  List<User> getUserListSortBy(@Param("sortBy") String sortBy);
  ```

  xml 配置文件

  ```xml
  <select id="getUserListSortBy" resultType="org.example.User">
    SELECT * FROM user 
    <if test="sortBy == 'name' or sortBy == 'email'">
  	order by ${sortBy}
    </if>
  </select>
  ```

  因为 Mybatis 不支持 else，需要默认值的情况，可以使用 `choose (when, otherwise)`

  ```xml
  <select id="getUserListSortBy" resultType="org.example.User">
    SELECT * FROM user 
    <choose>
      <when test="sortBy == 'name' or sortBy == 'email'">
        order by ${sortBy}
      </when>
      <otherwise>
        order by name
      </otherwise>     
   </choose>
  </select>
  ```

## 更多场景

除了 `order by ` 之外，还有一些可能会使用到 `${}` 情况，可以使用其他方法避免，如



**like 语句**

如需要使用通配符 ( wildcard characters `%` 和 `_`)  ，可以

- 在代码层，在参数值两边加上 `%`，然后再使用 `#{}`

- 使用 `bind` 标签来构造新参数，然后再使用 `#{}`

  Mapper 接口方法

  ```java
  List<User> getUserListLike(@Param("name") String name);
  ```

  xml 配置文件

  ```xml
  <select id="getUserListLike" resultType="org.example.User">
      <bind name="pattern" value="'%' + name + '%'" />
      SELECT * FROM user 
      WHERE name LIKE #{pattern}
  </select>
  ```

  `<bind>` 语句内的 value 为 OGNL expression，具体可参考 http://www.mybatis.org/mybatis-3/dynamic-sql.html  **bind** 部分

- 使用 SQL `concat()` 函数

  ```xml
  <select id="getUserListLikeConcat" resultType="org.example.User">
  	SELECT * FROM user WHERE name LIKE concat ('%', #{name}, '%')
  </select>
  ```

除了注入问题之外，这里还需要对用户的输入进行过滤，不允许有通配符，否则在表中数据量较多的时候，假设用户输入为 `%%`，会进行全表模糊查询，严重情况下可导致 DOS，参考  http://www.tothenew.com/blog/sql-wildcards-is-your-application-safe/



**IN 条件**

使用 `<foreach>` 和 `#{}`

Mapper 接口方法

```java
List<User> getUserListIn(@Param("nameList") List<String> nameList);
```

xml 配置文件

```xml
<select id="selectUserIn" resultType="com.example.User">
  SELECT * FROM user WHERE name in
  <foreach item="name" collection="nameList" 
           open="(" separator="," close=")">
        #{name}
  </foreach>
</select>
```

具体可参考 http://www.mybatis.org/mybatis-3/dynamic-sql.html  **foreach** 部分



**limit  语句**

直接使用 `#{}` 即可

Mapper 接口方法

```java
List<User> getUserListLimit(@Param("offset") int offset, @Param("limit") int limit);
```

xml 配置文件

```xml
<select id="getUserListLimit" resultType="org.example.User">
	SELECT * FROM user limit #{offset}, #{limit}
</select>
```



# 0x04 JPA & Hibernate

## 介绍

**JPA:** 

- 全称 Java Persistence API

- ORM (object-relational mapping) 持久层 API，需要有具体的实现

更多请参考 https://en.wikipedia.org/wiki/Java_Persistence_API



**Hibernate:** 

- JPA ORM 实现

更多请参考 http://hibernate.org/

## 说明

这里有一种错误的认识，使用了 ORM 框架，就不会有 SQL 注入。而实际上，在 Hibernate 中，支持 HQL (Hibernate Query Language) 和 native sql 查询，前者存在 HQL 注入，后者和之前 JDBC 存在相同的注入问题，来具体看一下

### HQL

HQL 查询例子

```java
Query<User> query = session.createQuery("from User where name = '" + name + "'", User.class);
User user = query.getSingleResult();
```

这里的 `User` 为类名，和原生 SQL 类似，拼接会导致注入

正确的用法：

- 位置参数 (Positional parameter)

```java
Query<User> query = session.createQuery("from User where name = ?", User.class);
query.setParameter(0, name);
```

-  命名参数 (named parameter)

```java
Query<User> query = session.createQuery("from User where name = :name", User.class);
query.setParameter("name", name);
```

- 命名参数 list (named parameter list)

```java
Query<User> query = session.createQuery("from User where name in (:nameList)", User.class);
query.setParameterList("nameList", Arrays.asList("lisi", "zhaowu"));
```

- 类实例 (JavaBean)

```java
User user = new User();
user.setName("zhaowu");
Query<User> query = session.createQuery("from User where name = :name", User.class);
// User 类需要有 getName() 方法
query.setProperties(user);
```



### Native SQL

 存在 SQL 注入

```java
String sql = "select * from user where name = '" + name + "'";
// deprecated
// Query query = session.createSQLQuery(sql);
Query query = session.createNativeQuery(sql);
```

使用参数绑定来设置参数值

```java
String sql = "select * from user where name = :name";
// deprecated
// Query query = session.createSQLQuery(sql);
Query query = session.createNativeQuery(sql);
query.setParameter("name", name);
```



## JPA

JPA 中使用  JPQL (Java Persistence Query Language)，同时也支持 native sql，因此和 Hibernate 存在类似的问题，这里就不再细说，感兴趣的可以参考 [How to How to Fix SQL Injection using the Java Persistence API (JPA)](https://software-security.sans.org/developer-how-to/fix-sql-injection-in-java-persistence-api-jpa)



# 0x05 参考

- [How to Fix SQL Injection Using Java PreparedStatement](https://software-security.sans.org/developer-how-to/fix-sql-injection-in-java-using-prepared-callable-statement)
- [How to Fix SQL Injection using MyBatis](https://software-security.sans.org/developer-how-to/fix-sql-injection-in-java-mybatis)
- [Mybatis Dynamic SQL](http://www.mybatis.org/mybatis-3/dynamic-sql.html)
- [How to Fix SQL Injection using Hibernate](https://software-security.sans.org/developer-how-to/fix-sql-injection-in-java-hibernate)
- [Java Persistence Tech & Framework](https://stackoverflow.com/a/2560546/6467552)
- [ORM 实现](https://stackoverflow.com/a/17883972/6467552)

