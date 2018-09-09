---
title: " link标签href属性DOM XSS笔记"
layout: post
date: 2016-12-24 22:00
headerImage: false
tag:
- DOM XSS
- XSS
blog: true
star: false
author: b1ngz
description: 输出点在<a>标签href属性的DOM XSS笔记
---



**场景：**获取 url query string 中的参数 `url` 作为 `<a>` 标签 `href` 属性的值 

**大致代码:**

```javascript
// 获取参数
s = urlQuery("url");
// url decode 一次
url = decodeURIComponent(s);
// 字符串拼接
back = '<a spm-auto="回退" href="' + escapeURL(url) + '">';
e.html(back);
```

这里的 `escapeURL` 函数会对 `&<>'"` 符号进行html实体编码

```text
{&: "&amp;", <: "&lt;", >: "&gt;", ": "&#34;", ': "&#39;"}
```

所以无法闭合，但是可以通过 `javascript:` 伪协议来执行 js 代码

```javascript
javascript: alert(document.domain)
```

某开发想的**正则修复方案**，大致代码如下:

```javascript
function check(e) {
    var t = /(javascript|data)(:|&#58;)/i;
    return t.test(e) ? "" : e
}
```

即忽略大小写匹配 `javascript:` 字符串

但浏览器有一个特性，在解析时，会忽略换行，比如下列代码，仍会执行

```html
<a href="j
avascript: alert(document.domain)">test</a>
```

所以 `url` 参数设置为 `j%0d%0aavascript: alert(document.domain)`， 解码后

```javascript
s = "j%0d%0aavascript: alert(document.domain)";
url = decodeURIComponent(s);
"j
avascript: alert(document.domain)"
```

绕过了正则修复方案

这里给出一种不需要其他依赖库的方案，代码如下

```javascript
// 检查 url 是否在白名单
function check(url) {
		// 域名白名单
      var n = ["baidu.com", "baidu.cn"]
        , t = document.createElement("a");
      t.href = url,
      t.href = t.href;
      var o = t.hostname.split(".")
        , r = o.length;
      return n.indexOf([o[r - 2], ".", o[r - 1]].join("")) > -1
}
```

即使用 `url` 创建一个 `<a>` 标签，然后获取到 `hostname` 属性，截取一级域名，检查是否在白名单中

当 `url` 参数不为真正的 url 时，`t.hostname` 属性会为空字符串，解决了 `javascript:` 伪协议执行 js 的问题 

另外，这里使用浏览器的 API 解析 url，解决了因 url 解析不正确导致白名单绕过的各种问题