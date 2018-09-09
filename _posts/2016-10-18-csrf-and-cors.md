---
title: "CSRF 与 CORS"
layout: post
date: 2016-10-19 10:52
image: /assets/images/markdown.jpg
headerImage: false
tag:
- CSRF
- CORS
- SOP
blog: true
star: false
author: b1ngz
description: Same origin policy 、CORS、CSRF 三者之间的关系
---


# 0x 01 背景
---

谈到 `CSRF`, `SOP(Same Origin Policy)`, `CORS`, 大家可能都不陌生。

因为同源策略，浏览器会限制脚本(如JS代码)发起的跨域请求，但这里的限制并非完全阻止，而是跨域请求可以正常发起，但返回的响应会被浏览器拦截。

这里我们来做一个测试，使用 `ruby` 的 `sinatra` 搭建两个站点，分别监听在 `18001` 和 `18002` 端口

访问 `127.0.0.1:18001`，页面中有一个 `name`为 `testSOP` 的 `button`，点击后会向 `127.0.0.1:18002` 发起一个异步请求。

服务端代码如下：

`127.0.0.1:18001` ： 

`app1.rb`

```ruby
require 'sinatra'

set :port, 18001

get '/' do
  File.read(File.join('public', 'index.html'))
end
```

`index.html`

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Title</title>
    <script>
        var xmlhttp;
        if (window.XMLHttpRequest)
        {// code for IE7+, Firefox, Chrome, Opera, Safari
            xmlhttp=new XMLHttpRequest();
        }
        else
        {// code for IE6, IE5
            xmlhttp=new ActiveXObject("Microsoft.XMLHTTP");
        }

        function testSOP() {
            xmlhttp.open("GET","http://127.0.0.1:18002/",true);
            xmlhttp.send();
            xmlhttp.onreadystatechange=function()
            {
                if (xmlhttp.readyState==4 && xmlhttp.status==200)
                {
                    alert(xmlhttp.responseText);
                }
            }
        }
    </script>
</head>
<body>

<button onclick="testSOP()">testSOP</button>
</body>
</html>
```


`127.0.0.1:18002`:

`app2.rb`

```ruby
require 'sinatra'

set :port, 18002

get '/' do
  'site2'
end

```

点击按钮后，我们查看控制台的 `Network`, 显示成功向 `127.0.0.1:18002` 发起了一个异步请求


![](/assets/images/csrf-cors/1.png)

查看服务端日志，可以看到请求确实发起了

![](/assets/images/csrf-cors/2.png)


再看一下 `Network` 中请求的响应，为空，如果我们正常访问，应该返回 `site2`

![](/assets/images/csrf-cors/3.png)


查看 `Console`, 出现报错，提示响应头中没有 `Access-Control-Allow-Origin` 响应头，无法加载。

![](/assets/images/csrf-cors/4.png)


这个就是典型的跨域资源请求问题，为了解决该问题，则有了`CORS` (The Cross-Origin Resource Sharing) 机制，即在响应头中增加 `Access-Control-Allow-Origin`，设置允许哪些域可以向该站发起跨域请求。

这里修改 `app2.rb` 代码, 将响应头 `Access-Control-Allow-Origin` 设置为 `*`, 即允许任何域发起请求

```ruby
require 'sinatra'

set :port, 18002

get '/' do
  response.headers['Access-Control-Allow-Origin'] = '*'
  'site2'
end

```

重新测试，成功弹出响应body

![](/assets/images/csrf-cors/5.png)


# 0x 02 问题
---

说完 `Same origin policy` 和 `CORS`，我们来思考几个问题：

`CORS` 和 `CSRF` 之间有什么关系？ 它是否可以防止 `CSRF` 的发生？
 
首先`CORS` 机制的目的是为了解决**脚本的跨域资源请求**问题，不是为了防止 `CSRF`。

前面提到脚本的跨域请求在同源策略的限制下，响应会被拦截，即阻止获取响应，但是请求还是发送到了后端服务器。

因为`Access-Control-Allow-Origin` 响应头是由浏览器来解析的，即使我们设置了正确的 `CORS` 规则，请求仍已经发起了，所以是无法防止 `CSRF`.

此外，`CSRF` 不仅可以通过**脚本(JS代码)**的方式来发起攻击，还可以通过如 `<form action=`， `<img src=` 等方式，这些方式是无视 `CORS` 的，因为它们不是通过脚本来发起请求.

# 0x 03 总结

---

- CSRF 攻击的发起有多种方式，如html资源标签、form表单提交、JS代码发起请求
- 同源策略限制的是 **脚本发起的跨域请求**，但仅仅是拦截响应，实际上请求已经发起了，并且不会限制对于通过html标签(< img>)、form表单提交的跨域资源请求方式 
- CORS 机制的目的不是为了解决 `CSRF`, 无法防止 `CSRF` 的发生

# 0x 04 参考

---

- [HTTP access control (CORS)](https://developer.mozilla.org/en-US/docs/Web/HTTP/Access_control_CORS)
- [Is CORS helping in anyway against Cross-Site Forgery?](http://security.stackexchange.com/questions/97825/is-cors-helping-in-anyway-against-cross-site-forgery?answertab=active#tab-top)
- [CORS & CSRF Prevention for an REST based API](http://security.stackexchange.com/questions/91087/cors-csrf-prevention-for-an-rest-based-api?answertab=active#tab-top)

