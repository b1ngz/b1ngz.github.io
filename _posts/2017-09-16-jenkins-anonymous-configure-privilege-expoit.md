---
title: "Jenkins Job Configure权限命令执行测试"
layout: post
date: 2017-09-16 22:27
headerImage: false
tag:
- Jenkins
- RCE
blog: true
star: false
author: b1ngz
description: Jenkins匿名用户Configure权限命令执行测试
---

# 0x01 简介

最近在测试的过程中，发现一个 Jenkins 允许匿名用户查看 `Job` ，并且拥有 `Job` 的 `Configure  ` 权限，但没有 `Build` 权限，无法通过在 `Job` 页面点击 `Build Now(立即构建)` 来触发命令的执行，研究了一下，这里还可以通过 `Configure` 页面 `Build Triggers` 的 `Build periodically` 选项，即周期构建功能来触发构建，这里记录一下本地复现的过程

# 0x02 环境搭建

Jenkins 测试版本为`2.60.3`，使用 docker 搭建

```shell
docker run -p 18080:8080 -p 50000:50000 --name=jenkins  jenkins:2.60.3
```

运行后 console 会输出如下内容

```shell
*************************************************************
*************************************************************
*************************************************************

Jenkins initial setup is required. An admin user has been created and a password generated.
Please use the following password to proceed to installation:

f9179271ec10492cb2606b1bd327414d

This may also be found at: /var/jenkins_home/secrets/initialAdminPassword

*************************************************************
*************************************************************
*************************************************************
```

其中 `f9179271ec10492cb2606b1bd327414d` 为安装时需要的 `password`

访问 http://127.0.0.1:18080/login?from=%2F，填入` password`，点击  `continue`

![](/assets/images/jenkins_configure/1.jpeg)

然后选择 `Install sugguested plugins`，会安装需要的插件，安装过程需要一定时间

![](/assets/images/jenkins_configure/2.jpeg)

插件安装完成后，需要设置 `Admin User` 的用户名和密码，这里设置为 `root/root`，点击 `Save and Finish`

![](/assets/images/jenkins_configure/3.jpeg)

默认安装的情况下，匿名用户是没有任何权限的，这里修改配置，让匿名用户只拥有 **查看Job**、**Job Configure** 权限

点击 `Manage Jenkins` -  `Configure Global Security`

![](/assets/images/jenkins_configure/4.jpeg)

修改 `Access Control` - `Authorization` 部分的配置，选择 `Project-based Matrix Authorization Strategy`

这里需要添加一个 root 用户，步骤为在 `User/group to add:` 填入 `root`，然后点击 `Add`，移到最右侧，点击 ✔️，让 root 用户拥有所有权限，**此步非常重要，不然保存后会导致  `admin is missing the Overall/Read permission` 错误**

匿名用户勾选 `Overall` 的 `Read` 权限，`Job` 的 `Configure` 和 `Read` 权限，如下图：

![](/assets/images/jenkins_configure/5.jpeg)

点击保存，然后访问 http://127.0.0.1:18080/newJob，创建一个 Job，名称填 `Test`，类型选择 `Freestyle project` 点击 `Save`，创建成功后如下图：

![](/assets/images/jenkins_configure/6.jpeg)

# 0x03 执行命令

退出 或 开隐私模式，访问 http://127.0.0.1:18080/，可以看到匿名用户可以查看 `Job`，点击后，可以看到匿名用户拥有 `Configure ` 权限

![](/assets/images/jenkins_configure/7.jpeg)

按照 [五、低权限用户命令执行突破](https://www.secpulse.com/archives/2166.html) 中的说明，点击 `Configure`，在 `Build` 部分选择 `Execute shell`

![](/assets/images/jenkins_configure/8.jpeg)

在 `Command ` 中填入要执行的命令

```
id
uname -a
```

然后点击 `Apply`，保存后需要回到 `Job` 页面，点击 **左上侧的立即构建**，才可以触发命令的执行，原文中图片为 

![](/assets/images/jenkins_configure/9.jpeg)

因为这里的匿名用户是没有 `Build` 权限，即 `Job` 的页面中是没有 `立即构建(Build Now)` 按钮，所以这里无法通过点击 `立即构建` 来触发命令的执行。

通过查看 `Configure` 页面的选项，得知在 `Build Triggers` 部分可以设置任务 Build 的触发规则，其中有一个 `Build periodically`，可以通过类似 `Crontab` 时间规则来触发，这里填入 

```
*/1 * * * *
```

即每分钟执行一次 `Build`，点击 `Save`

 ![](/assets/images/jenkins_configure/10.jpeg)

回到 `Job` 页面，等待一会，在左侧 `Build History` 可以看到，每分钟都会执行一次 `Build`，这里点击查看 `Console Output`

 ![](/assets/images/jenkins_configure/11.jpeg)

可以看到命令执行成功

 ![](/assets/images/jenkins_configure/12.jpeg)

# 0x04 参考

-    [知其一不知其二之Jenkins Hacking]( https://www.secpulse.com/archives/2166.html )