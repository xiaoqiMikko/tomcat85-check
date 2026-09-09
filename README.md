# tomcat85-check

还在跑 **Tomcat 8.5**?这个工具告诉你**到底中了哪些 2025 年的 CVE** ——
因为这个问题,你在官方页面、NVD、扫描器那里都问不出完整答案。

零依赖单 jar,离线跑,不联网、不上传任何东西。

---

## 它解决什么

Tomcat 8.5 于 **2024-03-31 EOL**,终版是 **8.5.100**(2024-03-19 发布)。
之后 Apache 仍在 CVE 记录里逐条声明「8.5 也中招」,而**说这话的地方最少人去看**。

**Apache 官方 9.x 安全页列出的 `CVE-2025-*` 共 17 条,其中 14 条逐字写着**:

> The following versions were EOL at the time the CVE was created but are
> **known to be affected: 8.5.x though 8.5.100**
>
> (原文如此 —— 14 条里有 8 条把 `through` 拼成了 `though`;下界多数是 `8.5.0`,也有 `8.5.6` / `8.5.44` / `8.5.60` / `8.5.90`)

这 14 条,你在三个地方分别看到的是:

| 你会去查的地方 | 你看到的 |
|---|---|
| **Apache 官方 8.5 安全页**(`security-8.html`) | **2025 年零条目** —— 页面停在 `2024-02-19 Fixed in Apache Tomcat 8.5.99` |
| **NVD** | 拿 `8.5.100` 按 cpe 查,这 14 条里只回得到 **4 条**;另外 **10 条的 cpe 配置里根本没有 8.5** |
| **GitHub advisory** | 14 条都在,但 8.5 那一侧的 `first_patched_version` **全是 `null`** |

**唯一完整说了这件事的,是 CVE.org 上 Apache 作为 CNA 提交的原始记录** ——
也就是最少人会去翻的那一层。本工具做的就是把那一层的信息,对着你机器上真实装的版本摆出来。

> 🔴 **本工具陈述的是数据源之间的差异,不是某个产品的行为。**
> 「你的扫描器会不会报这 10 条」取决于它读哪个库、怎么合并 ——
> 那没有实测过,所以这里不会写。

---

## 另一半同样重要:14 条里**只有 2 条**是默认配置就中招的

只按版本号报,等于把 12 条「要特定配置才成立」的条目也说成「你中了」——
**那是让你去做一件不必要的事。**

所以给出安装目录时,本工具会读 `conf/` 下的全部 XML(含 `conf/Catalina/<host>/`),
**剥掉注释块**之后再找触发条件的标记。剥注释不是可选项:
官方 `server.xml` 里 `UpgradeProtocol` 文本搜索命中 1 次,剥注释后是 **0 次** —— 它整段是被注释掉的。

对官方 8.5.100 **裸装**跑出来是这样:

```
默认即受影响 2 条 · 配置已确认 0 条 · 需人工确认 11 条 · 不适用 1 条
其中 10 条在 NVD 的 cpe 配置里查不到 8.5
```

同一套配置里打开 HTTP/2、RewriteValve、CGIServlet 之后,「配置已确认」变成 **5 条**。

---

## 用法

```bash
java -jar tomcat85-check.jar <安装目录 | jar | war> ...

  --all     连「版本不在区间内」的条目也列出来
  --utf8    Windows 控制台中文乱码时加这个
```

```bash
# 解压部署的 Tomcat —— 传含 conf/ 的那一级,能少一大截人工活
java -jar tomcat85-check.jar /opt/tomcat

# 只有一个 jar / war 也能扫
java -jar tomcat85-check.jar /opt/app/lib/catalina.jar
```

### 解压部署的版本号是怎么认出来的

`lib/` 下的 jar **文件名里一个版本号都没有**(是 `catalina.jar`,不是 `catalina-8.5.100.jar`)。
只按文件名取版本的工具,在这类部署上**一条都认不出来** ——
而「没扫到」看起来和「你很安全」一模一样。

本工具按这个顺序取版本:

1. `catalina.jar!/org/apache/catalina/util/ServerInfo.properties` 的 `server.number`
   —— Tomcat 自己的 `version.sh` 报的就是它
2. `META-INF/MANIFEST.MF` 的 `Implementation-Version`
3. 文件名(只有 Spring Boot 内嵌那种形态才有)

两个来源对不上时(`ServerInfo.properties` 是可以被覆盖的,常被用来隐藏版本),
**两个都报出来,不替你选**。

---

## 三条不会越过的线

**一、能确认开启,不能确认没开。**
报告里说「没找到」,意思是**在我看过的文件里没找到**,不是「你没开」。
配置可以出现在本工具看不到的地方:war 包内的 `WEB-INF/web.xml`、外部 `CATALINA_BASE`、启动参数。
所以没有「不受影响」这个档位 —— 找不到一律落进**需人工确认**。

**二、找到了也不总等于就是它。**
比如官方默认 `server.xml` 里 `AprLifecycleListener` **本来就是启用的**,
而它只是尝试加载 native 库 —— 库不存在时 APR 连接器不会启用。
所以它是「弱标记」:命中只报「有可能」,不报「已确认」。

**三、没有可升的 8.5 版本。**
14 条的 `first_patched_version` 在 8.5 那一侧全是 `null`。
**不是「还没修」,是「不会为 8.5 修了」。** 唯一的出路是换线(9.0 / 10.1 / 11.0)。
本工具回答「你中了什么」,不假装能回答「升到哪个 8.5」。

---

## 还有一件容易让你以为「工具报错了」的事:同一条 CVE 有好几个评级

拿 `CVE-2025-55754` 举例,四个数字都是真的:

| 谁给的 | 值 |
|---|---|
| Apache(ASF 四档) | **low** |
| GitHub advisory | **low** |
| CVSS v3.1(NVD 采信的就是它) | **9.6 critical** |
| CVSS v4.0 | **2.1** |

如果只看 NVD,你会以为这是最严重的一条;只看 Apache,你会以为可以不管。
**两个都不是错的** —— Apache 评的是<b>默认配置下的实际可利用性</b>,CVSS 是按向量机械计算、不看你开没开那个功能。

所以本工具**四个数字全印出来**,并在两边判得不一样时明确说出来。

### 两套词表不是一回事,对齐只做官方支持的那一步

Apache 用 `low / moderate / important / critical`,GitHub 用 `low / medium / high / critical`。
对齐依据来自 Tomcat 官方 `security-impact.html` 原文:

> **Important / High** — A vulnerability rated as **Important (or High)** impact is one which could
> result in the compromise of data or availability of the server.

→ `Important` 和 `High` 是同一档的两个叫法,这是官方自己写在一起的。
🔴 而 **`moderate` 与 `medium` 官方没说能对齐**,本工具也不替它对 ——
ASF 的 Moderate 定义的是「有显著缓解因素 / 不影响常见配置 / 需要认证」这类**可利用性**条件,
GitHub 的 medium 是 CVSS 分数区间,两者不是一回事。这种情况报「官方没说这两档相等」,两个都摆给你。

按这个口径,14 条里 **5 条两边判得实质不同**(最远的 `CVE-2025-52520`:Apache `low` / GitHub `high`),
**2 条对不齐**,7 条相同。

---

## 数据从哪来,怎么复现

判定表 `CveTable.java` 是**生成**的,一行都不手抄:

```bash
python -u tools/fetch_sources.py    # 拉三个一手源 → tools/sources.json
python -u tools/gen_table.py        # 生成 CveTable.java(5 条断言,任一不过就不写文件)
```

| 源 | 用来回答 |
|---|---|
| CVE.org(Apache 作为 CNA 的原始记录) | Apache 自己有没有声明「影响 8.5」,区间是什么 |
| NVD | cpe 配置里有没有 8.5 条目 |
| GitHub advisory | severity、受影响 Maven 坐标、8.5 侧有没有修复版 |

发文/发布前还要再跑一次**独立口径**的复核 —— 它不读上面那份 `sources.json`,
而是解析生成出来的 `CveTable.java`,再按 cpe 查一次 NVD:

```bash
python -u tools/recheck_before_publish.py
```

> 这一步不是走过场:**它第一次运行就抓到了一个真错。**
> 生成脚本判「NVD 有没有 8.5」时只认「区间下界以 `8.5` 开头」,
> 而 `CVE-2025-24813` 写的是 `versionStartIncluding=None .. versionEndExcluding=9.0.99`
> —— **下界开放,它是覆盖 8.5 的**。差集因此多算了一条。
> 逐条查 `cveId` 永远发现不了它;换成「拿 8.5.100 按 cpe 查一次」这个用户视角的口径才撞出来。

---

## 构建

```bash
mvn package        # → target/tomcat85-check.jar
mvn test           # 59 个测试
```

需要 JDK 17+。运行时零依赖,JUnit 仅测试期。

---

## License

MIT —— 见 [LICENSE](LICENSE)

## 退出码

| 码 | 含义 |
|---|---|
| `0` | 扫完了,**并且每个文件都真的读进去了**,没有需要你动作的发现 |
| `4` | **有文件读不动** —— 不是 zip、内容截断、或读取失败 |

🔴 **`4` 是 2026-09-09 加的,加它的理由值得说清楚。**
在此之前,读不动的文件只在输出里留一行提示,而**退出码照旧是 `0`** ——
留痕是给人看的,**CI 和脚本看的是退出码**,于是「我没能读它」在自动化里等于「通过」。
一个损坏、加密或下载不全的 jar,会安静地变成一句「没发现问题」。

**「我读不动它」和「你是安全的」必须是两句话。**

⚠️ **合法的空 jar 不算读不动**(一条 22 字节的 EOCD 记录是一个真的空 zip),不会触发 `4` ——
假告警多了,真告警就没人看。

其余退出码的含义见上文各判定档位与用法说明。
