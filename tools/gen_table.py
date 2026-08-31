# -*- coding: utf-8 -*-
r"""由 sources.json 生成 CveTable.java —— 一行都不手抄。

唯一的人工输入是下面的 CONDITIONS(触发条件),**逐字对照官方描述原文**,不外推。
ASSERT 1 强制每条 CVE 都要有条目,漏一条就中止 ——
🔴 留空会被读者读成「无条件即中招」,那是让用户做错事。

任一断言不满足 → **中止,不写文件**(防「解析失败生成空壳表而测试照样全绿」)。

用法:python -u tools/gen_table.py
"""
import json
import os
import re
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "sources.json")
OUT = os.path.join(HERE, "..", "src", "main", "java", "dev", "mikko",
                   "tomcat85check", "CveTable.java")

# ---------------------------------------------------------------- 人工输入
# 🔴 措辞只写「触发条件」本身,一律来自 CNA 描述原文。原文没说的**不许补**
#    （例如「默认未启用」这类常识,原文没写就不写 —— 说过头会被一查就抓）。
CONDITIONS = {
    "CVE-2025-24813": ("CONFIG",
                       "仅当 default servlet 开启了 writes(原文:disabled by default)"
                       "且支持 partial PUT(原文:enabled by default)"),
    "CVE-2025-31650": ("HTTP2", "仅当启用 HTTP/2(畸形 PRIORITY_UPDATE 帧)"),
    "CVE-2025-31651": ("REWRITE",
                       "仅当配置了 Rewrite Valve,且属于原文所说的"
                       "「a subset of unlikely rewrite rule configurations」"),
    "CVE-2025-46701": ("CGI", "仅当 URI 映射到 CGI servlet"),
    "CVE-2025-48988": ("DEFAULT", "默认配置即受影响(原文未给任何前置条件);触发面为 multipart 上传"),
    "CVE-2025-49124": ("WINDOWS_INSTALLER",
                       "🔴 仅当用 Windows 安装程序安装(漏洞在安装过程调用 icacls.exe)——"
                       "解压 zip/tar.gz 部署的不适用"),
    "CVE-2025-49125": ("CONFIG", "仅当配置了 PreResources / PostResources 且挂载点不在应用根"),
    "CVE-2025-52434": ("APR", "仅当使用 APR/Native 连接器"),
    "CVE-2025-52520": ("CONFIG", "仅当属于原文所说的「some unlikely configurations of multipart upload」"),
    "CVE-2025-53506": ("HTTP2", "仅当启用 HTTP/2(客户端不确认初始 settings 帧)"),
    "CVE-2025-55752": ("REWRITE",
                       "仅当 rewrite 规则会把 query 参数改写进 URI;"
                       "若同时启用 PUT 则可导致 RCE"),
    "CVE-2025-55754": ("WINDOWS_CONSOLE",
                       "仅当在 Windows 控制台中运行且该控制台支持 ANSI 转义序列"),
    "CVE-2025-61795": ("DEFAULT", "默认配置即受影响(原文未给任何前置条件);触发面为 multipart 上传"),
    "CVE-2025-66614": ("TLS",
                       "仅当配置了多个虚拟主机、其中部分要求客户端证书认证,"
                       "且认证只在 Connector 层强制(原文:not if enforced at the web application)"),
}


def q(s):
    """Java 字符串字面量。"""
    if s is None:
        return "null"
    return '"' + str(s).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ") + '"'


def num(x):
    """Java 里的 Double 字面量;None 写成 null。

    🔴 上游把「没有这个版本的分数」表示成 **0 或缺键** ——
    fetch_sources 已经统一成 None 了,这里只管把 None 写成 null。
    ☠️ 千万别把它当成「分数是 0」:2026-09-01 就是这么算出一堆假分歧的。
    """
    return "null" if x is None else "%.1f" % float(x)


def java_list(items):
    return "List.of(" + ", ".join(q(i) for i in items) + ")"


def main():
    with open(SRC, encoding="utf-8") as f:
        data = json.load(f)
    rows = data["rows"]
    gap = data["summary"]["gap"]
    both = data["summary"]["both"]
    targets = sorted(gap + both)

    # ---- ASSERT 1:每条都要有触发条件
    missing = [c for c in targets if c not in CONDITIONS]
    if missing:
        raise SystemExit("❌ ASSERT 1 失败:这些 CVE 没有触发条件,漏了会被读成「无条件即中招」:\n   "
                         + "\n   ".join(missing))
    extra = [c for c in CONDITIONS if c not in targets]
    if extra:
        raise SystemExit("❌ ASSERT 1 失败:CONDITIONS 里有表外的 CVE(数据变了?):\n   "
                         + "\n   ".join(extra))

    # ---- ASSERT 2:差集非空 —— 本注的核心事实
    if not gap:
        raise SystemExit("❌ ASSERT 2 失败:「上游写 8.5 / NVD 没有」的差集为空,本注前提不成立。")

    # ---- ASSERT 3:每条都要有上游 8.5 区间,且上界必须是闭区间
    #      🔴 8.5 那侧 GitHub 的 first_patched_version 全是 null,
    #         判「中不中招」只能靠这个区间的上界,取错一格就整体判错。
    for c in targets:
        r85 = rows[c]["cna"]["ranges85"]
        if not r85:
            raise SystemExit("❌ ASSERT 3 失败:%s 没有 8.5 区间,但它被归进了目标表。" % c)
        for x in r85:
            if not x["inclusive"]:
                raise SystemExit("❌ ASSERT 3 失败:%s 的 8.5 上界不是 lessThanOrEqual(%s),"
                                 "闭开区间取错一格会整体判错。" % (c, x))

    # ---- ASSERT 4:8.5 侧不该有任何修复版(有的话本注主张就变了)
    patched = []
    for c in targets:
        for p in rows[c]["gh"]["pkgs85"]:
            if p.get("first_patched"):
                patched.append((c, p["package"], p["first_patched"]))
    if patched:
        raise SystemExit("❌ ASSERT 4 失败:8.5 侧出现了 first_patched_version —— "
                         "「没有可升的版本」这个主张不再成立,先改文案再生成:\n   "
                         + "\n   ".join(map(str, patched)))


    # ---- ASSERT 5:CNA 的**结构化字段**与**描述文字**交叉校验
    #      🔴 实测 CVE-2025-49124 两处不一致(结构化 8.5.44 / 文字 8.5.0)。
    #      本表取**结构化字段**(区间更窄 = 少报),但不许默默吞掉这个矛盾 ——
    #      不一致的条目会把文字区间一并带进表里,由工具在输出时如实告诉用户。
    #      ⚠️ 官方描述里 14 条有 8 条把 through 拼成 though,正则两个都要认。
    text_pat = re.compile(r"(8\.5\.\d+)\s+thr?o?u?gh\s+(8\.5\.\d+)", re.I)
    text_range = {}
    conflicts = []
    for c in targets:
        st = rows[c]["cna"]["ranges85"][0]
        m = text_pat.search(rows[c]["cna"].get("description") or "")
        if not m:
            raise SystemExit("❌ ASSERT 5 失败：%s 的描述原文里找不到 8.5 区间（描述格式变了？）" % c)
        t = (m.group(1), m.group(2))
        if (st["lo"], st["hi"]) != t:
            text_range[c] = "%s..%s" % t
            conflicts.append((c, "%s..%s" % (st["lo"], st["hi"]), text_range[c]))


    # ---- ASSERT 6:CVSS 分数必须是「有」或「没有」,不许出现 0.0
    #      🔴 上游用 0 表示「没有这个版本的分数」。让 0 混进表里,
    #      下游算「两个版本差几分」时会得出一堆假分歧(2026-09-01 实测踩过)。
    for c in targets:
        for k in ("cvss3", "cvss4"):
            v = rows[c]["gh"].get(k)
            if v == 0:
                raise SystemExit("❌ ASSERT 6 失败:%s 的 %s 是 0 —— "
                                 "应该在 fetch_sources 里就归成 None。" % (c, k))


    # ---- ASSERT 7:每条都要拿到 Apache 自己的 ASF 评级
    #      🔴 缺了就只剩 GitHub 那一套,而两套 14 条里有 10 条说法不同
    #      (最极端 CVE-2025-52520:Apache low / GitHub high)。
    #      少一套 = 我们只能转述别人的判断,那本注就没有独立价值了。
    no_asf = [c for c in targets if not rows[c]["cna"].get("asf_severity")]
    if no_asf:
        raise SystemExit("❌ ASSERT 7 失败：这些 CVE 拿不到 ASF 评级：\n   " + "\n   ".join(no_asf))

    # ---- 生成
    lines = []
    for c in targets:
        r = rows[c]
        r85 = r["cna"]["ranges85"][0]
        cond, note = CONDITIONS[c]
        pkgs = sorted({p["package"] for p in r["gh"]["pkgs85"]})
        lines.append(
            "            new Cve(%s, %s, %s, %s,\n"
            "                    %s, %s, %s,\n"
            "                    %s, %s,\n"
            "                    %s,\n"
            "                    %s, %s, %s,\n"
            "                    %s, %s)" % (
                q(c), q(r["gh"].get("ghsa")), q(r["gh"].get("severity")),
                q(r["cna"].get("asf_severity")),
                q(r85["lo"]), q(r85["hi"]), "true" if r["nvd"]["has85"] else "false",
                q(r["nvd"].get("status")), q(r["nvd"].get("published")),
                java_list(pkgs),
                q(cond), q(note), q(text_range.get(c)),
                num(r["gh"].get("cvss3")), num(r["gh"].get("cvss4"))))

    # 🔴 每行自己不带尾逗号，由连接符补上——否则最后一条的尾逗号会让 List.of(...) 编译不过。
    body = ",\n".join(lines)
    java = TEMPLATE % {
        "generated": data["generated"],
        "total": len(rows),
        "gap": len(gap),
        "both": len(both),
        "rows": body,
    }
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(java)

    # 🔴 别写死条数 —— 本轮之前已经两次因为加了断言而让这句话过时(硬编码结论文本)。
    #    自己数源码里出现过的 ASSERT 编号。
    n_assert = len(set(re.findall(r"ASSERT (\d+) 失败", open(__file__, encoding="utf-8").read())))
    print("✅ %d 条断言全过（ASSERT 1~%d）" % (n_assert, n_assert))
    print("   目标表 %d 条(NVD 无 8.5 的 %d 条 + NVD 有 8.5 的 %d 条)" % (len(targets), len(gap), len(both)))
    from collections import Counter
    cc = Counter(CONDITIONS[c][0] for c in targets)
    print("   触发条件分布:", dict(sorted(cc.items())))
    print("   🔴 默认配置即受影响的只有 %d 条:%s"
          % (cc.get("DEFAULT", 0), [c for c in targets if CONDITIONS[c][0] == "DEFAULT"]))
    if conflicts:
        print("   ⚠️  CNA 结构化字段与描述文字不一致 %d 条（已写进表，取窄的那个）:" % len(conflicts))
        for c, a, b in conflicts:
            print("      %s  结构化=%s  文字=%s" % (c, a, b))
    print("已写", os.path.normpath(OUT))


TEMPLATE = '''package dev.mikko.tomcat85check;

import java.util.List;

/**
 * Tomcat 8.5 的 CVE 判定表 —— <b>本文件由 {@code tools/gen_table.py} 生成,不要手改。</b>
 *
 * <p>生成时间:%(generated)s。数据来自三个一手源(见 {@code tools/fetch_sources.py}):
 * Apache 作为 CNA 的原始记录(CVE.org)、NVD、GitHub advisory。
 *
 * <p>表里共 %(total)d 条 CVE-2025-* 中筛出的 <b>%(gap)d + %(both)d</b> 条 ——
 * 全部是 Apache 逐字写了
 * <i>"The following versions were EOL at the time the CVE was created but are known to be
 * affected: 8.5.x though 8.5.100"</i> 的条目。其中:
 * <ul>
 *   <li><b>%(gap)d 条 {@code nvdHas85 == false}</b> —— NVD 的 cpe 配置里查不到 8.5,
 *       读 NVD 的工具和文章看不见它们;</li>
 *   <li>%(both)d 条 NVD 也有 8.5。</li>
 * </ul>
 *
 * <p>🔴 <b>8.5 侧一条修复版都没有</b>({@code first_patched_version} 全为 null,由 ASSERT 4 守着)。
 * 所以本表回答的是「你中了什么」,<b>不是「升到哪个 8.5 版本」—— 那个版本不存在。</b>
 *
 * <p>🔴 <b>{@code condition} 不是装饰。</b> 表里绝大多数条目<b>只在特定配置下才成立</b>,
 * 默认配置即受影响的是少数。把它们一律报成「你中了」就是让用户做错事。
 */
public final class CveTable {

    private CveTable() {
    }

    /**
     * 一条 CVE。
     *
     * @param lo85       Apache 声明的 8.5 区间下界(闭)
     * @param hi85       上界(闭 —— 由 ASSERT 3 保证是 {@code lessThanOrEqual})
     * @param nvdHas85   NVD 的 cpe 配置里有没有 8.5 条目
     * @param packages   GitHub advisory 里 8.5 那侧的受影响 Maven 坐标(可能为空)
     * @param condition  触发条件分类;{@code DEFAULT} 表示默认配置即受影响
     * @param conditionNote 条件说明,逐字对照官方描述原文,未作外推
     * @param textRange85 仅当 CNA 结构化字段与描述正文的 8.5 区间对不上时非 null,值是正文那个
     * @param severity    GitHub advisory 的评级(low / medium / high / critical)
     * @param asfSeverity Apache 自己的 <b>ASF 四档</b>评级(low / moderate / important / critical)
     *                    —— 🔴 <b>和上面那个不是同一套</b>,14 条里 10 条两边说法不同
     * @param cvss3       CVSS v3.1 分数;<b>null 表示没有这个版本的分数,不是 0 分</b>
     * @param cvss4       CVSS v4.0 分数;同上
     */
    public record Cve(String id, String ghsa, String severity, String asfSeverity,
                      String lo85, String hi85, boolean nvdHas85,
                      String nvdStatus, String nvdPublished,
                      List<String> packages,
                      String condition, String conditionNote,
                      String textRange85,
                      Double cvss3, Double cvss4) {

        /**
         * CVSS v3.1 分数换算成档位;没有分数则返回 null。
         *
         * <p>🔴 {@code null} 是「<b>没有这个版本的分数</b>」,不是「分数是 0」——
         * 14 条里只有 9 条有 v3.1 分数。把缺失当 0 会算出一堆假的分歧。
         */
        public String cvss3Severity() {
            if (cvss3 == null) {
                return null;
            }
            return cvss3 >= 9 ? "critical" : cvss3 >= 7 ? "high" : cvss3 >= 4 ? "medium" : "low";
        }

        /**
         * Apache 和 GitHub 两套评级<b>实质不同</b> —— 不是词表差异,是判断差异。
         *
         * <p>对齐依据来自 <b>Tomcat 官方 {@code security-impact.html} 原文</b>,不是我们的推断:
         * <ul>
         *   <li><i>"<b>Important / High</b> — A vulnerability rated as Important (or High) impact
         *       is one which could result in the compromise of data or availability of the server."</i>
         *       → <b>Important 和 High 是同一档的两个叫法</b>,官方自己写在一起的。</li>
         *   <li>{@code Critical} 与 {@code Low} 两边同名,直接对上。</li>
         * </ul>
         *
         * <p>🔴 <b>{@code moderate} 与 {@code medium} 官方没说能对齐</b>,本方法也不替它对 ——
         * ASF 的 Moderate 定义的是「有显著缓解因素 / 不影响常见配置 / 需要认证」这类
         * <b>可利用性</b>条件,而 GitHub 的 medium 是 CVSS 分数区间,两者不是一回事。
         * 那种情况走 {@link #ratingUnalignable()},既不算相同也不算不同。
         *
         * <p>实测差最远的 {@code CVE-2025-52520}:<b>Apache 评 low,GitHub 评 high</b>。
         */
        public boolean ratingsDiffer() {
            String a = alignAsf(asfSeverity);
            String g = severity == null ? null : severity.toLowerCase();
            if (a == null || g == null || ratingUnalignable()) {
                return false;
            }
            return !a.equals(g);
        }

        /**
         * 两边的词无法在官方依据下对齐({@code moderate} / {@code medium})——
         * <b>说不清相同还是不同,就如实说说不清</b>,不许猜一个。
         */
        public boolean ratingUnalignable() {
            String a = alignAsf(asfSeverity);
            String g = severity == null ? null : severity.toLowerCase();
            // 🔴 只有 moderate 对 medium 这**一对**没有官方依据可判。
            //    `important` 已经被官方原文锚定成 `high`,所以 high vs medium 是判得了的「不同」——
            //    把它也归进「无法对齐」就是把判据放得过松,会把真实的分歧藏起来。
            return "moderate".equals(a) && "medium".equals(g);
        }

        /** 只做官方原文支持的那一步换算:Important → High。其余原样。 */
        private static String alignAsf(String s) {
            if (s == null) {
                return null;
            }
            String t = s.toLowerCase();
            return t.equals("important") ? "high" : t;
        }

        /**
         * 文字评级和 CVSS v3.1 差了 2 级以上 —— <b>用户会因此以为我们报错了</b>。
         *
         * <p>实测 {@code CVE-2025-55754}:Apache 官方评 <b>low</b>,而 CVSS v3.1 是
         * <b>9.6 critical</b>(NVD 采信的就是它)。一个只看 NVD 的人会认为这是最严重的一条。
         * <b>两个都不是错的 —— 它们量的本来就是不同的东西</b>:
         * 文字评级看默认配置下的实际可利用性,CVSS 向量机械计算、不看你开没开那个功能。
         */
        public boolean severityGap() {
            String d = cvss3Severity();
            if (d == null || severity == null) {
                return false;
            }
            return Math.abs(rank(d) - rank(severity)) >= 2;
        }

        /**
         * CVSS v3.1 与 v4.0 都有,且差 3 分以上。
         *
         * <p>实测 {@code CVE-2025-55754}:<b>v3.1 = 9.6,v4.0 = 2.1</b>,同一个机构给的两个版本差 7.5 分。
         * 引哪个数字,结论就差一个数量级。
         */
        public boolean cvssVersionSplit() {
            return cvss3 != null && cvss4 != null && Math.abs(cvss3 - cvss4) >= 3;
        }

        private static int rank(String s) {
            return switch (s) {
                case "critical" -> 4;
                case "high" -> 3;
                case "medium" -> 2;
                default -> 1;
            };
        }

        /**
         * Apache 自己的两处写法对不上 —— {@code affected} 结构化字段一个区间,
         * 描述正文里另一个区间。
         *
         * <p>实测 {@code CVE-2025-49124}:结构化写 {@code 8.5.44..8.5.100},
         * 正文写 {@code 8.5.0 through 8.5.100}。本表取<b>结构化字段</b>(区间更窄 = 少报),
         * 但把正文那个一并带出来 —— <b>不许默默吞掉官方自相矛盾这件事</b>,
         * 落在这段差里的用户有权知道「官方两处说法不同」。
         */
        public boolean upstreamSelfConflict() {
            return textRange85 != null;
        }

        /** 默认配置即受影响 —— 不需要用户开启任何东西。 */
        public boolean defaultAffected() {
            return "DEFAULT".equals(condition);
        }

        /**
         * 这个 8.5.x 版本在不在本条的影响区间内。
         *
         * <p>🔴 <b>只能这样判。</b> GitHub advisory 在 8.5 那侧的
         * {@code first_patched_version} <b>全是 null</b>,靠「低于修复版就算中招」这套判据
         * 会把每一条都判成「无法判定」或「全中」。而 GitHub 的
         * {@code vulnerable_version_range} 写的是 {@code ">= 8.5.0, <= 8.5.100"} ——
         * <b>闭区间上界</b>,不是修复版。(注:GitHub API 里<b>没有</b> {@code last_affected}
         * 字段,那是 OSV 的字段名,别照 OSV 的经验写判据。)
         */
        public boolean affects(TomcatVersion v) {
            return v != null && v.inRange(lo85, hi85);
        }
    }

    private static final List<Cve> ALL = List.of(
%(rows)s
    );

    public static List<Cve> all() {
        return ALL;
    }

    /** 命中这个版本的全部条目。 */
    public static List<Cve> matching(TomcatVersion v) {
        return ALL.stream().filter(c -> c.affects(v)).toList();
    }

    /** 命中且 <b>NVD 查不到</b> 的条目 —— 本工具存在的理由。 */
    public static List<Cve> invisibleInNvd(TomcatVersion v) {
        return ALL.stream().filter(c -> c.affects(v) && !c.nvdHas85()).toList();
    }
}
'''

if __name__ == "__main__":
    main()
