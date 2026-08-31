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

    # ---- 生成
    lines = []
    for c in targets:
        r = rows[c]
        r85 = r["cna"]["ranges85"][0]
        cond, note = CONDITIONS[c]
        pkgs = sorted({p["package"] for p in r["gh"]["pkgs85"]})
        lines.append(
            "            new Cve(%s, %s, %s,\n"
            "                    %s, %s, %s,\n"
            "                    %s, %s,\n"
            "                    %s,\n"
            "                    %s, %s, %s)" % (
                q(c), q(r["gh"].get("ghsa")), q(r["gh"].get("severity")),
                q(r85["lo"]), q(r85["hi"]), "true" if r["nvd"]["has85"] else "false",
                q(r["nvd"].get("status")), q(r["nvd"].get("published")),
                java_list(pkgs),
                q(cond), q(note), q(text_range.get(c))))

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

    print("✅ 五条断言全过（ASSERT 1~5）")
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
     */
    public record Cve(String id, String ghsa, String severity,
                      String lo85, String hi85, boolean nvdHas85,
                      String nvdStatus, String nvdPublished,
                      List<String> packages,
                      String condition, String conditionNote,
                      String textRange85) {

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
