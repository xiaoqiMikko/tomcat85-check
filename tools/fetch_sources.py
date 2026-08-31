# -*- coding: utf-8 -*-
r"""把三个一手源拉成一份 JSON —— 判定表的原料,一行都不手抄。

源 A  CVE.org / Apache 作为 CNA 的原始记录   cveawg.mitre.org/api/cve/<CVE>
      → Apache 自己有没有声明「影响 8.5」,以及区间。**这是唯一说了 8.5 的一层。**
源 B  NVD                                    services.nvd.nist.gov/rest/json/cves/2.0
      → cpe 配置里有没有 8.5 条目。**本注的核心信息差就在这里。**
源 C  GitHub advisory                        gh api advisories?cve_id=<CVE>
      → severity、受影响 Maven 坐标、8.5 的版本区间与修复版。

🔴 三个只有踩过才知道的坑,都写在这里,别再踩一遍:

  1. **CVE 编号年份 != 发布年份。** `CVE-2025-66614` 的 NVD `published` 是 **2026-02-17**。
     按 `pubStartDate=2025-01-01..2025-12-31` 分段查,**根本查不到它** ——
     而它恰恰是「上游写了 8.5、NVD 没有 8.5」的一条。
     → **主列表用 Apache 官方 security-9.html 抓 CVE 编号**,NVD 按 cpe 查只做交叉验证。

  2. **NVD 的 cpe 有两种形态,只看区间会漏。**
     区间型:`cpe:...:tomcat:*:...` + `versionStartIncluding` / `versionEndIncluding`;
     枚举型:`cpe:...:tomcat:10.1.0:m1:...`,版本写在 criteria 第 6 段,**没有任何区间字段**。
     `CVE-2025-66614` 有 3 条区间 + **73 条枚举**。
     → 判「NVD 有没有 8.5」必须**两种都看**。(本脚本已两种都看;实测那 73 条全是里程碑版,无 8.5。)

  3. **NVD 的 `pubStartDate`/`pubEndDate` 跨度硬上限 120 天**,超一天返回 **404** ——
     不是报错信息,是 404,很容易被读成「这个 CVE 不存在」。

⚠️ 为什么主列表用 9.x 页而不是 8.x 页:**Apache 官方的 security-8.html 停在 2024-02-19(8.5.99),
   2025 年零条目**(实测)。8.5 与 9.0 是姊妹线,影响 8.5 的必然也在 9.x 页上。
   → 这个事实本身就是本注的一块承重砖,别当成脚本的将就。

用法:  python -u tools/fetch_sources.py            拉取并写 tools/sources.json
       python -u tools/fetch_sources.py --selftest 只跑回测,不写文件
"""
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

GH = r"D:\Program Files\GitHub CLI\gh.exe"
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "sources.json")
UA = {"User-Agent": "tomcat85-check/0.1 (+https://github.com/)"}

# 🔴 回测锚点 —— 不过就不许出结论(照 install_base.py / existence_probe.py 的规矩)。
#    阳性:三个源都说影响 8.5。 负对照:上游自己也没说 8.5,NVD 也没有 —— 两边一致。
POSITIVE = "CVE-2025-55752"
NEGATIVE = "CVE-2025-55668"


def http_json(url, tries=4):
    req = urllib.request.Request(url, headers=UA)
    for i in range(tries):
        try:
            with urllib.request.urlopen(req, timeout=90) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                raise  # 参数错了,重试没意义
            if i == tries - 1:
                raise
            time.sleep(8)
        except Exception:
            if i == tries - 1:
                raise
            time.sleep(8)


def http_text(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=90) as r:
        return r.read().decode("utf-8", "replace")


# ------------------------------------------------------------------ 主列表

def cve_list(year="2025"):
    """从 Apache 官方 9.x 安全页抓该年份的 CVE 编号。见文件头坑 1。"""
    html = http_text("https://tomcat.apache.org/security-9.html")
    ids = sorted(set(re.findall(r"CVE-" + year + r"-\d{4,7}", html)))
    if not ids:
        raise SystemExit("❌ 官方页面一条 %s 的 CVE 都没抓到 —— 页面结构可能变了,中止。" % year)
    return ids


# ------------------------------------------------------------------ 源 A

def from_cna(cve):
    """@return {declares85, ranges85:[...], all_products:[...]}"""
    d = http_json("https://cveawg.mitre.org/api/cve/" + cve)
    cna = d["containers"]["cna"]
    desc = ""
    for x in cna.get("descriptions", []):
        if x.get("lang", "").startswith("en"):
            desc = x.get("value", "")
            break
    out = {"declares85": False, "ranges85": [], "affected_raw": [],
           "title": cna.get("title", ""), "description": desc}
    for af in cna.get("affected", []):
        prod = af.get("product") or ""
        for v in af.get("versions", []):
            lo = v.get("version")
            hi = v.get("lessThanOrEqual") or v.get("lessThan")
            st = v.get("status")
            out["affected_raw"].append(
                {"product": prod, "lo": lo, "hi": hi, "status": st,
                 "inclusive": "lessThanOrEqual" in v})
            # 🔴 只认「下界落在 8.5 线」的条目。
            #    `0 .. 8.5.0 [unaffected]` 这种上界含 8.5 的是**反向**声明,认了会判反。
            if st == "affected" and lo and str(lo).startswith("8.5"):
                out["declares85"] = True
                out["ranges85"].append({"lo": lo, "hi": hi,
                                        "inclusive": "lessThanOrEqual" in v})
    return out


# ------------------------------------------------------------------ 源 B

def from_nvd(cve):
    """@return {status, published, has85, tomcat_ranges, tomcat_enum_count}"""
    d = http_json("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + cve)
    vs = d.get("vulnerabilities") or []
    if not vs:
        return {"status": None, "published": None, "has85": False,
                "ranges": [], "enum85": [], "enum_count": 0, "in_nvd": False}
    it = vs[0]["cve"]
    ranges, enum85, enum_count = [], [], 0
    for cfg in it.get("configurations", []):
        for n in cfg.get("nodes", []):
            for m in n.get("cpeMatch", []):
                p = m["criteria"].split(":")
                if len(p) < 6 or p[4] != "tomcat":
                    continue
                ver = p[5]
                if ver == "*":
                    lo = m.get("versionStartIncluding") or m.get("versionStartExcluding")
                    hi = m.get("versionEndIncluding") or m.get("versionEndExcluding")
                    ranges.append({"lo": lo, "hi": hi})
                else:
                    # 见文件头坑 2:枚举型没有任何区间字段,只看区间会漏。
                    enum_count += 1
                    if ver.startswith("8.5"):
                        enum85.append(ver)
    has85 = any(r["lo"] and str(r["lo"]).startswith("8.5") for r in ranges) or bool(enum85)
    return {"status": it.get("vulnStatus"), "published": (it.get("published") or "")[:10],
            "has85": has85, "ranges": ranges, "enum85": enum85,
            "enum_count": enum_count, "in_nvd": True}


# ------------------------------------------------------------------ 源 C

def from_github(cve):
    """@return {ghsa, severity, type, pkgs85:[...], all_pkgs:[...]}

    ⚠️ GitHub advisory 的 vulnerability 对象**只有 4 个字段**:
       first_patched_version / package / vulnerable_functions / vulnerable_version_range。
       **没有 `last_affected`** —— 那是 OSV 的字段名,别照着 OSV 的经验写判据。
       8.5 那条的形状是 `range = ">= 8.5.0, <= 8.5.100"` 且 `first_patched_version = None`,
       所以「有没有修复版」要看 first_patched,「中不中招」必须解析 range 的上界。
    """
    r = subprocess.run([GH, "api", "advisories?cve_id=" + cve],
                       capture_output=True, text=True, encoding="utf-8")
    if r.returncode != 0:
        return {"ghsa": None, "severity": None, "type": None,
                "pkgs85": [], "all_pkgs": [], "error": r.stderr.strip()[:200]}
    advs = json.loads(r.stdout or "[]")
    if not advs:
        return {"ghsa": None, "severity": None, "type": None, "pkgs85": [], "all_pkgs": []}
    a = advs[0]
    pkgs85, allp = [], []
    for v in a.get("vulnerabilities", []):
        pkg = v.get("package") or {}
        name = "%s:%s" % (pkg.get("ecosystem"), pkg.get("name"))
        rng = v.get("vulnerable_version_range") or ""
        allp.append(name)
        if "8.5" in rng:
            pkgs85.append({"package": pkg.get("name"), "ecosystem": pkg.get("ecosystem"),
                           "range": rng, "first_patched": v.get("first_patched_version")})
    return {"ghsa": a.get("ghsa_id"), "severity": a.get("severity"), "type": a.get("type"),
            "summary": a.get("summary", ""), "cvss": ((a.get("cvss") or {}).get("vector_string")),
            "pkgs85": pkgs85, "all_pkgs": sorted(set(allp))}


# ------------------------------------------------------------------ 回测

def selftest():
    """已知答案回测 —— 不过就不许出结论。"""
    ok = True
    print("🔬 回测(阳性 %s / 负对照 %s)" % (POSITIVE, NEGATIVE))

    a = from_cna(POSITIVE)
    b = from_nvd(POSITIVE)
    print("  阳性 CNA.declares85=%s  NVD.has85=%s" % (a["declares85"], b["has85"]))
    if not (a["declares85"] and b["has85"]):
        print("  ❌ 阳性锚点没复现 —— 判据或数据源有问题,中止。")
        ok = False

    time.sleep(7)
    a = from_cna(NEGATIVE)
    b = from_nvd(NEGATIVE)
    print("  负对照 CNA.declares85=%s  NVD.has85=%s" % (a["declares85"], b["has85"]))
    if a["declares85"] or b["has85"]:
        print("  ❌ 负对照被判成有 8.5 —— 判据太松(很可能把 `0..8.5.0 unaffected` 认成了影响),中止。")
        ok = False

    print("  %s 回测%s" % ("✅" if ok else "❌", "通过" if ok else "失败"))
    return ok


def main():
    if not selftest():
        raise SystemExit(2)
    if "--selftest" in sys.argv:
        return

    ids = cve_list("2025")
    print("\n官方 security-9.html 抓到 %d 条 CVE-2025-*" % len(ids))
    rows = {}
    for i, cve in enumerate(ids, 1):
        print("  [%2d/%d] %s" % (i, len(ids), cve), flush=True)
        row = {"cve": cve}
        try:
            row["cna"] = from_cna(cve)
        except Exception as e:
            row["cna"] = {"error": str(e)[:200], "declares85": False, "ranges85": []}
        time.sleep(1)
        try:
            row["nvd"] = from_nvd(cve)
        except Exception as e:
            row["nvd"] = {"error": str(e)[:200], "has85": False, "in_nvd": False}
        row["gh"] = from_github(cve)
        rows[cve] = row
        time.sleep(7)  # NVD 无 key 限速 5 请求 / 30 秒

    gap = [c for c, r in rows.items() if r["cna"].get("declares85") and not r["nvd"].get("has85")]
    both = [c for c, r in rows.items() if r["cna"].get("declares85") and r["nvd"].get("has85")]
    none_ = [c for c, r in rows.items() if not r["cna"].get("declares85")]

    # 🔴 本注的核心事实就是这个差集。它要是空的,整注的前提就没了 —— 宁可中止也不生成空表。
    if not gap:
        raise SystemExit("❌ 差集为空:没有任何一条「上游写了 8.5、NVD 没有」。本注前提不成立,中止。")

    payload = {"generated": time.strftime("%Y-%m-%d %H:%M:%S"),
               "source_list": "https://tomcat.apache.org/security-9.html",
               "rows": rows,
               "summary": {"total": len(rows), "gap": sorted(gap),
                           "both": sorted(both), "no_85_upstream": sorted(none_)}}
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=1)

    print("\n" + "=" * 62)
    print("总计 %d 条 CVE-2025-*" % len(rows))
    print("  上游写 8.5 + NVD 也有   : %2d 条  %s" % (len(both), sorted(both)))
    print("  🔴 上游写 8.5 + NVD 没有: %2d 条  %s" % (len(gap), sorted(gap)))
    print("  上游自己也没写 8.5      : %2d 条  %s" % (len(none_), sorted(none_)))
    print("已写 " + OUT)


if __name__ == "__main__":
    main()
