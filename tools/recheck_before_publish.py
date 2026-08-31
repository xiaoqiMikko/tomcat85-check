# -*- coding: utf-8 -*-
r"""发文前的承重论据复核 —— **用和生成脚本无关的口径,把同一批东西再数一遍**。

🔴 **这一步不是走过场。** 第 6 注的教训:生成脚本写了 6 条断言、34 个测试、四个真 jar 复验,
   **全部通过**,而表里一条 CVE 挂着另一条的标题、另两条整个丢失 ——
   **所有防线验的都是「表里的东西对不对」,没有一条验「该在表里的是不是都在」。**

☠️ **本脚本第一次运行就抓到了一个真错**(2026-09-01):
   生成脚本判「NVD 有没有 8.5」时只认「下界以 8.5 开头」,
   而 `CVE-2025-24813` 在 NVD 里写的是 **`versionStartIncluding=None` .. `versionEndExcluding=9.0.99`**
   —— 下界开放,**它是覆盖 8.5 的**。于是差集被多算了一条(11 → 实际 10),
   而那条恰恰是全表**唯一的 critical**。
   **逐条查 cveId 永远发现不了它,是「按 cpe 查 8.5.100」这个用户视角的口径撞出来的。**

复核四条承重论据:
  A. 「N 条上游写了 8.5 而 NVD 查不到」—— 独立口径:**按 cpe 查 8.5.100**,
     数 NVD 那侧到底能查到几条,和表里的 `nvdHas85=true` 对上。
  B. 8.5 那侧 `first_patched_version` 仍然全是 null(「没有可升的版本」这个主张)。
  C. Apache 官方 `security-8.html` 仍然没有 2025 年条目(「官方 8.5 页停更」这个主张)。
  D. 默认配置即受影响的仍然只有 2 条(文案重心)。
     🔴 D 直接解析生成出来的 `CveTable.java`,**不读 sources.json** —— 读原料就不算独立了。

任一条不过 → **停下改文案,不要「先发了再说」**。

用法:python -u tools/recheck_before_publish.py
"""
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = os.path.dirname(os.path.abspath(__file__))
TABLE = os.path.join(HERE, "..", "src", "main", "java", "dev", "mikko",
                     "tomcat85check", "CveTable.java")
GH = r"D:\Program Files\GitHub CLI\gh.exe"
UA = {"User-Agent": "tomcat85-check-recheck/0.1"}

FAILS = []


def fail(msg):
    FAILS.append(msg)
    print("  ❌ " + msg)


def ok(msg):
    print("  ✅ " + msg)


def http_json(url, tries=4):
    req = urllib.request.Request(url, headers=UA)
    for i in range(tries):
        try:
            with urllib.request.urlopen(req, timeout=90) as r:
                return json.load(r)
        except Exception:
            if i == tries - 1:
                raise
            time.sleep(8)


def http_text(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=90) as r:
        return r.read().decode("utf-8", "replace")


# ------------------------------------------------------------------ 读表(独立于 sources.json)

def parse_table():
    """从生成出来的 CveTable.java 里把每条读回来。

    🔴 故意解析 Java 源文件而不是 sources.json —— 读原料就等于和生成脚本用同一份数据,
    那样再数一遍毫无意义。这里要的是「**发出去的那份**表里到底写了什么」。
    """
    src = open(TABLE, encoding="utf-8").read()
    rows = []
    # ⚠️ 生成物的字段一变，这个正则就对不上——2026-09-01 加 asfSeverity 时就撞过一次。
    #    好在下面那条 `if not rows` 会中止而不是静默给空结果。**别把它删掉。**
    for m in re.finditer(
            r'new Cve\("(CVE-[\d-]+)",\s*("(?:GHSA-[\w-]+)"|null),\s*"(\w+)",\s*"(\w+)",\s*\n'
            r'\s*"([\d.]+)",\s*"([\d.]+)",\s*(true|false),',
            src):
        rows.append({"cve": m.group(1), "ghsa": m.group(2).strip('"'),
                     "severity": m.group(3), "asf": m.group(4),
                     "lo": m.group(5), "hi": m.group(6),
                     "nvd_has85": m.group(7) == "true"})
    # 触发条件：每条的倒数第二行是 `"COND", "说明"`
    conds = re.findall(r'\n\s*"(\w+)", "', src)
    if not rows:
        raise SystemExit("❌ 一条都没解析出来 —— CveTable.java 的格式变了?先修本脚本再发文。")
    return rows, conds


# ------------------------------------------------------------------ A

def check_a(rows):
    """独立口径:按 cpe 查 8.5.100,看 NVD 那侧真能查到几条。"""
    print("\nA. 「NVD 查不到」的条数 —— 独立口径:按 cpe 查 8.5.100")
    cpe = "cpe:2.3:a:apache:tomcat:8.5.100:*:*:*:*:*:*:*"
    d = http_json("https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString="
                  + urllib.parse.quote(cpe))
    nvd_ids = {v["cve"]["id"] for v in d["vulnerabilities"] if v["cve"]["id"].startswith("CVE-2025-")}
    print("     NVD 按 cpe 8.5.100 查到的 CVE-2025-*:%d 条 %s"
          % (len(nvd_ids), sorted(nvd_ids)))

    table_has = {r["cve"] for r in rows if r["nvd_has85"]}
    table_gap = {r["cve"] for r in rows if not r["nvd_has85"]}
    print("     表里标 nvdHas85=true 的:%d 条 %s" % (len(table_has), sorted(table_has)))

    # 表里说「NVD 有」的,按 cpe 查也必须查得到
    missing = table_has - nvd_ids
    if missing:
        fail("表里标「NVD 有 8.5」但按 cpe 查不到:%s" % sorted(missing))
    else:
        ok("表里标「NVD 有」的 %d 条,按 cpe 查全部命中" % len(table_has))

    # 🔴 反方向才是要命的:表里说「NVD 没有」,而按 cpe 查得到 —— 差集被多算了。
    wrong = table_gap & nvd_ids
    if wrong:
        fail("表里标「NVD 查不到」但按 cpe **查得到**:%s —— 差集多算了,先改表再发文" % sorted(wrong))
    else:
        ok("表里标「NVD 查不到」的 %d 条,按 cpe 确实一条都查不到" % len(table_gap))
    return len(table_gap)


# ------------------------------------------------------------------ B

def check_b(rows):
    """8.5 侧还是一个修复版都没有。"""
    print("\nB. 8.5 那侧仍然没有任何 first_patched_version")
    patched = []
    for r in rows:
        if not r["ghsa"] or r["ghsa"] == "null":
            continue
        out = subprocess.run([GH, "api", "advisories/" + r["ghsa"]],
                             capture_output=True, text=True, encoding="utf-8")
        if out.returncode != 0:
            fail("拉 %s 失败:%s" % (r["ghsa"], out.stderr.strip()[:120]))
            continue
        adv = json.loads(out.stdout)
        for v in adv.get("vulnerabilities", []):
            rng = v.get("vulnerable_version_range") or ""
            if "8.5" in rng and v.get("first_patched_version"):
                patched.append((r["cve"], rng, v["first_patched_version"]))
    if patched:
        fail("8.5 侧出现了修复版 —— 「没有可升的版本」这个主张不再成立:%s" % patched)
    else:
        ok("查了 %d 条 advisory,8.5 侧 first_patched_version 仍然全是 null" % len(rows))


# ------------------------------------------------------------------ C

def check_c():
    """Apache 官方 8.5 安全页仍然停更。"""
    print("\nC. Apache 官方 security-8.html 仍无 2025 年条目")
    html = http_text("https://tomcat.apache.org/security-8.html")
    y2025 = sorted(set(re.findall(r"CVE-2025-\d{4,7}", html)))
    y2026 = sorted(set(re.findall(r"CVE-2026-\d{4,7}", html)))
    if y2025 or y2026:
        fail("官方 8.5 页出现了新条目(2025:%s / 2026:%s)—— 「官方停更」这个主张要改" % (y2025, y2026))
    else:
        n = len(set(re.findall(r"CVE-\d{4}-\d{4,7}", html)))
        ok("官方 8.5 页共 %d 条 CVE,2025/2026 年零条目" % n)


# ------------------------------------------------------------------ D

def check_d(conds):
    """默认即受影响的仍然只有 2 条。"""
    print("\nD. 默认配置即受影响的仍然只有 2 条(文案重心)")
    n = conds.count("DEFAULT")
    if n != 2:
        fail("默认即受影响变成 %d 条了 —— 文案重心要重算" % n)
    else:
        ok("DEFAULT 仍是 2 条")



# ------------------------------------------------------------------ 自测

def selftest():
    """验证 A 这条判据**真的抓得住错**,而不是永远报绿。

    🔴 项目纪律:结论正确不能反过来证明方法有效。两个方向各注入一次已知错误 ——
    第二个方向正是 2026-09-01 真实发生过的那个(差集多算了 CVE-2025-24813)。
    """
    global FAILS
    print("🔬 自测:往两个方向各注入一次已知错误,看 A 认不认得出")
    rows, _ = parse_table()

    def run(mutate, label, expect_fail):
        global FAILS
        rs = [dict(r) for r in rows]
        mutate(rs)
        FAILS = []
        buf = sys.stdout
        sys.stdout = open(os.devnull, "w", encoding="utf-8")
        try:
            check_a(rs)
        finally:
            sys.stdout.close()
            sys.stdout = buf
        got = bool(FAILS)
        print("  %s %-46s 报错=%s 期望=%s" % ("OK " if got == expect_fail else "❌",
                                              label, got, expect_fail))
        return got == expect_fail

    good = run(lambda rs: None, "原样(不该报错)", False)
    # 方向一:表里说「NVD 有」,实际查不到
    m1 = run(lambda rs: [r.update(nvd_has85=True) for r in rs if r["cve"] == "CVE-2025-53506"],
             "把真查不到的 53506 标成「NVD 有」", True)
    # 方向二:☠️ 真实发生过的那个 —— 差集多算
    m2 = run(lambda rs: [r.update(nvd_has85=False) for r in rs if r["cve"] == "CVE-2025-24813"],
             "把真查得到的 24813 标成「NVD 没有」", True)

    FAILS = []
    if good and m1 and m2:
        print("  ✅ 自测通过 —— 这条判据两个方向都抓得住")
        return True
    print("  ❌ 自测没过 —— 判据本身坏了,它给的绿灯不算数")
    return False



# ------------------------------------------------------------------ E

def check_e(rows):
    """两套文字评级都还在,且 Apache 那套仍是 ASF 四档。"""
    print("\nE. 两套评级都在,且 Apache 用的仍是 ASF 四档")
    asf_ok = {"low", "moderate", "important", "critical"}
    gh_ok = {"low", "medium", "high", "critical"}
    bad = [r["cve"] for r in rows
           if r["asf"].lower() not in asf_ok or r["severity"].lower() not in gh_ok]
    if bad:
        fail("这些条目的评级不在预期词表里(上游换口径了?):%s" % bad)
        return
    # 对齐依据是 Tomcat 官方 security-impact.html 原文:"Important (or High)"
    differ = [r["cve"] for r in rows
              if {"important": "high"}.get(r["asf"].lower(), r["asf"].lower())
              != r["severity"].lower()]
    ok("%d 条都有两套评级;按官方原文对齐(Important = High)后仍有 %d 条写得不一样"
       % (len(rows), len(differ)))


def main():
    print("=" * 66)
    print("tomcat85-check 发文前复核 ——", time.strftime("%Y-%m-%d %H:%M:%S"))
    print("=" * 66)
    if not selftest():
        sys.exit(2)
    if "--selftest" in sys.argv:
        return
    rows, conds = parse_table()
    print("从 CveTable.java 解析出 %d 条(独立于 sources.json)" % len(rows))

    gap = check_a(rows)
    time.sleep(7)
    check_b(rows)
    check_c()
    check_d(conds)
    check_e(rows)

    print("\n" + "=" * 66)
    if FAILS:
        print("❌ %d 条承重论据没过 —— 🔴 停下改文案,不要「先发了再说」:" % len(FAILS))
        for f in FAILS:
            print("   · " + f)
        sys.exit(1)
    print("✅ 五条承重论据全过。可以发文的数字:")
    print("   · 上游写了 8.5 而 NVD 查不到:**%d 条**" % gap)
    print("   · 表内共 %d 条,默认即受影响 %d 条" % (len(rows), conds.count("DEFAULT")))


if __name__ == "__main__":
    main()
