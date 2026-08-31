package dev.mikko.tomcat85check;

import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 命令行入口。
 *
 * <p>回答一个问题:<b>我这台还在跑的 Tomcat 8.5,到底中了哪些 2025 年的 CVE?</b>
 * 而这个问题在别处查不到答案 —— 官方 8.5 安全页停在 2024、NVD 里 10 条没有 8.5 的条目、
 * GitHub advisory 有但一条修复版都不给。
 */
public final class Main {

    public static void main(String[] args) throws Exception {
        boolean utf8 = false;
        boolean showAll = false;
        List<String> paths = new ArrayList<>();
        for (String a : args) {
            switch (a) {
                case "--utf8" -> utf8 = true;
                case "--all" -> showAll = true;
                case "-h", "--help" -> {
                    usage(System.out);
                    return;
                }
                default -> paths.add(a);
            }
        }
        // Windows 控制台默认 GBK,中文会花;--utf8 强制按 UTF-8 输出。
        PrintStream out = utf8
                ? new PrintStream(new java.io.FileOutputStream(java.io.FileDescriptor.out),
                true, StandardCharsets.UTF_8.name())
                : System.out;

        if (paths.isEmpty()) {
            usage(out);
            System.exit(2);
        }

        Scanner sc = new Scanner();
        for (String p : paths) {
            sc.scan(Paths.get(p));
        }
        report(out, sc, paths, showAll);
    }

    private static void usage(PrintStream out) {
        out.println("tomcat85-check - what your EOL Tomcat 8.5 is actually vulnerable to");
        out.println("  (Chinese text garbled? re-run with --utf8)");
        out.println();
        out.println("tomcat85-check —— 还在跑的 Tomcat 8.5 到底中了哪些 CVE");
        out.println();
        out.println("  用法:java -jar tomcat85-check.jar [选项] <安装目录 | jar | war> ...");
        out.println();
        out.println("  选项:");
        out.println("    --utf8   按 UTF-8 输出(Windows 控制台中文乱码时用)");
        out.println("    --all    连「版本不在区间内」的条目也列出来");
        out.println();
        out.println("  给安装目录(含 conf/ 的那一级)时,还会读 conf 下的 XML 判断触发条件 ——");
        out.println("  表里 14 条只有 2 条是默认即受影响的,不看配置的结论没有意义。");
    }

    private static void report(PrintStream out, Scanner sc, List<String> paths, boolean showAll)
            throws Exception {
        out.println("=".repeat(72));
        out.println("tomcat85-check");
        out.println("=".repeat(72));

        for (String w : sc.warnings()) {
            out.println("⚠️  " + w);
        }

        if (sc.artifacts().isEmpty()) {
            out.println();
            out.println("没有扫到任何 Tomcat 构件。");
            out.println("🔴 这不等于「你很安全」—— 也可能是路径给错了,或者这套部署本工具认不出来。");
            return;
        }

        // ---- 找到了什么
        out.println();
        out.println("扫到 " + sc.artifacts().size() + " 个 Tomcat 构件:");
        Map<String, List<Scanner.Artifact>> byVer = new LinkedHashMap<>();
        for (Scanner.Artifact a : sc.artifacts()) {
            byVer.computeIfAbsent(a.version().toString(), k -> new ArrayList<>()).add(a);
        }
        for (Map.Entry<String, List<Scanner.Artifact>> e : byVer.entrySet()) {
            out.printf("  %-12s %d 个(%s)%n", e.getKey(), e.getValue().size(),
                    e.getValue().get(0).source());
        }

        for (Scanner.Install in : sc.installs()) {
            out.println();
            out.println("安装目录:" + in.root());
            out.println("  ServerInfo:" + (in.serverInfo() == null ? "(无)" : in.serverInfo()));
            if (in.versionConflict()) {
                out.println("  🔴 两个版本源对不上:ServerInfo.properties = " + in.serverNumber()
                        + ",MANIFEST = " + in.manifest());
                out.println("     ServerInfo.properties 是可以被覆盖的(常用来隐藏版本)。"
                        + "本工具两个都报出来,不替你选 —— 下面按 ServerInfo 那个判。");
            }
        }

        // ---- 判定
        TomcatVersion v = sc.installs().isEmpty()
                ? sc.artifacts().get(0).version()
                : sc.installs().get(0).effective();

        ConfigProbe probe = null;
        for (String p : paths) {
            Path root = Paths.get(p);
            ConfigProbe cp = new ConfigProbe();
            cp.load(root);
            if (cp.hasConfig()) {
                probe = cp;
                break;
            }
        }

        out.println();
        if (probe == null) {
            out.println("⚠️  没读到 conf/ 下的配置文件 —— 需要特定配置才成立的条目一律落进「需人工确认」。");
            out.println("    把安装目录(含 conf/ 的那一级)传进来能少一大截人工活。");
        } else {
            out.println("已读 " + probe.scannedFiles().size() + " 个配置文件(已剥除 XML 注释块)。");
        }

        List<Applicability.Result> rs = Applicability.judge(v, probe);
        out.println();
        out.println("-".repeat(72));
        out.println("判定版本:" + v);
        out.print(Applicability.summarize(rs));
        out.println("-".repeat(72));

        // ---- 分档
        print(out, "🔴 默认配置即受影响 —— 不需要你开任何东西",
                rs, Applicability.Verdict.AFFECTED_DEFAULT);
        print(out, "🔴 触发条件已在你的配置里确认",
                rs, Applicability.Verdict.AFFECTED_CONFIG_CONFIRMED);
        print(out, "⚠️  需人工确认 —— 版本命中,但触发条件本工具确认不了",
                rs, Applicability.Verdict.NEEDS_REVIEW);
        print(out, "✅ 有结构性理由认为不适用",
                rs, Applicability.Verdict.NOT_APPLICABLE);
        if (showAll) {
            print(out, "· 版本不在区间内", rs, Applicability.Verdict.VERSION_NOT_AFFECTED);
        }

        // ---- 最后那句必须说清楚的话
        long hit = rs.stream()
                .filter(r -> r.verdict() != Applicability.Verdict.VERSION_NOT_AFFECTED).count();
        if (hit > 0) {
            out.println();
            out.println("=".repeat(72));
            out.println("🔴 没有可升的 8.5 版本。");
            out.println("   8.5.100 是终版(2024-03-19 发布),8.5 线已于 2024-03-31 EOL。");
            out.println("   上面每一条的 GitHub advisory 在 8.5 那一侧,first_patched_version 都是 null ——");
            out.println("   不是「还没修」,是「不会为 8.5 修了」。唯一的出路是换线(9.0 / 10.1 / 11.0)。");
            out.println("=".repeat(72));
        }
    }

    private static void print(PrintStream out, String header, List<Applicability.Result> rs,
                              Applicability.Verdict v) {
        List<Applicability.Result> list = rs.stream().filter(r -> r.verdict() == v)
                .sorted((a, b) -> rank(b.cve().severity()) - rank(a.cve().severity()))
                .toList();
        if (list.isEmpty()) {
            return;
        }
        out.println();
        out.println(header + "(" + list.size() + " 条)");
        for (Applicability.Result r : list) {
            CveTable.Cve c = r.cve();
            out.printf("  %-16s %-9s %s%n", c.id(), c.severity(),
                    c.nvdHas85() ? "" : "🔍 NVD 的 cpe 里查不到 8.5");
            out.println("      影响 " + c.lo85() + "–" + c.hi85()
                    + (c.ghsa() == null ? "" : "  " + c.ghsa()));
            // 🔴 四个数字都摆出来,标签必须写清是谁给的。
            //    Apache 用 ASF 四档(low/moderate/important/critical),
            //    GitHub 用 low/medium/high/critical —— **不是同一套**,别拿一个冒充另一个。
            out.println("      评级:Apache(ASF)" + c.asfSeverity()
                    + " · GitHub " + c.severity()
                    + " · CVSS v3.1 " + score(c.cvss3(), c.cvss3Severity())
                    + " · CVSS v4.0 " + score(c.cvss4(), null));
            // 分歧要主动说。不说的话,用户去别处一看对不上,会认为**本工具报错了**。
            if (c.ratingsDiffer()) {
                out.println("      ⚠️  Apache 和 GitHub 判得不一样(「" + c.asfSeverity()
                        + "」vs「" + c.severity() + "」)。两套体系量的不是同一件事:"
                        + "Apache 评的是默认配置下的实际可利用性,GitHub / CVSS 按向量机械计算。");
            } else if (c.ratingUnalignable()) {
                out.println("      ·  Apache 评「" + c.asfSeverity() + "」,GitHub 评「"
                        + c.severity() + "」—— 官方没说这两档相等,本工具不替它对齐,两个都摆给你。");
            }
            if (c.severityGap()) {
                out.println("      ⚠️  GitHub 评「" + c.severity()
                        + "」,而 CVSS v3.1 是「" + c.cvss3Severity() + "」—— NVD 采信的是后者。");
            }
            if (c.cvssVersionSplit()) {
                out.println("      ⚠️  同一条 CVE,CVSS v3.1 与 v4.0 差了 "
                        + String.format("%.1f", Math.abs(c.cvss3() - c.cvss4()))
                        + " 分 —— 引哪个版本的分数,结论就差一个档次。");
            }
            out.println("      " + r.reason());
            if (c.upstreamSelfConflict()) {
                out.println("      ⚠️  Apache 自己两处写法不一致:结构化字段 " + c.lo85() + "–" + c.hi85()
                        + ",描述正文 " + c.textRange85() + "。本工具取窄的那个(少报)。");
            }
        }
    }

    /** 没有那个版本的分数时印「—」,<b>不许印 0</b> —— 那会被读成「0 分 = 没风险」。 */
    private static String score(Double v, String tier) {
        if (v == null) {
            return "—";
        }
        return String.format("%.1f", v) + (tier == null ? "" : "(" + tier + ")");
    }

    private static int rank(String severity) {
        return switch (severity == null ? "" : severity) {
            case "critical" -> 4;
            case "high" -> 3;
            case "medium" -> 2;
            case "low" -> 1;
            default -> 0;
        };
    }

    private Main() {
    }
}
