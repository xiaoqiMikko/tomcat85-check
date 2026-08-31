package dev.mikko.tomcat85check;

import java.util.ArrayList;
import java.util.List;

/**
 * 把「版本命中」和「触发条件成不成立」合成一个用户能照着做事的结论。
 *
 * <h2>为什么不能只报版本</h2>
 *
 * <p>{@link CveTable} 里 14 条,<b>默认配置即受影响的只有 2 条</b>。
 * 只按版本报,等于把 12 条「要特定配置才成立」的条目也说成「你中了」——
 * 那是<b>让用户去做一件不必要的事</b>,而本项目的规矩是:判定规则错了不是误报,是害人。
 *
 * <h2>🔴 档位的设计原则:不确定就说不确定,不许替用户猜</h2>
 *
 * <p>没有「不受影响」这个档位,只有 {@link Verdict#NOT_APPLICABLE},
 * 而它<b>只在能给出结构性理由时</b>才用(目前仅 Windows 安装程序那一条)。
 * 配置没找到一律落进 {@link Verdict#NEEDS_REVIEW} ——
 * 因为 {@link ConfigProbe} 能确认开启,<b>不能确认没开</b>。
 */
public final class Applicability {

    public enum Verdict {
        /** 版本命中,且默认配置即受影响 —— 不需要用户开任何东西。 */
        AFFECTED_DEFAULT,
        /** 版本命中,且触发条件已在你的配置里确认开着。 */
        AFFECTED_CONFIG_CONFIRMED,
        /** 版本命中,但触发条件本工具确认不了 —— <b>要人来判断</b>。 */
        NEEDS_REVIEW,
        /** 有结构性理由说它不适用(目前只有 Windows 安装程序那条)。 */
        NOT_APPLICABLE,
        /** 版本不在这条的区间内。 */
        VERSION_NOT_AFFECTED
    }

    /**
     * 一条判定结果。
     *
     * @param reason 给用户看的理由 —— 每个档位都必须有,包括「为什么我说不准」
     */
    public record Result(CveTable.Cve cve, Verdict verdict, ConfigProbe.Finding finding,
                         String reason) {

        /** 要不要在报告里排在前面。 */
        public boolean actionable() {
            return verdict == Verdict.AFFECTED_DEFAULT
                    || verdict == Verdict.AFFECTED_CONFIG_CONFIRMED;
        }

        /** NVD 里查不到 —— 本工具存在的理由。 */
        public boolean invisibleInNvd() {
            return !cve.nvdHas85();
        }
    }

    private Applicability() {
    }

    /**
     * 判定全表。
     *
     * @param version 实际装的版本;为 null 表示没取到 —— 那样一条都不判,由调用方去报警告
     * @param probe   配置探测结果;为 null 表示没给安装目录
     */
    public static List<Result> judge(TomcatVersion version, ConfigProbe probe) {
        List<Result> out = new ArrayList<>();
        for (CveTable.Cve c : CveTable.all()) {
            out.add(judgeOne(c, version, probe));
        }
        return out;
    }

    static Result judgeOne(CveTable.Cve c, TomcatVersion version, ConfigProbe probe) {
        if (version == null || !c.affects(version)) {
            String why = version == null
                    ? "没取到版本号,无法判定 —— 🔴 这不等于「没有漏洞」。"
                    : "版本 " + version + " 不在 " + c.lo85() + "–" + c.hi85() + " 区间内。";
            return new Result(c, Verdict.VERSION_NOT_AFFECTED, null, why);
        }

        // Windows 安装程序那条是唯一能给出结构性「不适用」的
        if ("WINDOWS_INSTALLER".equals(c.condition())) {
            ConfigProbe.Finding f = probe == null
                    ? new ConfigProbe.Finding(c.condition(), ConfigProbe.State.NOT_CHECKED,
                    List.of(), "没给安装目录,判不了是不是用 Windows 安装程序装的。")
                    : probe.installedByWindowsInstaller();
            if (f.state() == ConfigProbe.State.CONFIRMED) {
                return new Result(c, Verdict.AFFECTED_CONFIG_CONFIRMED, f,
                        "版本命中,且找到了 Windows 安装程序的痕迹。");
            }
            if (f.state() == ConfigProbe.State.NOT_FOUND) {
                return new Result(c, Verdict.NOT_APPLICABLE, f,
                        "版本命中,但这条的漏洞在 Windows 安装程序里,"
                                + "而这个目录没有安装程序痕迹(多半是解压部署)。" + f.note());
            }
            return new Result(c, Verdict.NEEDS_REVIEW, f, f.note());
        }

        if (c.defaultAffected()) {
            return new Result(c, Verdict.AFFECTED_DEFAULT, null,
                    "版本命中,且" + c.conditionNote());
        }

        ConfigProbe.Finding f = probe == null
                ? new ConfigProbe.Finding(c.condition(), ConfigProbe.State.NOT_CHECKED,
                List.of(), "没给安装目录,没查配置。")
                : probe.check(c.condition());

        return switch (f.state()) {
            case CONFIRMED -> new Result(c, Verdict.AFFECTED_CONFIG_CONFIRMED, f,
                    "版本命中,且触发条件在你的配置里找到了(" + String.join("; ", f.where()) + ")。"
                            // 🔴 f.note() 不许省:CAVEATS 里那些「找到了也不等于就是它」的话都在里面。
                            + c.conditionNote() + " " + f.note());
            // 🔴 POSSIBLE / 没找到 / 没查 都落这里 ——
            //    弱标记(如默认就在的 AprLifecycleListener)命中不算确认,否则每个默认安装都被虚报。
            case POSSIBLE, NOT_FOUND, NOT_CHECKED -> new Result(c, Verdict.NEEDS_REVIEW, f,
                    "版本命中,但触发条件本工具确认不了。" + c.conditionNote() + " " + f.note());
        };
    }

    /** 一份可直接读的小结。 */
    public static String summarize(List<Result> rs) {
        long def = rs.stream().filter(r -> r.verdict() == Verdict.AFFECTED_DEFAULT).count();
        long conf = rs.stream().filter(r -> r.verdict() == Verdict.AFFECTED_CONFIG_CONFIRMED).count();
        long rev = rs.stream().filter(r -> r.verdict() == Verdict.NEEDS_REVIEW).count();
        long na = rs.stream().filter(r -> r.verdict() == Verdict.NOT_APPLICABLE).count();
        long invisible = rs.stream()
                .filter(r -> r.verdict() != Verdict.VERSION_NOT_AFFECTED)
                .filter(Result::invisibleInNvd).count();
        return String.format(
                "默认即受影响 %d 条 · 配置已确认 %d 条 · 需人工确认 %d 条 · 不适用 %d 条%n"
                        + "其中 %d 条在 NVD 的 cpe 配置里查不到 8.5 —— 读 NVD 的工具和文章看不见它们。%n",
                def, conf, rev, na, invisible);
    }
}
