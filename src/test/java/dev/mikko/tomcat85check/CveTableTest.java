package dev.mikko.tomcat85check;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 判定表的自检。
 *
 * <p>⚠️ 这里验的全是「表里的东西对不对」。第 6 注的教训是:
 * <b>所有防线都在验表里的东西,没有一条验「该在表里的是不是都在」</b> ——
 * 那一项要用**和生成脚本无关的独立口径**做,放在 {@code tools/recheck_before_publish.py}(联网),
 * 不放在单元测试里。两者别互相替代。
 */
class CveTableTest {

    // ---------------------------------------------------------------- 边界

    @Test
    void 终版8_5_100必须命中() {
        // 🔴 本注最容易判错的一格。8.5 那侧 GitHub 的 first_patched_version 全是 null,
        //    区间是闭区间 `>= 8.5.0, <= 8.5.100`。用「低于修复版才算中招」的判据,
        //    8.5.100(**终版,也是绝大多数还在跑的版本**)会被判成不中招 —— 整个工具就废了。
        TomcatVersion v = TomcatVersion.parse("8.5.100");
        assertFalse(CveTable.matching(v).isEmpty(), "8.5.100 必须命中条目");
        assertEquals(CveTable.all().size(), CveTable.matching(v).size(),
                "8.5.100 落在每一条的区间上界内,应当全部命中");
    }

    @Test
    void 四段版本号也要命中() {
        // ServerInfo.properties 报的是四段 8.5.100.0,不能因为多一段就判不中。
        assertEquals(CveTable.all().size(),
                CveTable.matching(TomcatVersion.parse("8.5.100.0")).size());
    }

    @Test
    void 区间下界之外的不该命中() {
        // CVE-2025-31650 的上游区间是 8.5.90 .. 8.5.100 —— 8.5.89 不该中。
        CveTable.Cve c = byId("CVE-2025-31650");
        assertEquals("8.5.90", c.lo85());
        assertFalse(c.affects(TomcatVersion.parse("8.5.89")), "低于下界不该命中");
        assertTrue(c.affects(TomcatVersion.parse("8.5.90")), "下界是闭的");
    }

    @Test
    void 别的版本线不该命中() {
        for (String v : List.of("9.0.107", "10.1.43", "11.0.11", "7.0.109", "8.5.101")) {
            assertTrue(CveTable.matching(TomcatVersion.parse(v)).isEmpty(),
                    v + " 不在 8.5 区间内,不该命中任何条目");
        }
    }

    @Test
    void 解析不出的版本不该命中() {
        assertTrue(CveTable.matching(TomcatVersion.parse("8.5.x")).isEmpty());
        assertTrue(CveTable.matching(null).isEmpty(), "null 不该 NPE,也不该命中");
    }

    // ---------------------------------------------------------------- 表本身

    @Test
    void 核心事实必须还在() {
        long gap = CveTable.all().stream().filter(c -> !c.nvdHas85()).count();
        assertTrue(gap > 0, "「上游写了 8.5、NVD 查不到」的条目一条都没有的话,本注就没有理由存在");
        assertEquals(gap, CveTable.invisibleInNvd(TomcatVersion.parse("8.5.100")).size(),
                "8.5.100 应命中全部 NVD 不可见条目");
    }

    @Test
    void 每条都要有触发条件() {
        // 🔴 缺了会被读成「无条件即中招」—— 那是让用户做错事。
        for (CveTable.Cve c : CveTable.all()) {
            assertNotNull(c.condition(), c.id() + " 缺 condition");
            assertFalse(c.condition().isBlank(), c.id() + " 的 condition 是空的");
            assertNotNull(c.conditionNote(), c.id() + " 缺 conditionNote");
            assertFalse(c.conditionNote().isBlank(), c.id() + " 的 conditionNote 是空的");
        }
    }

    @Test
    void 默认配置即受影响的是少数() {
        // 🔴 这不是凑数的断言,是本注的头号风险:绝大多数条目要特定配置才成立。
        //    哪天它变成「多数」,文案的重心就得改 —— 这条测试就是那个提醒。
        long def = CveTable.all().stream().filter(CveTable.Cve::defaultAffected).count();
        assertTrue(def < CveTable.all().size() / 2,
                "默认即受影响的条目变成多数了(" + def + "/" + CveTable.all().size()
                        + ")—— 回去改文案重心,别直接改这条断言");
    }

    @Test
    void 字段格式合法() {
        Set<String> ok = Set.of("low", "medium", "high", "critical");
        for (CveTable.Cve c : CveTable.all()) {
            assertTrue(c.id().startsWith("CVE-"), c.id());
            assertTrue(c.ghsa() == null || c.ghsa().startsWith("GHSA-"), c.id() + " ghsa=" + c.ghsa());
            assertTrue(ok.contains(c.severity()), c.id() + " severity=" + c.severity());
            assertTrue(c.lo85().startsWith("8.5"), c.id() + " lo85=" + c.lo85());
            assertEquals("8.5.100", c.hi85(), c.id() + " 的上界应是 8.5 终版");
        }
    }

    @Test
    void 编号不重复() {
        Set<String> ids = CveTable.all().stream().map(CveTable.Cve::id).collect(Collectors.toSet());
        assertEquals(CveTable.all().size(), ids.size(), "表里有重复的 CVE 编号");
    }

    @Test
    void Windows安装程序那条要能被单独认出来() {
        // 🔴 CVE-2025-49124 的漏洞在 Windows 安装程序里,解压 zip/tar.gz 部署的**不适用**。
        //    本注的用户大量是解压部署 —— 把它报成「你中了」就是虚报。
        CveTable.Cve c = byId("CVE-2025-49124");
        assertEquals("WINDOWS_INSTALLER", c.condition());
        assertFalse(c.defaultAffected());
    }

    // ---------------------------------------------------------------- 官方自相矛盾

    @Test
    void 官方自相矛盾的条目要带出来() {
        // 🔴 CVE-2025-49124:CNA 结构化字段写 8.5.44,描述正文写 8.5.0。
        //    本表取窄的那个(少报),但不许默默吞掉这个矛盾。
        CveTable.Cve c = byId("CVE-2025-49124");
        assertTrue(c.upstreamSelfConflict(), "官方两处写法不一致,表里必须看得出来");
        assertEquals("8.5.44", c.lo85(), "取结构化字段(区间更窄)");
        assertEquals("8.5.0..8.5.100", c.textRange85(), "正文那个也要带着");
        assertFalse(c.affects(TomcatVersion.parse("8.5.43")),
                "取窄区间就要真的少报,不能只是记个字段");
    }

    @Test
    void 只有那一条自相矛盾() {
        long n = CveTable.all().stream().filter(CveTable.Cve::upstreamSelfConflict).count();
        assertEquals(1, n, "自相矛盾的条目数变了,回去看是不是上游改了数据");
    }

    // ---------------------------------------------------------------- 评级(三套 + 两个 CVSS 版本)

    @Test
    void 每条都要有两套文字评级() {
        // 🔴 只剩 GitHub 那一套的话,我们就只是在转述别人的判断,本注没有独立价值。
        for (CveTable.Cve c : CveTable.all()) {
            assertNotNull(c.severity(), c.id() + " 缺 GitHub 评级");
            assertNotNull(c.asfSeverity(), c.id() + " 缺 Apache 的 ASF 评级");
        }
    }

    @Test
    void 两套评级用的是两套词表() {
        // ASF:low / moderate / important / critical;GitHub:low / medium / high / critical
        Set<String> asf = Set.of("low", "moderate", "important", "critical");
        Set<String> gh = Set.of("low", "medium", "high", "critical");
        for (CveTable.Cve c : CveTable.all()) {
            assertTrue(asf.contains(c.asfSeverity().toLowerCase()),
                    c.id() + " 的 ASF 评级不在四档里:" + c.asfSeverity());
            assertTrue(gh.contains(c.severity().toLowerCase()), c.id() + " " + c.severity());
        }
    }

    @Test
    void 两套评级的分歧要按官方原文对齐后再数() {
        // 对齐依据是 Tomcat 官方 security-impact.html 原文:"Important (or High)" —— 同一档两个叫法。
        long differ = CveTable.all().stream().filter(CveTable.Cve::ratingsDiffer).count();
        long unalign = CveTable.all().stream().filter(CveTable.Cve::ratingUnalignable).count();
        assertTrue(differ > 0, "两套评级一条分歧都没有的话,回去看是不是对齐表写死了");
        // 三类必须互斥且覆盖全表
        for (CveTable.Cve c : CveTable.all()) {
            assertFalse(c.ratingsDiffer() && c.ratingUnalignable(),
                    c.id() + " 同时被判成「不同」和「无法对齐」");
        }
        assertTrue(differ + unalign < CveTable.all().size(),
                "不该全表都有分歧(" + differ + "+" + unalign + ")");
    }

    @Test
    void 官方明写同档的不许判成不同() {
        // 🔴 CVE-2025-48988:Apache important / GitHub high。
        //    官方原文 "Important (or High)" —— 这是**同一档**,判成「说法不同」就是制造噪音。
        CveTable.Cve c = byId("CVE-2025-48988");
        assertEquals("important", c.asfSeverity().toLowerCase());
        assertEquals("high", c.severity().toLowerCase());
        assertFalse(c.ratingsDiffer(), "important 与 high 是官方明写的同一档");
        assertFalse(c.ratingUnalignable());
    }

    @Test
    void 对不齐的只有moderate对medium那一对() {
        // 🔴 ASF 的 Moderate 定义的是「有显著缓解因素 / 不影响常见配置 / 需认证」,
        //    而 GitHub 的 medium 是 CVSS 分数区间 —— 官方没说这两个相等,我们也不猜。
        //    但别把判据放太松:important(=high)对 medium 是判得了的「不同」。
        for (CveTable.Cve c : CveTable.all()) {
            if (c.ratingUnalignable()) {
                assertEquals("moderate", c.asfSeverity().toLowerCase(), c.id());
                assertEquals("medium", c.severity().toLowerCase(), c.id());
            }
        }
        CveTable.Cve c = byId("CVE-2025-31650");
        assertEquals("important", c.asfSeverity().toLowerCase());
        assertEquals("medium", c.severity().toLowerCase());
        assertTrue(c.ratingsDiffer(), "important(=high)对 medium 是真分歧,不该被藏进「无法对齐」");
    }

    @Test
    void 最极端那条要能被认出来() {
        // 🔴 CVE-2025-52520:Apache 评 low,GitHub 评 high —— 差最远的一条。
        CveTable.Cve c = byId("CVE-2025-52520");
        assertEquals("low", c.asfSeverity().toLowerCase());
        assertEquals("high", c.severity().toLowerCase());
        assertTrue(c.ratingsDiffer());
    }

    @Test
    void CVSS缺失是null不是零() {
        // ☠️ 上游用 0 表示「没有这个版本的分数」。让 0 混进来,算差值时会得出一堆假分歧。
        for (CveTable.Cve c : CveTable.all()) {
            assertFalse(Double.valueOf(0.0).equals(c.cvss3()), c.id() + " 的 cvss3 是 0.0");
            assertFalse(Double.valueOf(0.0).equals(c.cvss4()), c.id() + " 的 cvss4 是 0.0");
        }
        // 14 条里只有一部分有 v3.1 分数 —— 缺失是常态,不是异常
        long withV3 = CveTable.all().stream().filter(c -> c.cvss3() != null).count();
        assertTrue(withV3 > 0 && withV3 < CveTable.all().size(),
                "有 v3.1 分数的应是「部分」,实际 " + withV3 + "/" + CveTable.all().size());
    }

    @Test
    void 文字评级与CVSS分档的分歧要认得出() {
        // CVE-2025-55754:GitHub 评 low,而 CVSS v3.1 是 9.6(critical)—— NVD 采信的是后者。
        CveTable.Cve c = byId("CVE-2025-55754");
        assertEquals("low", c.severity());
        assertEquals(9.6, c.cvss3(), 0.001);
        assertEquals("critical", c.cvss3Severity());
        assertTrue(c.severityGap(), "差 3 级都认不出来的话,用户会以为我们报错了");
        // 同一条的 v4.0 只有 2.1 —— 引哪个版本,结论差一个数量级
        assertEquals(2.1, c.cvss4(), 0.001);
        assertTrue(c.cvssVersionSplit());
    }

    @Test
    void 没有CVSS分数时不判分歧() {
        for (CveTable.Cve c : CveTable.all()) {
            if (c.cvss3() == null) {
                assertNull(c.cvss3Severity(), c.id());
                assertFalse(c.severityGap(), c.id() + " 没有 v3.1 分数却判了分歧");
            }
            if (c.cvss3() == null || c.cvss4() == null) {
                assertFalse(c.cvssVersionSplit(), c.id() + " 缺一个版本却判了版本分裂");
            }
        }
    }

    private static CveTable.Cve byId(String id) {
        return CveTable.all().stream().filter(c -> c.id().equals(id)).findFirst()
                .orElseThrow(() -> new AssertionError("表里没有 " + id));
    }
}
