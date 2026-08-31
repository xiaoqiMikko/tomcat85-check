package dev.mikko.tomcat85check;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 判定的自检 —— <b>两个方向都要验</b>:该报的报了,不该报的没报。
 *
 * <p>基线来自 2026-09-01 对官方 8.5.100 发行包的实测:
 * <b>裸装(默认配置)= 默认即受影响 2 条、配置已确认 0 条</b>;
 * 打开 HTTP/2 + RewriteValve + CGIServlet 后 = <b>配置已确认 5 条</b>。
 */
class ApplicabilityTest {

    @TempDir
    Path tmp;

    private static final TomcatVersion V = TomcatVersion.parse("8.5.100");

    private ConfigProbe probeWith(String serverXml) throws IOException {
        Path p = tmp.resolve("conf/server.xml");
        Files.createDirectories(p.getParent());
        Files.write(p, serverXml.getBytes(StandardCharsets.UTF_8));
        ConfigProbe cp = new ConfigProbe();
        cp.load(tmp);
        return cp;
    }

    private static long count(List<Applicability.Result> rs, Applicability.Verdict v) {
        return rs.stream().filter(r -> r.verdict() == v).count();
    }

    // ---------------------------------------------------------------- 阴性:默认配置

    @Test
    void 裸装只有两条默认即受影响() throws IOException {
        // 官方默认 server.xml 的等价物:AprLifecycleListener 开着(弱标记),其余都没有。
        ConfigProbe p = probeWith(
                "<Server>\n<Listener className=\"org.apache.catalina.core.AprLifecycleListener\"/>\n"
                        + "<!-- <UpgradeProtocol className=\"...Http2Protocol\"/> -->\n</Server>");
        List<Applicability.Result> rs = Applicability.judge(V, p);

        assertEquals(2, count(rs, Applicability.Verdict.AFFECTED_DEFAULT));
        // 🔴 关键:AprLifecycleListener 默认就开着,不能因此判「配置已确认」——
        //    否则每一个默认安装都会被虚报一条。
        assertEquals(0, count(rs, Applicability.Verdict.AFFECTED_CONFIG_CONFIRMED),
                "裸装不该确认任何配置类条目");
    }

    @Test
    void 注释掉的HTTP2不算开() throws IOException {
        ConfigProbe p = probeWith("<Server>\n<!-- <UpgradeProtocol className=\"...Http2Protocol\"/> -->\n</Server>");
        for (Applicability.Result r : Applicability.judge(V, p)) {
            if ("HTTP2".equals(r.cve().condition())) {
                assertEquals(Applicability.Verdict.NEEDS_REVIEW, r.verdict(), r.cve().id());
            }
        }
    }

    // ---------------------------------------------------------------- 阳性:开了配置

    @Test
    void 开了HTTP2和Rewrite要确认出来() throws IOException {
        ConfigProbe p = probeWith(
                "<Server>\n<UpgradeProtocol className=\"org.apache.coyote.http2.Http2Protocol\"/>\n"
                        + "<Valve className=\"org.apache.catalina.valves.rewrite.RewriteValve\"/>\n</Server>");
        List<Applicability.Result> rs = Applicability.judge(V, p);

        // HTTP2 两条(31650 / 53506)+ REWRITE 两条(31651 / 55752)
        assertEquals(4, count(rs, Applicability.Verdict.AFFECTED_CONFIG_CONFIRMED));
        for (Applicability.Result r : rs) {
            if (List.of("HTTP2", "REWRITE").contains(r.cve().condition())) {
                assertEquals(Applicability.Verdict.AFFECTED_CONFIG_CONFIRMED, r.verdict(), r.cve().id());
                assertTrue(r.actionable(), r.cve().id() + " 应当是可行动的");
            }
        }
    }

    // ---------------------------------------------------------------- 档位纪律

    @Test
    void 没给配置时一律落进需人工确认() {
        List<Applicability.Result> rs = Applicability.judge(V, null);
        assertEquals(2, count(rs, Applicability.Verdict.AFFECTED_DEFAULT));
        assertEquals(0, count(rs, Applicability.Verdict.AFFECTED_CONFIG_CONFIRMED));
        // 🔴 没查过 ≠ 不受影响。除了默认那 2 条,其余 12 条全部要人来看。
        assertEquals(CveTable.all().size() - 2, count(rs, Applicability.Verdict.NEEDS_REVIEW));
        assertEquals(0, count(rs, Applicability.Verdict.NOT_APPLICABLE),
                "没给安装目录时不该有任何「不适用」——那是替用户猜");
    }

    @Test
    void 解压部署时Windows安装那条判不适用() throws IOException {
        ConfigProbe p = probeWith("<Server/>");
        Applicability.Result r = Applicability.judge(V, p).stream()
                .filter(x -> x.cve().id().equals("CVE-2025-49124")).findFirst().orElseThrow();
        assertEquals(Applicability.Verdict.NOT_APPLICABLE, r.verdict());
        assertFalse(r.actionable());
    }

    @Test
    void 版本不在区间时不判为受影响() {
        List<Applicability.Result> rs = Applicability.judge(TomcatVersion.parse("9.0.107"), null);
        assertEquals(CveTable.all().size(),
                count(rs, Applicability.Verdict.VERSION_NOT_AFFECTED));
    }

    @Test
    void 取不到版本时要说清这不等于没漏洞() {
        List<Applicability.Result> rs = Applicability.judge(null, null);
        assertTrue(rs.stream().allMatch(r -> r.verdict() == Applicability.Verdict.VERSION_NOT_AFFECTED));
        assertTrue(rs.get(0).reason().contains("不等于"), rs.get(0).reason());
    }

    @Test
    void 每条结果都要有理由() {
        for (Applicability.Result r : Applicability.judge(V, null)) {
            assertFalse(r.reason() == null || r.reason().isBlank(), r.cve().id() + " 没给理由");
        }
    }

    @Test
    void 确认档不许吞掉caveat() throws IOException {
        // 🔴 曾经吞过:CONFIRMED 分支只拼 conditionNote,把 ConfigProbe 的 caveat 丢了,
        //    于是「找到了也不等于就是它」这句话到不了用户眼前。
        ConfigProbe p = probeWith(
                "<Server>\n<UpgradeProtocol className=\"org.apache.coyote.http2.Http2Protocol\"/>\n</Server>");
        Applicability.Result r = Applicability.judge(V, p).stream()
                .filter(x -> x.cve().id().equals("CVE-2025-53506")).findFirst().orElseThrow();
        assertEquals(Applicability.Verdict.AFFECTED_CONFIG_CONFIRMED, r.verdict());
        assertTrue(r.reason().contains("注释掉的"),
                "ConfigProbe 的 caveat 没进 reason:" + r.reason());
    }

    @Test
    void 小结里要点出NVD查不到的条数() {
        String s = Applicability.summarize(Applicability.judge(V, null));
        assertTrue(s.contains("NVD"), s);
        long gap = CveTable.all().stream().filter(c -> !c.nvdHas85()).count();
        assertTrue(s.contains(String.valueOf(gap)), "小结里应出现 " + gap + ":" + s);
    }
}
