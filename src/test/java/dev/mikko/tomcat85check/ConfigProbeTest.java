package dev.mikko.tomcat85check;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 配置探测的自检。
 *
 * <p>形状来自 2026-09-01 对官方 8.5.100 发行包的实测:
 * 默认 {@code server.xml} 里 {@code AprLifecycleListener} 剥注释后命中 1 次(**默认就开着**),
 * {@code UpgradeProtocol} 剥注释后 0 次(**整段被注释掉**),{@code RewriteValve} 0 次。
 */
class ConfigProbeTest {

    @TempDir
    Path tmp;

    private void conf(String name, String xml) throws IOException {
        Path p = tmp.resolve("conf").resolve(name);
        Files.createDirectories(p.getParent());
        Files.write(p, xml.getBytes(StandardCharsets.UTF_8));
    }

    private ConfigProbe load() throws IOException {
        ConfigProbe p = new ConfigProbe();
        p.load(tmp);
        return p;
    }

    // ---------------------------------------------------------------- 剥注释

    @Test
    void 剥注释() {
        assertEquals("ab", ConfigProbe.stripComments("a<!-- x -->b"));
        assertEquals("ab", ConfigProbe.stripComments("a<!-- <Valve/> \n 多行 -->b"));
        assertEquals("ac", ConfigProbe.stripComments("a<!--1--><!--2-->c"));
        // 注释没闭合:后面全算注释 —— 宁可漏报,不许把注释当配置读进来
        assertEquals("a", ConfigProbe.stripComments("a<!-- 没闭合 <Valve/>"));
        assertEquals("no comment", ConfigProbe.stripComments("no comment"));
    }

    @Test
    void 注释里的标记不算数() throws IOException {
        // 🔴 官方 server.xml 把大量示范配置放在注释里。不剥注释就会把「官方给的例子」数成「用户开了」。
        conf("server.xml", "<Server>\n<!-- <Valve className=\"...rewrite.RewriteValve\"/> -->\n</Server>");
        ConfigProbe p = load();
        assertEquals(ConfigProbe.State.NOT_FOUND, p.check("REWRITE").state());
    }

    @Test
    void 真实配置要认出来并指出在哪个文件() throws IOException {
        conf("server.xml", "<Server>\n<Valve className=\"org.apache.catalina.valves.rewrite.RewriteValve\"/>\n</Server>");
        ConfigProbe.Finding f = load().check("REWRITE");
        assertEquals(ConfigProbe.State.CONFIRMED, f.state());
        assertEquals(1, f.where().size());
        assertTrue(f.where().get(0).contains("server.xml"), f.where().toString());
    }

    @Test
    void 递归扫conf下的context片段() throws IOException {
        // conf/Catalina/<host>/<app>.xml 也是配置,漏了会漏报
        conf("Catalina/localhost/app.xml",
                "<Context><Valve className=\"org.apache.catalina.valves.rewrite.RewriteValve\"/></Context>");
        ConfigProbe.Finding f = load().check("REWRITE");
        assertEquals(ConfigProbe.State.CONFIRMED, f.state());
        assertTrue(f.where().get(0).contains("Catalina/localhost/app.xml"), f.where().toString());
    }

    // ---------------------------------------------------------------- 强弱标记

    @Test
    void 弱标记只给POSSIBLE不给CONFIRMED() throws IOException {
        // 🔴 AprLifecycleListener 在官方默认 server.xml 里本来就开着(实测)。
        //    拿它判「你用了 APR」会把**每一个默认安装**都虚报一遍。
        conf("server.xml", "<Server>\n<Listener className=\"org.apache.catalina.core.AprLifecycleListener\"/>\n</Server>");
        ConfigProbe.Finding f = load().check("APR");
        assertEquals(ConfigProbe.State.POSSIBLE, f.state());
        assertTrue(f.note().contains("native"), "必须说清为什么它不足以确认:" + f.note());
    }

    @Test
    void 强标记才给CONFIRMED() throws IOException {
        conf("server.xml", "<Server>\n<Connector protocol=\"org.apache.coyote.http11.Http11AprProtocol\"/>\n</Server>");
        assertEquals(ConfigProbe.State.CONFIRMED, load().check("APR").state());
    }

    // ---------------------------------------------------------------- 措辞纪律

    @Test
    void 没找到的措辞必须是没找到而不是没开() throws IOException {
        // 🔴 能确认开启,不能确认没开 —— 配置可能在 war 包内的 web.xml、外部 CATALINA_BASE、启动参数里。
        conf("server.xml", "<Server/>");
        ConfigProbe.Finding f = load().check("REWRITE");
        assertEquals(ConfigProbe.State.NOT_FOUND, f.state());
        assertTrue(f.note().contains("这不等于没开"), "措辞跑偏了:" + f.note());
    }

    @Test
    void 没给配置目录时是NOT_CHECKED不是NOT_FOUND() throws IOException {
        ConfigProbe p = new ConfigProbe();
        p.load(tmp);   // tmp 下没有 conf/
        assertFalse(p.hasConfig());
        assertEquals(ConfigProbe.State.NOT_CHECKED, p.check("REWRITE").state());
    }

    @Test
    void 查不了的条件要说清为什么() throws IOException {
        conf("server.xml", "<Server/>");
        ConfigProbe p = load();
        for (String cond : new String[]{"CONFIG", "WINDOWS_CONSOLE"}) {
            ConfigProbe.Finding f = p.check(cond);
            assertEquals(ConfigProbe.State.NOT_CHECKED, f.state(), cond);
            assertFalse(f.note().isBlank(), cond + " 没说为什么查不了");
        }
    }

    // ---------------------------------------------------------------- Windows 安装程序

    @Test
    void Windows安装痕迹能认出来() throws IOException {
        conf("server.xml", "<Server/>");
        Files.write(tmp.resolve("uninstall.exe"), new byte[]{0});
        assertEquals(ConfigProbe.State.CONFIRMED, load().installedByWindowsInstaller().state());
    }

    @Test
    void 解压部署没有安装痕迹() throws IOException {
        conf("server.xml", "<Server/>");
        ConfigProbe.Finding f = load().installedByWindowsInstaller();
        assertEquals(ConfigProbe.State.NOT_FOUND, f.state());
        assertTrue(f.note().contains("间接判据"), "间接判据必须说明白:" + f.note());
    }
}
