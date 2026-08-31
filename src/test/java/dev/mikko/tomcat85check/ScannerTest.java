package dev.mikko.tomcat85check;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 🔴 这些用例的形状全部来自 2026-08-31 对官方 apache-tomcat-8.5.100.zip 的实测,
 * 不是凭印象编的。真包冒烟测试见 {@link #realDistributionSmokeTest()}。
 */
class ScannerTest {

    @TempDir
    Path tmp;

    /** 造一个 jar:entries 是「路径 -> 内容」。 */
    private static byte[] jar(Map<String, String> entries) throws IOException {
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        try (ZipOutputStream zo = new ZipOutputStream(bo)) {
            for (Map.Entry<String, String> e : entries.entrySet()) {
                zo.putNextEntry(new ZipEntry(e.getKey()));
                zo.write(e.getValue().getBytes(StandardCharsets.UTF_8));
                zo.closeEntry();
            }
        }
        return bo.toByteArray();
    }

    private static Map<String, String> manifest(String implVersion) {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("META-INF/MANIFEST.MF",
                "Manifest-Version: 1.0\r\n"
                        + "Implementation-Title: Apache Tomcat\r\n"
                        + "Implementation-Version: " + implVersion + "\r\n\r\n");
        return m;
    }

    private static String serverInfo(String number) {
        return "server.info=Apache Tomcat/" + number.replaceAll("\\.0$", "") + "\n"
                + "server.number=" + number + "\n"
                + "server.built=Mar 19 2024 13:54:42 UTC\n";
    }

    private Path write(String rel, byte[] bytes) throws IOException {
        Path p = tmp.resolve(rel);
        Files.createDirectories(p.getParent());
        Files.write(p, bytes);
        return p;
    }

    // ---------------------------------------------------------------- 核心形态

    @Test
    void 解压部署的catalina没有版本文件名也能认出版本() throws IOException {
        // 🔴 本注存在的技术前提:lib/catalina.jar 文件名里一个数字都没有。
        Map<String, String> e = manifest("8.5.100");
        e.put("org/apache/catalina/util/ServerInfo.properties", serverInfo("8.5.100.0"));
        write("tomcat/lib/catalina.jar", jar(e));

        Scanner s = new Scanner();
        s.scan(tmp);

        assertEquals(1, s.artifacts().size(), "应认出 catalina");
        Scanner.Artifact a = s.artifacts().get(0);
        assertEquals("catalina", a.artifact());
        assertEquals("ServerInfo.properties", a.source(), "官方自报口径必须优先");
        assertEquals(0, TomcatVersion.parse("8.5.100").compareTo(a.version()),
                "四段 8.5.100.0 应与三段 8.5.100 相等");
    }

    @Test
    void 集群组件用发行包文件名也要认出来() throws IOException {
        // 发行包叫 catalina-tribes.jar,Maven 坐标却叫 tomcat-tribes —— 只认坐标名会漏。
        write("tomcat/lib/catalina-tribes.jar", jar(manifest("8.5.100")));
        write("tomcat/lib/catalina-ha.jar", jar(manifest("8.5.100")));

        Scanner s = new Scanner();
        s.scan(tmp);

        assertEquals(2, s.artifacts().size());
        assertTrue(s.artifacts().stream().allMatch(Scanner.Artifact::cluster),
                "两个都该被判为集群组件");
    }

    @Test
    void 规范API的jar没有版本属性不该报警告() throws IOException {
        // servlet-api.jar 实测没有 Implementation-Version —— 那是设计如此,不是异常。
        Map<String, String> e = new LinkedHashMap<>();
        e.put("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\r\nAnt-Version: Apache Ant 1.10.14\r\n\r\n");
        write("tomcat/lib/servlet-api.jar", jar(e));

        Scanner s = new Scanner();
        s.scan(tmp);

        assertTrue(s.artifacts().isEmpty());
        assertTrue(s.warnings().isEmpty(),
                "规范 API jar 取不到版本是正常的,报警告会把真警告淹掉:" + s.warnings());
    }

    @Test
    void 真的取不到版本的实现构件必须报警告() throws IOException {
        // 反向对照:同样没有版本,但它是实现构件 -> 必须出声。
        Map<String, String> e = new LinkedHashMap<>();
        e.put("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\r\n\r\n");
        write("tomcat/lib/tomcat-coyote.jar", jar(e));

        Scanner s = new Scanner();
        s.scan(tmp);

        assertTrue(s.artifacts().isEmpty());
        assertEquals(1, s.warnings().size(), "实现构件取不到版本必须报警告");
        assertTrue(s.warnings().get(0).contains("不等于"), "警告要说清「没扫到 != 安全」");
    }

    // ---------------------------------------------------------------- 版本源冲突

    @Test
    void 两个版本源不一致时两个都报出来不替用户选() throws IOException {
        // ServerInfo.properties 可被覆盖以隐藏版本 —— 这时它和 MANIFEST 会对不上。
        Map<String, String> e = manifest("8.5.100");
        e.put("org/apache/catalina/util/ServerInfo.properties", serverInfo("9.9.9.0"));
        write("tomcat/lib/catalina.jar", jar(e));

        Scanner s = new Scanner();
        s.scan(tmp);

        assertEquals(1, s.installs().size());
        Scanner.Install in = s.installs().get(0);
        assertTrue(in.versionConflict(), "两源不一致必须能被识别出来");
        assertEquals("8.5.100", in.manifest().toString());
        assertNotNull(in.serverNumber());
        assertTrue(in.root().endsWith("/tomcat"), "安装根目录应剥掉 /lib/xxx.jar:" + in.root());
    }

    @Test
    void 只有MANIFEST时也算一个安装并且不算冲突() throws IOException {
        write("tomcat/lib/catalina.jar", jar(manifest("8.5.100")));

        Scanner s = new Scanner();
        s.scan(tmp);

        assertEquals(1, s.installs().size());
        Scanner.Install in = s.installs().get(0);
        assertFalse(in.versionConflict(), "缺一个源不该被当成冲突");
        assertNull(in.serverNumber());
        assertEquals("8.5.100", in.effective().toString());
    }

    // ---------------------------------------------------------------- 内嵌形态

    @Test
    void 内嵌形态仍然按文件名兜底() throws IOException {
        // fat jar 里的 tomcat-embed-core-9.0.107.jar 连 MANIFEST 都没有时,文件名是最后一道。
        write("app/BOOT-INF/lib/tomcat-embed-core-9.0.107.jar", jar(new LinkedHashMap<>()));

        Scanner s = new Scanner();
        s.scan(tmp);

        assertEquals(1, s.artifacts().size());
        Scanner.Artifact a = s.artifacts().get(0);
        assertEquals("文件名", a.source());
        assertEquals("9.0.107", a.version().toString());
        assertTrue(a.embedded());
    }

    @Test
    void fatjar里的内嵌构件要能扫出来() throws IOException {
        Map<String, String> outer = new LinkedHashMap<>();
        outer.put("BOOT-INF/classes/x.txt", "x");
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        try (ZipOutputStream zo = new ZipOutputStream(bo)) {
            zo.putNextEntry(new ZipEntry("BOOT-INF/lib/tomcat-embed-core-9.0.107.jar"));
            zo.write(jar(manifest("9.0.107")));
            zo.closeEntry();
        }
        write("app.jar", bo.toByteArray());

        Scanner s = new Scanner();
        s.scan(tmp);

        assertEquals(1, s.artifacts().size());
        assertEquals("MANIFEST", s.artifacts().get(0).source());
        assertTrue(s.artifacts().get(0).path().contains("!/"), "内嵌路径要带 !/ 便于定位");
    }

    // ---------------------------------------------------------------- 真包冒烟

    /**
     * 拿真发行包跑一遍。合成 jar 只能验我以为的结构,验不了真实结构。
     *
     * <p>包有 11MB,不进仓库 —— 传 {@code -Dtomcat85.dist=<解压后的目录>} 才跑,
     * 没传就跳过(而不是失败),否则 CI 上会红成一片。
     */
    @Test
    void realDistributionSmokeTest() throws IOException {
        String dist = System.getProperty("tomcat85.dist");
        if (dist == null || dist.isEmpty()) {
            return;
        }
        Path root = Paths.get(dist);
        Scanner s = new Scanner();
        s.scan(root);

        assertFalse(s.artifacts().isEmpty(), "真包里必须扫出构件");
        assertEquals(1, s.installs().size(), "一个安装目录应只报一个 Install");
        Scanner.Install in = s.installs().get(0);
        assertFalse(in.versionConflict(), "官方发行包的两个版本源必须一致");
        assertNotNull(in.effective());
        assertTrue(s.warnings().isEmpty(), "官方发行包不该产生任何警告:" + s.warnings());
    }
}
