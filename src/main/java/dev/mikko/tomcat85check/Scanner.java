package dev.mikko.tomcat85check;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.jar.Manifest;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * 找出实际装的 Tomcat 版本。
 *
 * <p>🔴 <b>本类和第 6 注(tomcat-check)的 Scanner 不是一回事,别直接照搬。</b>
 * 第 6 注面向 Spring Boot 内嵌形态,本注面向 <b>解压部署</b> —— 两者的差异是实测出来的
 * (2026-08-31,官方 apache-tomcat-8.5.100.zip / 8.5.99.zip / 9.0.107.zip 三包对照):
 *
 * <ol>
 *   <li><b>解压部署的 jar 文件名一个版本号都没有。</b> {@code lib/} 下是 {@code catalina.jar}、
 *       {@code tomcat-coyote.jar},不是 {@code tomcat-embed-core-9.0.107.jar}。
 *       → <b>文件名在这里只能回答「是哪个构件」,回答不了「是哪个版本」。</b>
 *       只按文件名取版本的扫描器在这类部署上会一条都认不出来 ——
 *       而「没扫到」看起来和「你很安全」一模一样。</li>
 *   <li><b>集群组件的文件名和 Maven 坐标名不同。</b> 发行包里叫 {@code catalina-tribes.jar} /
 *       {@code catalina-ha.jar},Maven 坐标却是 {@code tomcat-tribes} / {@code tomcat-catalina-ha}。
 *       只认坐标名会漏掉解压部署的集群组件。</li>
 *   <li><b>29 个 lib jar 里有 8 个没有 {@code Implementation-Version}</b>,全部是规范 API jar
 *       ({@code servlet-api} / {@code el-api} / {@code jsp-api} / {@code websocket-api} /
 *       {@code annotations-api} / {@code jaspic-api})加 {@code ecj} 与 {@code tomcat-jdbc}。
 *       它们不是 Tomcat 实现构件,取不到版本属正常
 *       → <b>不该为它们报「取不到版本」的警告</b>,否则真警告会被淹掉。</li>
 * </ol>
 *
 * <p>版本源优先级(高到低),依据同上实测:
 * <ol>
 *   <li>{@code catalina.jar!/org/apache/catalina/util/ServerInfo.properties} 的 {@code server.number}
 *       —— Tomcat 自己的 {@code version.sh} 报的就是它,是<b>官方自报口径</b>。
 *       注意它是<b>四段</b>({@code 8.5.100.0}),而 MANIFEST 是三段({@code 8.5.100});
 *       {@link TomcatVersion#compareTo} 按缺位补零对齐,两者相等。</li>
 *   <li>{@code META-INF/MANIFEST.MF} 的 {@code Implementation-Version}</li>
 *   <li>文件名里的版本号 —— <b>只有内嵌形态才有</b></li>
 * </ol>
 *
 * <p>⚠️ 已知未验证项:{@code ServerInfo.properties} 是<b>可以被覆盖的</b>(把同路径文件放进
 * {@code lib/} 即可改掉版本显示,常被用来隐藏版本)。默认发行包不带散放的覆盖文件(三包均已确认),
 * 但用户环境可能有 → 两源不一致时本类<b>两个都报出来</b>,不替用户选,见 {@link Install#versionConflict()}。
 */
public final class Scanner {

    /** 发行包文件名(解压部署)到构件标识。键是去掉 {@code .jar} 和版本后缀后的名字。 */
    private static final Map<String, String> DIST_NAMES = new LinkedHashMap<>();
    /** Maven 坐标名(内嵌 / fat jar)到构件标识。 */
    private static final Map<String, String> COORD_NAMES = new LinkedHashMap<>();

    static {
        DIST_NAMES.put("catalina", "catalina");
        DIST_NAMES.put("catalina-ha", "catalina-ha");
        DIST_NAMES.put("catalina-tribes", "catalina-tribes");
        DIST_NAMES.put("catalina-ant", "catalina-ant");
        DIST_NAMES.put("catalina-storeconfig", "catalina-storeconfig");
        DIST_NAMES.put("tomcat-coyote", "tomcat-coyote");
        DIST_NAMES.put("tomcat-util", "tomcat-util");
        DIST_NAMES.put("tomcat-util-scan", "tomcat-util-scan");
        DIST_NAMES.put("tomcat-api", "tomcat-api");
        DIST_NAMES.put("tomcat-jni", "tomcat-jni");
        DIST_NAMES.put("tomcat-websocket", "tomcat-websocket");
        DIST_NAMES.put("jasper", "jasper");
        DIST_NAMES.put("jasper-el", "jasper-el");
        DIST_NAMES.put("tomcat-dbcp", "tomcat-dbcp");

        COORD_NAMES.put("tomcat-embed-core", "tomcat-embed-core");
        COORD_NAMES.put("tomcat-embed-websocket", "tomcat-embed-websocket");
        COORD_NAMES.put("tomcat-embed-el", "tomcat-embed-el");
        COORD_NAMES.put("tomcat-embed-jasper", "tomcat-embed-jasper");
        COORD_NAMES.put("tomcat-catalina", "catalina");
        COORD_NAMES.put("tomcat-catalina-ha", "catalina-ha");
        COORD_NAMES.put("tomcat-tribes", "catalina-tribes");
    }

    /**
     * 已知<b>本来就没有</b> {@code Implementation-Version} 的 jar —— 实测自 8.5.100 发行包。
     */
    private static final Set<String> NO_VERSION_BY_DESIGN = new LinkedHashSet<>(List.of(
            "servlet-api", "el-api", "jsp-api", "websocket-api",
            "annotations-api", "jaspic-api", "tomcat-jdbc", "ecj"));

    private static final Pattern NAME_VER =
            Pattern.compile("^(.+?)-(\\d[\\w.\\-]*)\\.jar$", Pattern.CASE_INSENSITIVE);

    /** 一次扫描认出的一个 Tomcat 构件。 */
    public record Artifact(String path, String artifact, TomcatVersion version, String source) {
        /** 内嵌形态(Spring Boot 那套坐标)。 */
        public boolean embedded() {
            return artifact.startsWith("tomcat-embed-");
        }

        /** 集群组件在不在 —— 决定 CLUSTER 类条目对本次扫描是否适用。 */
        public boolean cluster() {
            return artifact.equals("catalina-tribes") || artifact.equals("catalina-ha");
        }
    }

    /**
     * 一个解压部署的安装目录。
     *
     * @param serverNumber {@code ServerInfo.properties} 的 {@code server.number},可能为 null
     * @param manifest     {@code catalina.jar} MANIFEST 的版本,可能为 null
     */
    public record Install(String root, TomcatVersion serverNumber, TomcatVersion manifest,
                          String serverInfo) {
        /** 两个版本源对不上 —— 通常意味着 ServerInfo.properties 被人覆盖过。 */
        public boolean versionConflict() {
            return serverNumber != null && manifest != null && serverNumber.compareTo(manifest) != 0;
        }

        /** 拿来做判定的版本:官方自报口径优先。 */
        public TomcatVersion effective() {
            return serverNumber != null ? serverNumber : manifest;
        }
    }

    private final List<Artifact> found = new ArrayList<>();
    private final List<Install> installs = new ArrayList<>();
    private final List<String> warnings = new ArrayList<>();

    /**
     * 有多少个文件是「读不动」的(不是 zip / 截断 / IO 失败)。
     *
     * <p>🔴 它存在的理由是退出码:留痕是给人看的,而 CI 与脚本看的是退出码 ——
     * 少了它,「我没能读它」在自动化里等于「通过」(2026-09-09 加)。
     * <p>🔴 用计数器而不是去匹配告警文案:文案改一个字,匹配式判据就安静失效了。
     */
    private int unreadable;

    /** 读不动的文件数 —— 大于 0 时退出码不许是 0。 */
    public int unreadableCount() {
        return unreadable;
    }


    public List<Artifact> artifacts() {
        return found;
    }

    public List<Install> installs() {
        return installs;
    }

    public List<String> warnings() {
        return warnings;
    }

    public void scan(Path target) throws IOException {
        if (!Files.exists(target)) {
            warnings.add("路径不存在:" + target);
            return;
        }
        if (Files.isDirectory(target)) {
            Files.walkFileTree(target, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult visitFile(Path f, BasicFileAttributes a) {
                    String n = f.getFileName().toString().toLowerCase();
                    if (n.endsWith(".jar") || n.endsWith(".war")) {
                        try {
                            scanArchive(f);
                        } catch (IOException e) {
                            unreadable++;
            warnings.add("读取失败 " + f + ":" + e.getMessage());
                        }
                    }
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFileFailed(Path f, IOException e) {
                    warnings.add("无法访问 " + f + ":" + e.getMessage());
                    return FileVisitResult.CONTINUE;
                }
            });
        } else {
            scanArchive(target);
        }
    }

    /**
     * ☠️ <b>ZipInputStream 对非 zip 内容不抛异常,只是一个条目都不给</b>(2026-09-08 实测)。
     *
     * <p>后果:损坏 / 加密 / 根本不是 zip 的 .jar 会静默走完扫描,得出「没扫到 Tomcat」——
     * 用户会把它读成「我不受影响」。<b>「读不动」和「你是安全的」必须是两句话。</b>
     *
     * <p>🔴 第 10 注(log4j-check)实测记过并在那一注加了防线,但后续各注的扫描代码是复制来的,
     * <b>防线没跟着传下来</b>。空 zip({@code PK\05\06})合法,不算坏文件。
     */
    static boolean looksLikeZip(byte[] b) {
        if (b == null || b.length < 4 || b[0] != 'P' || b[1] != 'K') return false;
        int c = b[2], d = b[3];
        return (c == 3 && d == 4) || (c == 5 && d == 6) || (c == 7 && d == 8);
    }


    /**
     * 是不是一个<b>合法的空 zip</b> —— 整个文件就是一条 22 字节的 EOCD 记录。
     *
     * <p>🔴 判据不是「魔数像 zip」:一个 PK 03 04 开头但截断的文件魔数也是对的。
     * 空 zip 是真的空,不该报错;截断的必须报。
     */
    static boolean isEmptyZip(byte[] b) {
        return b != null && b.length == 22
                && b[0] == 'P' && b[1] == 'K' && b[2] == 5 && b[3] == 6;
    }

    private void scanArchive(Path file) throws IOException {
        byte[] bytes = Files.readAllBytes(file);
        record0(file.toString(), file.getFileName().toString(), bytes);

        if (!looksLikeZip(bytes)) {
            unreadable++;
            warnings.add("这个文件读不动,不是有效的 zip/jar:" + file
                    + "(可能是截断、加密,或其实是个 HTML 错误页)"
                    + " —— 🔴 **这不等于「里面没有 Tomcat」**");
            return;
        }

        int entries = 0;
        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(bytes))) {
            ZipEntry e;
            while ((e = zis.getNextEntry()) != null) {
                entries++;
                String name = e.getName();
                if (e.isDirectory() || !name.toLowerCase().endsWith(".jar")) {
                    continue;
                }
                // 🔴 ZIP 规范要求正斜杠,但现实中存在写成反斜杠的归档
                // (PowerShell Compress-Archive 就是一例)。只认正斜杠的话,
                // 这类归档会一条都扫不出来,而「没扫到」看起来和「你很安全」一模一样。
                String base = name.substring(
                        Math.max(name.lastIndexOf('/'), name.lastIndexOf('\\')) + 1);
                if (identify(base) == null) {
                    continue;
                }
                record0(file + "!/" + name, base, zis.readAllBytes());
            }
        }

        // 🔴 第二层防线:魔数对、也没抛异常,但一个条目都没解出来。
        //    ☠️ 2026-09-08 实测:魔数校验只挡住一半 —— PK 03 04 开头但**内容截断**的文件
        //    魔数是对的、ZipInputStream 也不抛异常,只是零条目。少了这一层它照样静默通过。
        if (entries == 0 && !isEmptyZip(bytes)) {
            unreadable++;
            warnings.add("这个文件魔数像 zip,但一个条目都解不出来(多半是截断或下载不全):" + file
                    + " —— 🔴 **这不等于「里面没有 Tomcat」**");
            return;
        }
    }

    private void record0(String path, String fileName, byte[] bytes) {
        String artifact = identify(fileName);
        if (artifact == null) {
            return;
        }
        // catalina.jar 额外承担安装目录的版本权威:它是唯一带 ServerInfo.properties 的 jar
        TomcatVersion serverNumber = null;
        String serverInfo = null;
        if (artifact.equals("catalina") || artifact.equals("tomcat-embed-core")) {
            String[] si = fromServerInfo(bytes);
            if (si != null) {
                serverNumber = TomcatVersion.parse(si[0]);
                serverInfo = si[1];
            }
        }
        TomcatVersion mfVer = fromManifest(bytes);

        // 🔴 顺序即优先级,别调换:官方自报 > MANIFEST > 文件名。
        TomcatVersion v = serverNumber;
        String source = "ServerInfo.properties";
        if (v == null) {
            v = mfVer;
            source = "MANIFEST";
        }
        if (v == null) {
            v = fromFileName(fileName);
            source = "文件名";
        }
        if (v == null) {
            if (!NO_VERSION_BY_DESIGN.contains(stem(fileName))) {
                warnings.add("识别出 " + artifact + " 但取不到版本号:" + path
                        + "(🔴 这不等于「没有漏洞」,请手工确认版本)");
            }
            return;
        }
        for (Artifact a : found) {
            if (a.path().equals(path) && a.artifact().equals(artifact)) {
                return;
            }
        }
        found.add(new Artifact(path, artifact, v, source));

        if (serverNumber != null || (artifact.equals("catalina") && mfVer != null)) {
            installs.add(new Install(installRoot(path), serverNumber, mfVer, serverInfo));
        }
    }

    /** {@code <root>/lib/catalina.jar} 到 {@code <root>};认不出就原样返回。 */
    private static String installRoot(String jarPath) {
        String p = jarPath.replace('\\', '/');
        int i = p.lastIndexOf("/lib/");
        return i > 0 ? p.substring(0, i) : p;
    }

    /** 去掉 {@code .jar} 和版本后缀后的名字。 */
    private static String stem(String fileName) {
        String n = fileName.toLowerCase();
        Matcher m = NAME_VER.matcher(n);
        return m.matches() ? m.group(1) : n.replaceAll("\\.jar$", "");
    }

    private static String identify(String fileName) {
        String stem = stem(fileName);
        String a = COORD_NAMES.get(stem);
        return a != null ? a : DIST_NAMES.get(stem);
    }

    private static TomcatVersion fromFileName(String fileName) {
        Matcher m = NAME_VER.matcher(fileName.toLowerCase());
        return m.matches() ? TomcatVersion.parse(m.group(2)) : null;
    }

    /** @return {@code [server.number, server.info]},没有则 null */
    private static String[] fromServerInfo(byte[] bytes) {
        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(bytes))) {
            ZipEntry e;
            while ((e = zis.getNextEntry()) != null) {
                if (!"org/apache/catalina/util/ServerInfo.properties".equals(e.getName())) {
                    continue;
                }
                Properties p = new Properties();
                p.load(new NonClosing(zis));
                String num = p.getProperty("server.number");
                return num == null ? null : new String[]{num, p.getProperty("server.info")};
            }
        } catch (IOException | IllegalArgumentException ex) {
            return null;
        }
        return null;
    }

    /**
     * 只读 MANIFEST 主属性段。
     *
     * <p>⚠️ 第 4 注(bc-check)踩过:签名 jar 的 MANIFEST 可以上兆(每个类一个条目),
     * 整段读进来会撑破缓冲。{@link Manifest} 读主属性即可,不要遍历 entries。
     */
    private static TomcatVersion fromManifest(byte[] bytes) {
        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(bytes))) {
            ZipEntry e;
            while ((e = zis.getNextEntry()) != null) {
                if (!"META-INF/MANIFEST.MF".equalsIgnoreCase(e.getName())) {
                    continue;
                }
                Manifest mf = new Manifest(new NonClosing(zis));
                String v = mf.getMainAttributes().getValue("Implementation-Version");
                if (v == null) {
                    v = mf.getMainAttributes().getValue("Bundle-Version");
                }
                return TomcatVersion.parse(v);
            }
        } catch (IOException | IllegalArgumentException ex) {
            return null;
        }
        return null;
    }

    /** Manifest / Properties 的构造器会关掉流,而我们还要继续遍历同一个 ZipInputStream。 */
    private static final class NonClosing extends java.io.FilterInputStream {
        NonClosing(InputStream in) {
            super(in);
        }

        @Override
        public void close() {
            // 故意不关
        }
    }
}
