package dev.mikko.tomcat85check;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

/**
 * 从安装目录的配置文件里找出「某个触发条件是不是真的开着」。
 *
 * <p>本工具的真正价值在这一层:别的扫描器只能说「你的版本可能中招」,
 * 而 {@link CveTable} 里 14 条只有 2 条是默认即受影响的 —— 剩下 12 条不看配置就下结论,
 * <b>要么虚报要么漏报</b>。
 *
 * <h2>🔴 唯一一条必须守住的纪律:能确认开启,不能确认没开</h2>
 *
 * <p>{@link State#NOT_FOUND} 的意思是「<b>在我看过的文件里没找到</b>」,<b>不是「你没开」</b>。
 * 配置可以出现在本工具看不到的地方:应用自己的 {@code WEB-INF/web.xml}(在 war 包里)、
 * {@code conf/Catalina/<host>/<context>.xml}、外部 {@code CATALINA_BASE}、
 * 运行时系统属性、乃至启动脚本。
 * → 所以 {@code NOT_FOUND} <b>只降低优先级,永远不判「不适用」</b>。
 * 这和项目里「探针只能否决不能支持」是同一条纪律的镜像面。
 *
 * <h2>⚠️ 一个具体的、不许含糊过去的例子:APR</h2>
 *
 * <p>官方 8.5.100 的默认 {@code server.xml} 里 {@code AprLifecycleListener}
 * <b>是启用的</b>(不在注释块里,实测)。但它只是<b>尝试加载 native 库</b> ——
 * 库不存在时 APR 连接器根本不会启用。
 * → 所以找到它<b>只说明「有可能」</b>,{@link Finding} 会如实带上这句话,
 * <b>本工具不替用户判断 native 库在不在</b>。
 *
 * <h2>剥注释是必须的</h2>
 *
 * <p>实测默认 {@code server.xml}:{@code UpgradeProtocol} 文本搜索命中 <b>1</b> 次,
 * 剥掉 {@code <!-- -->} 后是 <b>0</b> 次 —— 它整段被注释掉了。
 * {@code conf/web.xml} 里的 {@code CGIServlet}、{@code readonly} 同理。
 * <b>不剥注释就会把「官方示范配置」数成「用户开了」。</b>
 */
public final class ConfigProbe {

    /** 一个标记的查找结果。 */
    public enum State {
        /** 在剥掉注释后的配置里找到了。 */
        CONFIRMED,
        /**
         * 找到了标记,但那个标记<b>不足以确认条件成立</b>。
         *
         * <p>典型:{@code AprLifecycleListener} 在官方默认 server.xml 里<b>本来就是启用的</b>,
         * 拿它判「你用了 APR」会把每一个默认安装都虚报一遍。
         * 强标记(如 {@code Http11AprProtocol})才给 {@link #CONFIRMED}。
         */
        POSSIBLE,
        /** 看过的文件里没找到 —— 🔴 <b>不等于没开</b>。 */
        NOT_FOUND,
        /** 没查(没给安装目录,或这个条件本工具查不了)。 */
        NOT_CHECKED
    }

    /**
     * 一条触发条件的查找结果。
     *
     * @param where 命中的文件(相对安装根),没命中则为空
     * @param note  给用户看的话;不确定的地方必须写在这里,不许省
     */
    public record Finding(String condition, State state, List<String> where, String note) {
    }

    /**
     * 触发条件 → <b>强标记</b>:找到即可确认条件成立。
     *
     * <p>🔴 判据是「这东西出现在默认配置里吗」——
     * 出现在默认配置里的一律不能当强标记,否则每个默认安装都会被虚报。
     */
    private static final Map<String, String[]> MARKERS = new LinkedHashMap<>();
    /** 触发条件 → <b>弱标记</b>:找到只说明「有可能」,给 {@link State#POSSIBLE}。 */
    private static final Map<String, String[]> WEAK = new LinkedHashMap<>();
    /** 找到之后要额外说明的话 —— 「找到了」不总等于「就是它」。 */
    private static final Map<String, String> CAVEATS = new LinkedHashMap<>();
    /** 本工具查不了的条件,以及为什么。诚实优先于覆盖率。 */
    private static final Map<String, String> UNCHECKABLE = new LinkedHashMap<>();

    static {
        // 强标记:默认配置里**没有**它们(实测 8.5.100 官方发行包,剥注释后计数为 0)
        MARKERS.put("REWRITE", new String[]{"RewriteValve"});
        MARKERS.put("APR", new String[]{"Http11AprProtocol"});
        MARKERS.put("HTTP2", new String[]{"UpgradeProtocol", "Http2Protocol"});
        MARKERS.put("CGI", new String[]{"CGIServlet"});
        MARKERS.put("TLS", new String[]{"certificateVerification"});

        // 弱标记:默认配置里**本来就有**,或存在不代表启用
        WEAK.put("APR", new String[]{"AprLifecycleListener"});
        WEAK.put("TLS", new String[]{"SSLHostConfig"});

        CAVEATS.put("APR",
                "🔴 官方默认 server.xml 里 AprLifecycleListener 本来就是启用的(实测),"
                        + "而它只是尝试加载 native 库 —— 库不存在时 APR 连接器不会启用。"
                        + "找到它只说明「有可能」,本工具不判断 native 库在不在。");
        CAVEATS.put("TLS",
                "还需要「配置了多个虚拟主机、其中部分要求客户端证书认证、且认证只在 Connector 层强制」"
                        + "这三件同时成立 —— 本工具只确认了 TLS 配置存在。");
        CAVEATS.put("HTTP2",
                "官方默认 server.xml 里 HTTP/2 的 UpgradeProtocol 整段是注释掉的(实测),"
                        + "找到它说明有人显式打开过。");

        UNCHECKABLE.put("CONFIG",
                "触发条件涉及应用自己的配置(default servlet 的 readonly、multipart 限额、"
                        + "PreResources / PostResources 挂载点),这些多半在 war 包内的 WEB-INF/web.xml 里 —— "
                        + "本工具不拆应用包,请人工确认。");
        UNCHECKABLE.put("WINDOWS_CONSOLE",
                "取决于运行方式(是不是在 Windows 控制台里跑、该控制台支不支持 ANSI 转义),"
                        + "不是配置文件能回答的问题。");
        UNCHECKABLE.put("WINDOWS_INSTALLER",
                "取决于当初是用 Windows 安装程序装的、还是解压 zip/tar.gz —— 见 installedByWindowsInstaller()。");
    }

    private final List<String> scanned = new ArrayList<>();
    private final Map<String, String> stripped = new LinkedHashMap<>();
    private Path root;

    /** 有没有真的读到配置文件。 */
    public boolean hasConfig() {
        return !stripped.isEmpty();
    }

    public List<String> scannedFiles() {
        return scanned;
    }

    /**
     * 读安装目录下的配置。{@code root} 是 {@code CATALINA_BASE}(即含 {@code conf/} 的那一级)。
     *
     * <p>扫 {@code conf/} 下全部 {@code .xml}(含 {@code conf/Catalina/<host>/} 里的 context 片段)。
     */
    public void load(Path installRoot) throws IOException {
        this.root = installRoot;
        Path conf = installRoot.resolve("conf");
        if (!Files.isDirectory(conf)) {
            return;
        }
        try (Stream<Path> s = Files.walk(conf)) {
            for (Path p : s.filter(Files::isRegularFile)
                    .filter(p -> p.getFileName().toString().toLowerCase().endsWith(".xml"))
                    .toList()) {
                String rel = installRoot.relativize(p).toString().replace('\\', '/');
                try {
                    String raw = new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
                    stripped.put(rel, stripComments(raw));
                    scanned.add(rel);
                } catch (IOException e) {
                    // 读不了就跳过,但要让它出现在 scanned 之外 —— 静默吞掉会让 NOT_FOUND 更不可信
                    scanned.add(rel + "(读取失败:" + e.getMessage() + ")");
                }
            }
        }
    }

    /**
     * 剥掉 XML 注释块。
     *
     * <p>🔴 <b>这一步不是可选的。</b> 官方 server.xml 把大量示范配置放在注释里,
     * 不剥就会把「官方给的例子」数成「用户开了」——
     * 实测 {@code UpgradeProtocol} 含注释命中 1 次、剥后 0 次。
     */
    static String stripComments(String xml) {
        StringBuilder out = new StringBuilder(xml.length());
        int i = 0;
        while (i < xml.length()) {
            int s = xml.indexOf("<!--", i);
            if (s < 0) {
                out.append(xml, i, xml.length());
                break;
            }
            out.append(xml, i, s);
            int e = xml.indexOf("-->", s + 4);
            if (e < 0) {
                // 注释没闭合 —— 后面全算注释,总比把它当配置读进来安全
                break;
            }
            i = e + 3;
        }
        return out.toString();
    }

    private List<String> find(String[] marks) {
        List<String> hits = new ArrayList<>();
        if (marks == null) {
            return hits;
        }
        for (Map.Entry<String, String> e : stripped.entrySet()) {
            for (String m : marks) {
                if (e.getValue().contains(m)) {
                    hits.add(e.getKey() + " → " + m);
                    break;
                }
            }
        }
        return hits;
    }

    /** 查一个触发条件。 */
    public Finding check(String condition) {
        if (UNCHECKABLE.containsKey(condition)) {
            return new Finding(condition, State.NOT_CHECKED, List.of(), UNCHECKABLE.get(condition));
        }
        String[] marks = MARKERS.get(condition);
        if (marks == null) {
            return new Finding(condition, State.NOT_CHECKED, List.of(),
                    "本工具没有这个条件的查法。");
        }
        if (!hasConfig()) {
            return new Finding(condition, State.NOT_CHECKED, List.of(),
                    "没有读到任何配置文件(没给安装目录,或目录下没有 conf/)。");
        }
        List<String> hits = find(marks);
        String caveat = CAVEATS.get(condition);
        if (hits.isEmpty()) {
            // 强标记没中 —— 再看弱标记。中了只给 POSSIBLE,不给 CONFIRMED。
            List<String> weak = find(WEAK.get(condition));
            if (!weak.isEmpty()) {
                return new Finding(condition, State.POSSIBLE, weak,
                        (caveat == null ? "" : caveat + " ")
                                + "找到的是弱标记(" + String.join("; ", weak)
                                + "),它不足以确认条件成立 —— 请人工确认。");
            }
        }
        if (hits.isEmpty()) {
            // 🔴 措辞必须是「没找到」,不能是「没开」。
            return new Finding(condition, State.NOT_FOUND, List.of(),
                    "在扫过的 " + stripped.size() + " 个配置文件里没找到 —— "
                            + "🔴 这不等于没开:应用自己的 WEB-INF/web.xml、外部 CATALINA_BASE、"
                            + "启动参数都可能开启它,本工具看不到。");
        }
        return new Finding(condition, State.CONFIRMED, hits,
                caveat == null ? "在配置里找到了(已剥除注释块)。" : caveat);
    }

    /**
     * 这个安装是不是用 Windows 安装程序装的 —— 决定 {@code CVE-2025-49124} 适不适用。
     *
     * <p>判据是安装程序留下的痕迹({@code uninstall.exe} / {@code tomcat8.exe} 等)。
     * 找不到就是 {@link State#NOT_FOUND},同样<b>不等于「肯定是解压装的」</b>。
     */
    public Finding installedByWindowsInstaller() {
        if (root == null) {
            return new Finding("WINDOWS_INSTALLER", State.NOT_CHECKED, List.of(), "没给安装目录。");
        }
        List<String> hits = new ArrayList<>();
        for (String f : List.of("uninstall.exe", "bin/tomcat8.exe", "bin/tomcat8w.exe")) {
            if (Files.exists(root.resolve(f))) {
                hits.add(f);
            }
        }
        if (hits.isEmpty()) {
            return new Finding("WINDOWS_INSTALLER", State.NOT_FOUND, List.of(),
                    "没找到 Windows 安装程序的痕迹(uninstall.exe / tomcat8.exe)—— "
                            + "多半是解压 zip/tar.gz 部署,那样 CVE-2025-49124 不适用。"
                            + "🔴 但这是间接判据,请自行确认。");
        }
        return new Finding("WINDOWS_INSTALLER", State.CONFIRMED, hits,
                "找到了 Windows 安装程序的痕迹 → CVE-2025-49124 适用。");
    }
}
