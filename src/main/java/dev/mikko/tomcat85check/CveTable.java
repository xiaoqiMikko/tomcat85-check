package dev.mikko.tomcat85check;

import java.util.List;

/**
 * Tomcat 8.5 的 CVE 判定表 —— <b>本文件由 {@code tools/gen_table.py} 生成,不要手改。</b>
 *
 * <p>生成时间:2026-09-01 01:40:06。数据来自三个一手源(见 {@code tools/fetch_sources.py}):
 * Apache 作为 CNA 的原始记录(CVE.org)、NVD、GitHub advisory。
 *
 * <p>表里共 17 条 CVE-2025-* 中筛出的 <b>10 + 4</b> 条 ——
 * 全部是 Apache 逐字写了
 * <i>"The following versions were EOL at the time the CVE was created but are known to be
 * affected: 8.5.x though 8.5.100"</i> 的条目。其中:
 * <ul>
 *   <li><b>10 条 {@code nvdHas85 == false}</b> —— NVD 的 cpe 配置里查不到 8.5,
 *       读 NVD 的工具和文章看不见它们;</li>
 *   <li>4 条 NVD 也有 8.5。</li>
 * </ul>
 *
 * <p>🔴 <b>8.5 侧一条修复版都没有</b>({@code first_patched_version} 全为 null,由 ASSERT 4 守着)。
 * 所以本表回答的是「你中了什么」,<b>不是「升到哪个 8.5 版本」—— 那个版本不存在。</b>
 *
 * <p>🔴 <b>{@code condition} 不是装饰。</b> 表里绝大多数条目<b>只在特定配置下才成立</b>,
 * 默认配置即受影响的是少数。把它们一律报成「你中了」就是让用户做错事。
 */
public final class CveTable {

    private CveTable() {
    }

    /**
     * 一条 CVE。
     *
     * @param lo85       Apache 声明的 8.5 区间下界(闭)
     * @param hi85       上界(闭 —— 由 ASSERT 3 保证是 {@code lessThanOrEqual})
     * @param nvdHas85   NVD 的 cpe 配置里有没有 8.5 条目
     * @param packages   GitHub advisory 里 8.5 那侧的受影响 Maven 坐标(可能为空)
     * @param condition  触发条件分类;{@code DEFAULT} 表示默认配置即受影响
     * @param conditionNote 条件说明,逐字对照官方描述原文,未作外推
     * @param textRange85 仅当 CNA 结构化字段与描述正文的 8.5 区间对不上时非 null,值是正文那个
     */
    public record Cve(String id, String ghsa, String severity,
                      String lo85, String hi85, boolean nvdHas85,
                      String nvdStatus, String nvdPublished,
                      List<String> packages,
                      String condition, String conditionNote,
                      String textRange85) {

        /**
         * Apache 自己的两处写法对不上 —— {@code affected} 结构化字段一个区间,
         * 描述正文里另一个区间。
         *
         * <p>实测 {@code CVE-2025-49124}:结构化写 {@code 8.5.44..8.5.100},
         * 正文写 {@code 8.5.0 through 8.5.100}。本表取<b>结构化字段</b>(区间更窄 = 少报),
         * 但把正文那个一并带出来 —— <b>不许默默吞掉官方自相矛盾这件事</b>,
         * 落在这段差里的用户有权知道「官方两处说法不同」。
         */
        public boolean upstreamSelfConflict() {
            return textRange85 != null;
        }

        /** 默认配置即受影响 —— 不需要用户开启任何东西。 */
        public boolean defaultAffected() {
            return "DEFAULT".equals(condition);
        }

        /**
         * 这个 8.5.x 版本在不在本条的影响区间内。
         *
         * <p>🔴 <b>只能这样判。</b> GitHub advisory 在 8.5 那侧的
         * {@code first_patched_version} <b>全是 null</b>,靠「低于修复版就算中招」这套判据
         * 会把每一条都判成「无法判定」或「全中」。而 GitHub 的
         * {@code vulnerable_version_range} 写的是 {@code ">= 8.5.0, <= 8.5.100"} ——
         * <b>闭区间上界</b>,不是修复版。(注:GitHub API 里<b>没有</b> {@code last_affected}
         * 字段,那是 OSV 的字段名,别照 OSV 的经验写判据。)
         */
        public boolean affects(TomcatVersion v) {
            return v != null && v.inRange(lo85, hi85);
        }
    }

    private static final List<Cve> ALL = List.of(
            new Cve("CVE-2025-24813", "GHSA-83qj-6fr2-vhqg", "critical",
                    "8.5.0", "8.5.100", true,
                    "Analyzed", "2025-03-10",
                    List.of("org.apache.tomcat.embed:tomcat-embed-core", "org.apache.tomcat:tomcat-catalina"),
                    "CONFIG", "仅当 default servlet 开启了 writes(原文:disabled by default)且支持 partial PUT(原文:enabled by default)", null),
            new Cve("CVE-2025-31650", "GHSA-3p2h-wqq4-wf4h", "medium",
                    "8.5.90", "8.5.100", false,
                    "Modified", "2025-04-28",
                    List.of("org.apache.tomcat.embed:tomcat-embed-core", "org.apache.tomcat:tomcat-coyote"),
                    "HTTP2", "仅当启用 HTTP/2(畸形 PRIORITY_UPDATE 帧)", null),
            new Cve("CVE-2025-31651", "GHSA-ff77-26x5-69cr", "low",
                    "8.5.0", "8.5.100", false,
                    "Modified", "2025-04-28",
                    List.of("org.apache.tomcat.embed:tomcat-embed-core", "org.apache.tomcat:tomcat-catalina"),
                    "REWRITE", "仅当配置了 Rewrite Valve,且属于原文所说的「a subset of unlikely rewrite rule configurations」", null),
            new Cve("CVE-2025-46701", "GHSA-h2fw-rfh5-95r3", "low",
                    "8.5.0", "8.5.100", false,
                    "Modified", "2025-05-29",
                    List.of("org.apache.tomcat.embed:tomcat-embed-core", "org.apache.tomcat:tomcat-catalina"),
                    "CGI", "仅当 URI 映射到 CGI servlet", null),
            new Cve("CVE-2025-48988", "GHSA-h3gc-qfqq-6h8f", "high",
                    "8.5.0", "8.5.100", false,
                    "Modified", "2025-06-16",
                    List.of("org.apache.tomcat.embed:tomcat-embed-core", "org.apache.tomcat:tomcat-catalina"),
                    "DEFAULT", "默认配置即受影响(原文未给任何前置条件);触发面为 multipart 上传", null),
            new Cve("CVE-2025-49124", "GHSA-42wg-hm62-jcwg", "medium",
                    "8.5.44", "8.5.100", false,
                    "Modified", "2025-06-16",
                    List.of(),
                    "WINDOWS_INSTALLER", "🔴 仅当用 Windows 安装程序安装(漏洞在安装过程调用 icacls.exe)——解压 zip/tar.gz 部署的不适用", "8.5.0..8.5.100"),
            new Cve("CVE-2025-49125", "GHSA-wc4r-xq3c-5cf3", "medium",
                    "8.5.0", "8.5.100", false,
                    "Modified", "2025-06-16",
                    List.of("org.apache.tomcat.embed:tomcat-embed-core", "org.apache.tomcat:tomcat-catalina"),
                    "CONFIG", "仅当配置了 PreResources / PostResources 且挂载点不在应用根", null),
            new Cve("CVE-2025-52434", "GHSA-4j3c-42xv-3f84", "medium",
                    "8.5.0", "8.5.100", false,
                    "Modified", "2025-07-10",
                    List.of("org.apache.tomcat.embed:tomcat-embed-core", "org.apache.tomcat:tomcat-coyote"),
                    "APR", "仅当使用 APR/Native 连接器", null),
            new Cve("CVE-2025-52520", "GHSA-wr62-c79q-cv37", "high",
                    "8.5.0", "8.5.100", false,
                    "Modified", "2025-07-10",
                    List.of("org.apache.tomcat.embed:tomcat-embed-core", "org.apache.tomcat:tomcat-catalina"),
                    "CONFIG", "仅当属于原文所说的「some unlikely configurations of multipart upload」", null),
            new Cve("CVE-2025-53506", "GHSA-25xr-qj8w-c4vf", "high",
                    "8.5.0", "8.5.100", false,
                    "Modified", "2025-07-10",
                    List.of("org.apache.tomcat.embed:tomcat-embed-core", "org.apache.tomcat:tomcat-coyote"),
                    "HTTP2", "仅当启用 HTTP/2(客户端不确认初始 settings 帧)", null),
            new Cve("CVE-2025-55752", "GHSA-wmwf-9ccg-fff5", "high",
                    "8.5.6", "8.5.100", true,
                    "Modified", "2025-10-27",
                    List.of("org.apache.tomcat.embed:tomcat-embed-core", "org.apache.tomcat:tomcat", "org.apache.tomcat:tomcat-catalina"),
                    "REWRITE", "仅当 rewrite 规则会把 query 参数改写进 URI;若同时启用 PUT 则可导致 RCE", null),
            new Cve("CVE-2025-55754", "GHSA-vfww-5hm6-hx2j", "low",
                    "8.5.60", "8.5.100", true,
                    "Modified", "2025-10-27",
                    List.of("org.apache.tomcat.embed:tomcat-embed-core", "org.apache.tomcat:tomcat", "org.apache.tomcat:tomcat-catalina"),
                    "WINDOWS_CONSOLE", "仅当在 Windows 控制台中运行且该控制台支持 ANSI 转义序列", null),
            new Cve("CVE-2025-61795", "GHSA-hgrr-935x-pq79", "low",
                    "8.5.0", "8.5.100", true,
                    "Modified", "2025-10-27",
                    List.of("org.apache.tomcat.embed:tomcat-embed-core", "org.apache.tomcat:tomcat", "org.apache.tomcat:tomcat-catalina"),
                    "DEFAULT", "默认配置即受影响(原文未给任何前置条件);触发面为 multipart 上传", null),
            new Cve("CVE-2025-66614", "GHSA-fpj8-gq4v-p354", "medium",
                    "8.5.0", "8.5.100", false,
                    "Modified", "2026-02-17",
                    List.of(),
                    "TLS", "仅当配置了多个虚拟主机、其中部分要求客户端证书认证,且认证只在 Connector 层强制(原文:not if enforced at the web application)", null)
    );

    public static List<Cve> all() {
        return ALL;
    }

    /** 命中这个版本的全部条目。 */
    public static List<Cve> matching(TomcatVersion v) {
        return ALL.stream().filter(c -> c.affects(v)).toList();
    }

    /** 命中且 <b>NVD 查不到</b> 的条目 —— 本工具存在的理由。 */
    public static List<Cve> invisibleInNvd(TomcatVersion v) {
        return ALL.stream().filter(c -> c.affects(v) && !c.nvdHas85()).toList();
    }
}
