package egovframework.com.msa.manager;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.yaml.snakeyaml.Yaml;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

@Service
public class OpsInsightService {
    private static final List<String> MAPPING_FILE_CANDIDATES = Arrays.asList(
            AppPaths.resolvePath("msa-mappings.yml").toString());
    private static final String MODULE_ROOT = AppPaths.moduleRoot();
    private static final DateTimeFormatter TS_FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private static final Pattern IMG_NO_ALT = Pattern.compile("<img\\b(?![^>]*\\balt\\s*=)[^>]*>", Pattern.CASE_INSENSITIVE);
    private static final Pattern INPUT_TAG = Pattern.compile("<(input|select|textarea)\\b[^>]*>", Pattern.CASE_INSENSITIVE);
    private static final Pattern BUTTON_EMPTY = Pattern.compile("<button\\b[^>]*>\\s*</button>", Pattern.CASE_INSENSITIVE);
    private static final Pattern A_EMPTY = Pattern.compile("<a\\b[^>]*>\\s*</a>", Pattern.CASE_INSENSITIVE);

    private static final long SECURITY_CACHE_TTL_MS = 15000L;
    private static final int SECURITY_MAX_ITEMS = 3000;
    private static final long SOURCE_SCAN_MAX_FILE_BYTES = 768L * 1024L;
    private static final int EXPLORER_TERMINAL_MAX_LINES = 300;
    private static final List<String> EXPLORER_LOG_FILES = Arrays.asList(
            AppPaths.resolvePath("logs", "critical-events.jsonl").toString(),
            AppPaths.resolvePath("logs", "module-log-events.jsonl").toString());

    private static final String EXTERNAL_URLS_ENV = "MSA_SECURITY_API_URLS";
    private static final String EXTERNAL_TOKEN_ENV = "MSA_SECURITY_API_TOKEN";
    private static final int EXTERNAL_TIMEOUT_MS = 3000;

    private static final List<String> CODE_SCAN_EXTS = Arrays.asList(
            ".java", ".kt", ".js", ".ts", ".jsx", ".tsx", ".py", ".go", ".rb", ".php", ".yml", ".yaml", ".properties", ".xml");

    private static final List<SecurityRule> CODE_RULES = Arrays.asList(
            new SecurityRule(
                    "CRITICAL",
                    "SQL_INJECTION_STRING_CONCAT",
                    "critical",
                    "db/query",
                    Pattern.compile("(jdbcTemplate\\.(query|update|execute)|createNativeQuery|createQuery|prepareStatement|execute(Query|Update))\\s*\\([^\\n;]*\\+", Pattern.CASE_INSENSITIVE)),
            new SecurityRule(
                    "CRITICAL",
                    "COMMAND_INJECTION_RUNTIME_EXEC",
                    "critical",
                    "command-exec",
                    Pattern.compile("Runtime\\.getRuntime\\(\\)\\.exec\\s*\\((?!\\s*\\\"[^\\\"]+\\\")", Pattern.CASE_INSENSITIVE)),
            new SecurityRule(
                    "CRITICAL",
                    "COMMAND_INJECTION_PROCESS_BUILDER",
                    "critical",
                    "command-exec",
                    Pattern.compile("new\\s+ProcessBuilder\\s*\\([^\\)]*\\+", Pattern.CASE_INSENSITIVE)),
            new SecurityRule(
                    "HIGH",
                    "HARDCODED_SECRET",
                    "high",
                    "secrets",
                    Pattern.compile("(password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|private[_-]?key)\\s*[:=]\\s*[\\\"'][^\\\"']{8,}[\\\"']", Pattern.CASE_INSENSITIVE)),
            new SecurityRule(
                    "HIGH",
                    "XSS_UNESCAPED_RESPONSE_WRITE",
                    "high",
                    "web-threat",
                    Pattern.compile("(getWriter\\(\\)\\.write|getWriter\\(\\)\\.print)\\s*\\([^\\)]*(request\\.|getParameter\\()", Pattern.CASE_INSENSITIVE),
                    ".java", ".kt"),
            new SecurityRule(
                    "HIGH",
                    "PATH_TRAVERSAL_USER_INPUT_PATH",
                    "high",
                    "path-traversal",
                    Pattern.compile("(new\\s+File|Paths?\\.get)\\s*\\([^\\)]*(getParameter|getHeader|getQueryString|request\\.)", Pattern.CASE_INSENSITIVE)),
            new SecurityRule(
                    "HIGH",
                    "WEAK_HASH_ALGO",
                    "high",
                    "crypto",
                    Pattern.compile("MessageDigest\\.getInstance\\(\\s*\\\"(MD5|SHA-1)\\\"\\s*\\)", Pattern.CASE_INSENSITIVE),
                    ".java", ".kt"),
            new SecurityRule(
                    "HIGH",
                    "SSL_TRUST_ALL",
                    "high",
                    "tls",
                    Pattern.compile("(setHostnameVerifier\\s*\\(\\s*\\([^\\)]*\\)\\s*->\\s*true\\s*\\)|X509TrustManager)", Pattern.CASE_INSENSITIVE),
                    ".java", ".kt"),
            new SecurityRule(
                    "MEDIUM",
                    "INSECURE_RANDOM",
                    "medium",
                    "crypto",
                    Pattern.compile("new\\s+Random\\s*\\(", Pattern.CASE_INSENSITIVE),
                    ".java", ".kt"),
            new SecurityRule(
                    "MEDIUM",
                    "CSRF_DISABLED",
                    "medium",
                    "auth",
                    Pattern.compile("csrf\\s*\\(\\s*\\)\\s*\\.disable\\s*\\(", Pattern.CASE_INSENSITIVE),
                    ".java", ".kt"),
            new SecurityRule(
                    "HIGH",
                    "OPEN_REDIRECT_USER_CONTROLLED",
                    "high",
                    "web-threat",
                    Pattern.compile("sendRedirect\\s*\\([^\\)]*(getParameter|getHeader|getQueryString|request\\.)", Pattern.CASE_INSENSITIVE),
                    ".java", ".kt"),
            new SecurityRule(
                    "HIGH",
                    "SSRF_USER_CONTROLLED_URL",
                    "high",
                    "web-threat",
                    Pattern.compile("(new\\s+URL|RestTemplate\\s*\\.|WebClient\\s*\\.|HttpURLConnection)\\s*[^\\n;]*(getParameter|getHeader|getQueryString|request\\.)", Pattern.CASE_INSENSITIVE),
                    ".java", ".kt"),
            new SecurityRule(
                    "HIGH",
                    "INSECURE_DESERIALIZATION",
                    "high",
                    "serialization",
                    Pattern.compile("new\\s+ObjectInputStream\\s*\\(", Pattern.CASE_INSENSITIVE),
                    ".java", ".kt"),
            new SecurityRule(
                    "HIGH",
                    "CLASSLOADER_USER_INPUT",
                    "high",
                    "rce",
                    Pattern.compile("Class\\.forName\\s*\\([^\\)]*(getParameter|getHeader|getQueryString|request\\.)", Pattern.CASE_INSENSITIVE),
                    ".java", ".kt"),
            new SecurityRule(
                    "HIGH",
                    "PERMIT_ALL_WILDCARD",
                    "high",
                    "authorization",
                    Pattern.compile("(antMatchers|requestMatchers)\\s*\\(\\s*\"/\\*\\*\"\\s*\\)\\s*\\.permitAll\\s*\\(", Pattern.CASE_INSENSITIVE),
                    ".java", ".kt"),
            new SecurityRule(
                    "HIGH",
                    "CORS_WILDCARD_ORIGIN",
                    "high",
                    "web-threat",
                    Pattern.compile("(Access-Control-Allow-Origin\\s*[:=]\\s*\\*|allowedOrigins\\s*\\(\\s*\"\\*\"\\s*\\)|setAllowedOrigins\\s*\\([^\\)]*\\*[^\\)]*\\))", Pattern.CASE_INSENSITIVE)),
            new SecurityRule(
                    "MEDIUM",
                    "SECURITY_HEADERS_DISABLED",
                    "medium",
                    "auth",
                    Pattern.compile("(frameOptions\\s*\\(\\s*\\)\\s*\\.disable\\s*\\(|contentSecurityPolicy\\s*\\(\\s*\\)\\s*\\.disable\\s*\\(|xssProtection\\s*\\(\\s*\\)\\s*\\.disable\\s*\\()", Pattern.CASE_INSENSITIVE),
                    ".java", ".kt"),
            new SecurityRule(
                    "HIGH",
                    "COOKIE_HTTPONLY_FALSE",
                    "high",
                    "auth",
                    Pattern.compile("httpOnly\\s*\\(\\s*false\\s*\\)", Pattern.CASE_INSENSITIVE),
                    ".java", ".kt"),
            new SecurityRule(
                    "MEDIUM",
                    "COOKIE_SECURE_FALSE",
                    "medium",
                    "auth",
                    Pattern.compile("secure\\s*\\(\\s*false\\s*\\)", Pattern.CASE_INSENSITIVE),
                    ".java", ".kt"),
            new SecurityRule(
                    "MEDIUM",
                    "TRUST_ALL_HOSTNAME_VERIFIER",
                    "medium",
                    "tls",
                    Pattern.compile("HostnameVerifier\\s*\\{[^\\n]*return\\s+true\\s*;", Pattern.CASE_INSENSITIVE),
                    ".java", ".kt"),
            new SecurityRule(
                    "HIGH",
                    "WEAK_JWT_SECRET_VALUE",
                    "high",
                    "secrets",
                    Pattern.compile("(jwt|token|access|refresh)[^\\n:=]{0,24}(secret|key)[^\\n:=]{0,10}[:=]\\s*[\"']?(test|dev|sample|default|changeme|1234|secret)[\"']?", Pattern.CASE_INSENSITIVE),
                    ".yml", ".yaml", ".properties"),
            new SecurityRule(
                    "HIGH",
                    "PRIVATE_KEY_IN_SOURCE",
                    "high",
                    "secrets",
                    Pattern.compile("-----BEGIN\\s+(RSA|EC|OPENSSH|DSA)?\\s*PRIVATE\\s+KEY-----", Pattern.CASE_INSENSITIVE)),
            new SecurityRule(
                    "HIGH",
                    "AWS_ACCESS_KEY_EXPOSED",
                    "high",
                    "secrets",
                    Pattern.compile("AKIA[0-9A-Z]{16}", Pattern.CASE_INSENSITIVE)),
            new SecurityRule(
                    "MEDIUM",
                    "POTENTIAL_CREDENTIAL_LOGGING",
                    "medium",
                    "secrets",
                    Pattern.compile("(log\\.(info|debug|warn|error)|System\\.out\\.println)\\s*\\([^\\)]*(password|passwd|token|secret|authorization)", Pattern.CASE_INSENSITIVE),
                    ".java", ".kt"),
            new SecurityRule(
                    "MEDIUM",
                    "SQL_SELECT_STAR_PRODUCTION",
                    "medium",
                    "db/query",
                    Pattern.compile("select\\s+\\*\\s+from\\s+", Pattern.CASE_INSENSITIVE),
                    ".java", ".kt", ".xml"),
            new SecurityRule(
                    "HIGH",
                    "XML_EXTERNAL_ENTITY_RISK",
                    "high",
                    "xxe",
                    Pattern.compile("(DocumentBuilderFactory\\.newInstance\\s*\\(|SAXParserFactory\\.newInstance\\s*\\(|XMLInputFactory\\.newFactory\\s*\\()", Pattern.CASE_INSENSITIVE),
                    ".java", ".kt"),
            new SecurityRule(
                    "MEDIUM",
                    "YAML_UNSAFE_LOAD",
                    "medium",
                    "deserialization",
                    Pattern.compile("new\\s+Yaml\\s*\\(\\s*\\)\\s*;?", Pattern.CASE_INSENSITIVE),
                    ".java", ".kt"),
            new SecurityRule(
                    "HIGH",
                    "FILE_UPLOAD_NO_EXTENSION_VALIDATION",
                    "high",
                    "file-upload",
                    Pattern.compile("(MultipartFile|getOriginalFilename\\s*\\()", Pattern.CASE_INSENSITIVE),
                    ".java", ".kt"),
            new SecurityRule(
                    "MEDIUM",
                    "POTENTIAL_DIRECTORY_LISTING",
                    "medium",
                    "path-traversal",
                    Pattern.compile("(new\\s+File\\s*\\([^\\)]*\\)\\s*\\.listFiles\\s*\\()", Pattern.CASE_INSENSITIVE),
                    ".java", ".kt"),
            new SecurityRule(
                    "HIGH",
                    "EXEC_SQL_SCRIPT_RUNTIME",
                    "high",
                    "db/query",
                    Pattern.compile("(ScriptRunner|RUNSCRIPT|execute\\s*\\(\\s*\"\\s*drop\\s+|execute\\s*\\(\\s*\"\\s*alter\\s+)", Pattern.CASE_INSENSITIVE),
                    ".java", ".kt", ".sql"),
            new SecurityRule(
                    "MEDIUM",
                    "HTTP_CLIENT_WITHOUT_TLS",
                    "medium",
                    "tls",
                    Pattern.compile("http://", Pattern.CASE_INSENSITIVE),
                    ".yml", ".yaml", ".properties", ".java", ".kt"),
            new SecurityRule(
                    "HIGH",
                    "JDBC_URL_WITHOUT_SSL",
                    "high",
                    "tls",
                    Pattern.compile("jdbc:[^\\n]*(useSSL=false|ssl=false)", Pattern.CASE_INSENSITIVE),
                    ".yml", ".yaml", ".properties"),
            new SecurityRule(
                    "MEDIUM",
                    "HARDCODED_BASIC_AUTH",
                    "medium",
                    "secrets",
                    Pattern.compile("Authorization\\s*[:=]\\s*Basic\\s+[A-Za-z0-9+/=]{8,}", Pattern.CASE_INSENSITIVE)),
            new SecurityRule(
                    "HIGH",
                    "JWT_NONE_ALGORITHM",
                    "high",
                    "auth",
                    Pattern.compile("alg\\s*[:=]\\s*\"?none\"?", Pattern.CASE_INSENSITIVE)),
            new SecurityRule(
                    "MEDIUM",
                    "X_FRAME_OPTIONS_DISABLED",
                    "medium",
                    "auth",
                    Pattern.compile("X-Frame-Options\\s*[:=]\\s*(ALLOWALL|ALLOW-FROM|\\*)", Pattern.CASE_INSENSITIVE)),
            new SecurityRule(
                    "MEDIUM",
                    "TRACE_METHOD_ENABLED",
                    "medium",
                    "web-threat",
                    Pattern.compile("(HttpMethod\\.TRACE|REQUEST_METHOD\\s*==\\s*\"TRACE\"|allowTrace\\s*[:=]\\s*true)", Pattern.CASE_INSENSITIVE)),
            new SecurityRule(
                    "HIGH",
                    "PASSWORD_IN_QUERY_PARAM",
                    "high",
                    "secrets",
                    Pattern.compile("(\\?|&)(password|passwd|pwd|token|secret)=", Pattern.CASE_INSENSITIVE),
                    ".java", ".kt", ".yml", ".yaml", ".properties")
    );

    @Autowired
    private LogAnalyticsService logAnalyticsService;

    @Autowired
    private MsaProcessManager processManager;

    private final MsaScanner scanner = new MsaScanner();
    private final ObjectMapper objectMapper = new ObjectMapper();

    private volatile Map<String, Object> securityCache = null;
    private volatile long securityCacheAtMs = 0L;
    private final Object securityLock = new Object();

    private volatile boolean sourceScanEnabled = false;
    private volatile List<Map<String, Object>> latestSourceFindings = Collections.emptyList();
    private volatile String latestSourceScanAt = "";
    private volatile String sourceScanProfile = "strict";
    private volatile boolean securityIncludeEventEngine = true;
    private volatile boolean securityIncludeExternalEngine = true;
    private volatile boolean securityNewOnlyMode = false;
    private volatile boolean securityGateHigh = false;
    private volatile boolean securityGateCritical = true;
    private final Set<String> securityBaselineFingerprints = Collections.synchronizedSet(new HashSet<String>());

    private final Object exploreLock = new Object();
    private volatile boolean exploreRunning = false;
    private volatile String exploreMode = "source";
    private volatile String explorePhase = "idle";
    private volatile String exploreStartedAt = "";
    private volatile String exploreFinishedAt = "";
    private volatile String exploreCurrentTarget = "";
    private volatile int exploreProgressPct = 0;
    private volatile int exploreScannedFiles = 0;
    private volatile int exploreTotalFiles = 0;
    private volatile int exploreMatchedCount = 0;
    private volatile long exploreElapsedMs = 0L;
    private volatile long exploreEtaSeconds = -1L;
    private final List<String> exploreTerminalLines = Collections.synchronizedList(new ArrayList<String>());
    private final List<Map<String, Object>> exploreTimeline = Collections.synchronizedList(new ArrayList<Map<String, Object>>());
    private final Object trafficLoadLock = new Object();
    private volatile boolean trafficLoadRunning = false;
    private volatile Map<String, Object> lastTrafficLoadResult = null;
    private volatile String lastTrafficLoadStartedAt = "";
    private volatile String lastTrafficLoadFinishedAt = "";

    public Map<String, Object> getSecurityViolations() {
        long now = System.currentTimeMillis();
        Map<String, Object> cached = securityCache;
        if (cached != null && (now - securityCacheAtMs) < SECURITY_CACHE_TTL_MS) {
            return cached;
        }

        synchronized (securityLock) {
            now = System.currentTimeMillis();
            cached = securityCache;
            if (cached != null && (now - securityCacheAtMs) < SECURITY_CACHE_TTL_MS) {
                return cached;
            }

            Map<String, Object> out = buildSecurityViolations();
            securityCache = out;
            securityCacheAtMs = now;
            return out;
        }
    }

    public Map<String, Object> getSourceScanConfig() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("enabled", sourceScanEnabled);
        out.put("profile", sourceScanProfile);
        out.put("lastScanAt", latestSourceScanAt);
        out.put("cachedItems", latestSourceFindings.size());
        out.put("includeEventEngine", securityIncludeEventEngine);
        out.put("includeExternalEngine", securityIncludeExternalEngine);
        out.put("newOnlyMode", securityNewOnlyMode);
        out.put("gateHigh", securityGateHigh);
        out.put("gateCritical", securityGateCritical);
        out.put("baselineCount", securityBaselineFingerprints.size());
        return out;
    }

    public Map<String, Object> setSourceScanEnabled(boolean enabled) {
        sourceScanEnabled = enabled;
        synchronized (securityLock) {
            securityCache = null;
            securityCacheAtMs = 0L;
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("status", "ok");
        out.put("enabled", sourceScanEnabled);
        out.put("profile", sourceScanProfile);
        out.put("lastScanAt", latestSourceScanAt);
        out.put("cachedItems", latestSourceFindings.size());
        out.put("includeEventEngine", securityIncludeEventEngine);
        out.put("includeExternalEngine", securityIncludeExternalEngine);
        out.put("newOnlyMode", securityNewOnlyMode);
        out.put("gateHigh", securityGateHigh);
        out.put("gateCritical", securityGateCritical);
        out.put("baselineCount", securityBaselineFingerprints.size());
        return out;
    }

    public Map<String, Object> setSourceScanProfile(String profileRaw) {
        String p = str(profileRaw).toLowerCase(Locale.ROOT);
        if (!"strict".equals(p) && !"balanced".equals(p) && !"paranoid".equals(p)) {
            p = "strict";
        }
        sourceScanProfile = p;
        synchronized (securityLock) {
            securityCache = null;
            securityCacheAtMs = 0L;
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("status", "ok");
        out.put("enabled", sourceScanEnabled);
        out.put("profile", sourceScanProfile);
        out.put("lastScanAt", latestSourceScanAt);
        out.put("cachedItems", latestSourceFindings.size());
        out.put("includeEventEngine", securityIncludeEventEngine);
        out.put("includeExternalEngine", securityIncludeExternalEngine);
        out.put("newOnlyMode", securityNewOnlyMode);
        out.put("gateHigh", securityGateHigh);
        out.put("gateCritical", securityGateCritical);
        out.put("baselineCount", securityBaselineFingerprints.size());
        return out;
    }

    public Map<String, Object> setSourceScanOptions(Map<String, Object> req) {
        if (req != null) {
            if (req.containsKey("includeEventEngine")) {
                securityIncludeEventEngine = Boolean.parseBoolean(String.valueOf(req.get("includeEventEngine")));
            }
            if (req.containsKey("includeExternalEngine")) {
                securityIncludeExternalEngine = Boolean.parseBoolean(String.valueOf(req.get("includeExternalEngine")));
            }
            if (req.containsKey("newOnlyMode")) {
                securityNewOnlyMode = Boolean.parseBoolean(String.valueOf(req.get("newOnlyMode")));
            }
            if (req.containsKey("gateHigh")) {
                securityGateHigh = Boolean.parseBoolean(String.valueOf(req.get("gateHigh")));
            }
            if (req.containsKey("gateCritical")) {
                securityGateCritical = Boolean.parseBoolean(String.valueOf(req.get("gateCritical")));
            }
        }
        synchronized (securityLock) {
            securityCache = null;
            securityCacheAtMs = 0L;
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("status", "ok");
        out.put("includeEventEngine", securityIncludeEventEngine);
        out.put("includeExternalEngine", securityIncludeExternalEngine);
        out.put("newOnlyMode", securityNewOnlyMode);
        out.put("gateHigh", securityGateHigh);
        out.put("gateCritical", securityGateCritical);
        out.put("baselineCount", securityBaselineFingerprints.size());
        return out;
    }

    public Map<String, Object> getSecurityBaselineStatus() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("status", "ok");
        out.put("baselineCount", securityBaselineFingerprints.size());
        out.put("newOnlyMode", securityNewOnlyMode);
        return out;
    }

    public Map<String, Object> rebuildSecurityBaseline() {
        boolean oldNewOnly = securityNewOnlyMode;
        securityNewOnlyMode = false;
        Map<String, Object> current = buildSecurityViolations();
        securityNewOnlyMode = oldNewOnly;
        Object items = current.get("items");
        Set<String> next = new HashSet<>();
        if (items instanceof List) {
            for (Object it : (List<?>) items) {
                if (it instanceof Map) {
                    String fp = buildFingerprint((Map<String, Object>) it);
                    if (!fp.isEmpty()) {
                        next.add(fp);
                    }
                }
            }
        }
        synchronized (securityBaselineFingerprints) {
            securityBaselineFingerprints.clear();
            securityBaselineFingerprints.addAll(next);
        }
        synchronized (securityLock) {
            securityCache = null;
            securityCacheAtMs = 0L;
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("status", "ok");
        out.put("baselineCount", securityBaselineFingerprints.size());
        return out;
    }

    public Map<String, Object> startExplore(String modeRaw) {
        final String mode = normalizeExploreMode(modeRaw);
        synchronized (exploreLock) {
            if (exploreRunning) {
                Map<String, Object> busy = new LinkedHashMap<>();
                busy.put("status", "busy");
                busy.put("running", true);
                busy.put("mode", exploreMode);
                return busy;
            }

            resetExploreState(mode);
            exploreRunning = true;

            Thread t = new Thread(() -> runExploreJob(mode), "msa-security-explorer");
            t.setDaemon(true);
            t.start();
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("status", "ok");
        out.put("running", true);
        out.put("mode", mode);
        return out;
    }

    public Map<String, Object> getExploreStatus() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("running", exploreRunning);
        out.put("mode", exploreMode);
        out.put("phase", explorePhase);
        out.put("startedAt", exploreStartedAt);
        out.put("finishedAt", exploreFinishedAt);
        out.put("currentTarget", exploreCurrentTarget);
        out.put("progressPct", exploreProgressPct);
        out.put("scannedFiles", exploreScannedFiles);
        out.put("totalFiles", exploreTotalFiles);
        out.put("matchedCount", exploreMatchedCount);
        out.put("elapsedMs", exploreElapsedMs);
        out.put("etaSeconds", exploreEtaSeconds);
        synchronized (exploreTerminalLines) {
            out.put("terminalLines", new ArrayList<>(exploreTerminalLines));
        }
        synchronized (exploreTimeline) {
            out.put("timeline", new ArrayList<>(exploreTimeline));
        }
        out.put("sourceScanEnabled", sourceScanEnabled);
        out.put("sourceScanProfile", sourceScanProfile);
        out.put("sourceLastScanAt", latestSourceScanAt);
        out.put("sourceCachedItems", latestSourceFindings.size());
        out.put("includeEventEngine", securityIncludeEventEngine);
        out.put("includeExternalEngine", securityIncludeExternalEngine);
        out.put("newOnlyMode", securityNewOnlyMode);
        out.put("gateHigh", securityGateHigh);
        out.put("gateCritical", securityGateCritical);
        out.put("baselineCount", securityBaselineFingerprints.size());
        return out;
    }

    private Map<String, Object> buildSecurityViolations() {
        List<Map<String, Object>> rows = new ArrayList<>();
        Map<String, Integer> gradeCounts = initGradeCounts();

        if (securityIncludeEventEngine) {
            List<Map<String, Object>> critical = logAnalyticsService.getCriticalEvents();
            for (Map<String, Object> event : critical) {
                String msg = str(event.get("message"));
                String grade = classifyGrade(msg);
                String category = classifyCategory(msg);

                Map<String, Object> row = new LinkedHashMap<>();
                row.put("time", strOrNow(event.get("time")));
                row.put("module", str(event.get("module")));
                row.put("level", str(event.get("level")));
                row.put("grade", grade);
                row.put("category", category);
                row.put("message", msg);
                row.put("engine", "internal-log");
                rows.add(row);
                bumpGrade(gradeCounts, grade);
            }
        }

        if (sourceScanEnabled) {
            List<Map<String, Object>> staticRows = latestSourceFindings;
            for (Map<String, Object> row : staticRows) {
                rows.add(row);
                bumpGrade(gradeCounts, str(row.get("grade")));
            }
        }

        if (securityIncludeExternalEngine) {
            List<Map<String, Object>> externalRows = fetchExternalSecurityFindings();
            for (Map<String, Object> row : externalRows) {
                rows.add(row);
                bumpGrade(gradeCounts, str(row.get("grade")));
            }
        }

        rows = dedupeSecurityRows(rows);
        for (Map<String, Object> row : rows) {
            String fp = buildFingerprint(row);
            row.put("fingerprint", fp);
            boolean isNew = !fp.isEmpty() && !securityBaselineFingerprints.contains(fp);
            row.put("isNew", isNew);
        }
        if (securityNewOnlyMode) {
            List<Map<String, Object>> onlyNew = new ArrayList<>();
            for (Map<String, Object> row : rows) {
                if (bool(row.get("isNew"))) {
                    onlyNew.add(row);
                }
            }
            rows = onlyNew;
            gradeCounts = recalcGrades(rows);
        }
        int actionRequiredCount = 0;
        for (Map<String, Object> row : rows) {
            int score = computeActionPriority(row);
            String action = score >= 75 ? "immediate"
                    : score >= 55 ? "required"
                    : score >= 35 ? "review"
                    : "observe";
            boolean required = "immediate".equals(action) || "required".equals(action);
            row.put("priorityScore", score);
            row.put("action", action);
            row.put("actionRequired", required);
            row.put("confidence", computeConfidence(row, score));
            row.put("remediation", suggestRemediation(row));
            if (required) {
                actionRequiredCount++;
            }
        }
        rows.sort((a, b) -> {
            int aReq = bool(a.get("actionRequired")) ? 1 : 0;
            int bReq = bool(b.get("actionRequired")) ? 1 : 0;
            if (aReq != bReq) return Integer.compare(bReq, aReq);
            int as = intVal(a.get("priorityScore"));
            int bs = intVal(b.get("priorityScore"));
            if (as != bs) return Integer.compare(bs, as);
            int ag = gradeWeight(str(a.get("grade")));
            int bg = gradeWeight(str(b.get("grade")));
            if (ag != bg) return Integer.compare(bg, ag);
            LocalDateTime at = parseTime(str(a.get("time")));
            LocalDateTime bt = parseTime(str(b.get("time")));
            if (at == null && bt == null) return 0;
            if (at == null) return 1;
            if (bt == null) return -1;
            return bt.compareTo(at);
        });

        if (rows.size() > SECURITY_MAX_ITEMS) {
            rows = new ArrayList<>(rows.subList(0, SECURITY_MAX_ITEMS));
            gradeCounts = recalcGrades(rows);
        }

        int newCritical = 0;
        int newHigh = 0;
        for (Map<String, Object> row : rows) {
            if (!bool(row.get("isNew"))) {
                continue;
            }
            String g = normalizeGrade(str(row.get("grade")));
            if ("critical".equals(g)) {
                newCritical++;
            } else if ("high".equals(g)) {
                newHigh++;
            }
        }
        boolean gateBlocked = (securityGateCritical && newCritical > 0) || (securityGateHigh && newHigh > 0);
        Map<String, Object> gate = new LinkedHashMap<>();
        gate.put("blocked", gateBlocked);
        gate.put("newCritical", newCritical);
        gate.put("newHigh", newHigh);
        gate.put("gateCritical", securityGateCritical);
        gate.put("gateHigh", securityGateHigh);

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("total", rows.size());
        out.put("actionRequired", actionRequiredCount);
        out.put("gradeCounts", gradeCounts);
        out.put("gate", gate);
        out.put("baselineCount", securityBaselineFingerprints.size());
        out.put("items", rows);
        return out;
    }

    private void runExploreJob(String mode) {
        long startMs = System.currentTimeMillis();
        appendTerminal("탐색 시작 mode=" + mode);
        addTimeline("START", "탐색 시작 (" + mode + ")");

        try {
            if ("source".equals(mode) || "all".equals(mode)) {
                explorePhase = "source";
                addTimeline("SOURCE", "소스 정적 보안 탐색 시작");
                List<Map<String, Object>> scanned = scanSourceSecurityFindings(true);
                latestSourceFindings = Collections.unmodifiableList(new ArrayList<>(scanned));
                latestSourceScanAt = LocalDateTime.now().format(TS_FMT);
                appendTerminal("소스 탐색 완료 findings=" + latestSourceFindings.size());
                addTimeline("SOURCE_DONE", "소스 탐색 완료 (" + latestSourceFindings.size() + "건)");
                synchronized (securityLock) {
                    securityCache = null;
                    securityCacheAtMs = 0L;
                }
            }

            if ("logs".equals(mode) || "all".equals(mode)) {
                explorePhase = "logs";
                addTimeline("LOGS", "로그 탐색 시작");
                int matched = runLogExplore();
                appendTerminal("로그 탐색 완료 matched=" + matched);
                addTimeline("LOGS_DONE", "로그 탐색 완료 (" + matched + "건)");
            }
        } catch (Exception e) {
            appendTerminal("탐색 실패: " + e.getMessage());
            addTimeline("ERROR", "탐색 실패: " + e.getMessage());
        } finally {
            exploreRunning = false;
            explorePhase = "done";
            exploreFinishedAt = LocalDateTime.now().format(TS_FMT);
            exploreElapsedMs = System.currentTimeMillis() - startMs;
            exploreCurrentTarget = "";
            exploreEtaSeconds = 0;
            exploreProgressPct = 100;
            addTimeline("DONE", "탐색 완료");
        }
    }

    private int runLogExplore() {
        int matched = 0;
        List<Path> targets = new ArrayList<>();
        for (String logFile : EXPLORER_LOG_FILES) {
            Path p = Paths.get(logFile);
            if (Files.isRegularFile(p)) {
                targets.add(p);
            }
        }
        if (targets.isEmpty()) {
            appendTerminal("로그 파일이 없어 로그 탐색을 건너뜁니다.");
            return 0;
        }

        int doneFiles = 0;
        int totalFiles = targets.size();
        for (Path path : targets) {
            doneFiles++;
            long fileSize = 0L;
            try {
                fileSize = Files.size(path);
            } catch (Exception ignored) {
            }
            long readBytes = 0L;
            int lineNo = 0;
            exploreCurrentTarget = path.toString();
            appendTerminal("LOG> " + path.toString() + " 분석 시작");
            addTimeline("LOG_FILE", path.getFileName().toString() + " 분석");

            try (BufferedReader br = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
                String line;
                while ((line = br.readLine()) != null) {
                    lineNo++;
                    readBytes += line.length() + 1L;
                    String lower = line.toLowerCase(Locale.ROOT);
                    if (containsAny(lower, "forbidden", "unauthorized", "xss", "csrf", "sql", "token", "access denied", "exception")) {
                        matched++;
                    }
                    if (lineNo % 2000 == 0) {
                        long elapsed = Math.max(1L, System.currentTimeMillis() - parseExploreTime(exploreStartedAt));
                        double speed = (lineNo * 1000.0) / elapsed;
                        long eta = fileSize > 0L ? Math.max(0L, (long) ((fileSize - readBytes) / Math.max(1.0, readBytes / (elapsed / 1000.0)))) : -1L;
                        appendTerminal("LOG> " + path.getFileName() + " line=" + lineNo + " matched=" + matched + " speed=" + round2(speed) + "l/s");
                        exploreEtaSeconds = eta >= 0L ? eta : -1L;
                        int base = totalFiles == 0 ? 0 : (int) (((doneFiles - 1) * 100.0) / totalFiles);
                        int inner = fileSize > 0L ? (int) Math.min(99L, (readBytes * 100L) / Math.max(1L, fileSize)) : 0;
                        exploreProgressPct = Math.min(99, base + inner / Math.max(1, totalFiles));
                    }
                }
            } catch (Exception e) {
                appendTerminal("LOG> 파일 읽기 실패: " + path + " (" + e.getMessage() + ")");
            }
        }
        exploreMatchedCount += matched;
        return matched;
    }

    private long parseExploreTime(String ts) {
        try {
            if (ts == null || ts.isEmpty()) {
                return System.currentTimeMillis();
            }
            return java.sql.Timestamp.valueOf(ts).getTime();
        } catch (Exception e) {
            return System.currentTimeMillis();
        }
    }

    private String normalizeExploreMode(String modeRaw) {
        String mode = str(modeRaw).toLowerCase(Locale.ROOT);
        if ("source".equals(mode) || "logs".equals(mode) || "all".equals(mode)) {
            return mode;
        }
        return "source";
    }

    private void resetExploreState(String mode) {
        exploreMode = mode;
        explorePhase = "queued";
        exploreStartedAt = LocalDateTime.now().format(TS_FMT);
        exploreFinishedAt = "";
        exploreCurrentTarget = "";
        exploreProgressPct = 0;
        exploreScannedFiles = 0;
        exploreTotalFiles = 0;
        exploreMatchedCount = 0;
        exploreElapsedMs = 0L;
        exploreEtaSeconds = -1L;
        synchronized (exploreTerminalLines) {
            exploreTerminalLines.clear();
        }
        synchronized (exploreTimeline) {
            exploreTimeline.clear();
        }
    }

    private void appendTerminal(String line) {
        String ts = LocalDateTime.now().format(TS_FMT);
        synchronized (exploreTerminalLines) {
            exploreTerminalLines.add("[" + ts + "] " + line);
            int over = exploreTerminalLines.size() - EXPLORER_TERMINAL_MAX_LINES;
            if (over > 0) {
                exploreTerminalLines.subList(0, over).clear();
            }
        }
        long startedMs = parseExploreTime(exploreStartedAt);
        exploreElapsedMs = Math.max(0L, System.currentTimeMillis() - startedMs);
    }

    private void addTimeline(String type, String message) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("time", LocalDateTime.now().format(TS_FMT));
        row.put("type", type);
        row.put("message", message);
        synchronized (exploreTimeline) {
            exploreTimeline.add(row);
            if (exploreTimeline.size() > 200) {
                exploreTimeline.remove(0);
            }
        }
    }

    private List<Map<String, Object>> scanSourceSecurityFindings() {
        return scanSourceSecurityFindings(false);
    }

    private List<Map<String, Object>> scanSourceSecurityFindings(boolean progressEnabled) {
        Path root = Paths.get(MODULE_ROOT);
        if (!Files.isDirectory(root)) {
            return Collections.emptyList();
        }

        String now = LocalDateTime.now().format(TS_FMT);
        List<Map<String, Object>> out = new ArrayList<>();
        List<Path> candidates = new ArrayList<>();
        try (Stream<Path> stream = Files.walk(root, 12)) {
            stream.filter(Files::isRegularFile)
                    .filter(this::isCodeScanCandidate)
                    .forEach(candidates::add);
        } catch (Exception ignored) {
        }

        int total = candidates.size();
        if (progressEnabled) {
            exploreTotalFiles = total;
            appendTerminal("SOURCE> 대상 파일 " + total + "건");
        }

        for (int idx = 0; idx < candidates.size(); idx++) {
            Path path = candidates.get(idx);
            if (out.size() >= SECURITY_MAX_ITEMS) {
                break;
            }
            scanCodeFile(path, root, now, out);
            if (progressEnabled) {
                exploreScannedFiles = idx + 1;
                exploreMatchedCount = out.size();
                String rel = root.relativize(path).toString().replace('\\', '/');
                exploreCurrentTarget = rel;
                long startedMs = parseExploreTime(exploreStartedAt);
                long elapsedMs = Math.max(1L, System.currentTimeMillis() - startedMs);
                double perFile = elapsedMs / (double) Math.max(1, idx + 1);
                long etaMs = (long) (perFile * (total - (idx + 1)));
                exploreEtaSeconds = Math.max(0L, etaMs / 1000L);
                exploreProgressPct = total == 0 ? 100 : (int) (((idx + 1) * 100.0) / total);
                if ((idx + 1) % 25 == 0 || idx == total - 1) {
                    appendTerminal("SOURCE> " + (idx + 1) + "/" + total + " " + rel + " findings=" + out.size() + " eta=" + exploreEtaSeconds + "s");
                }
            }
        }

        return out;
    }

    private boolean isCodeScanCandidate(Path path) {
        String p = path.toString().replace('\\', '/');
        boolean isMain = p.contains("/src/main/");
        boolean isTestParanoid = "paranoid".equals(sourceScanProfile) && p.contains("/src/test/");
        if (!isMain && !isTestParanoid) {
            return false;
        }
        if (p.contains("/src/main/resources/static/")) {
            return false;
        }
        if (p.contains("/target/") || p.contains("/node_modules/") || p.contains("/.git/") || p.contains("/runtime/") || p.contains("/logs/")) {
            return false;
        }
        String lower = p.toLowerCase(Locale.ROOT);
        if (lower.endsWith(".min.js")) {
            return false;
        }
        for (String ext : CODE_SCAN_EXTS) {
            if (lower.endsWith(ext)) {
                return true;
            }
        }
        return false;
    }

    private void scanCodeFile(Path path, Path root, String now, List<Map<String, Object>> out) {
        try {
            long size = Files.size(path);
            if (size > SOURCE_SCAN_MAX_FILE_BYTES) {
                return;
            }
        } catch (Exception e) {
            return;
        }

        String rel = root.relativize(path).toString().replace('\\', '/');
        String lower = rel.toLowerCase(Locale.ROOT);
        String module = extractModule(rel);

        List<String> lines;
        try {
            lines = Files.readAllLines(path, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return;
        }

        for (int i = 0; i < lines.size(); i++) {
            if (out.size() >= SECURITY_MAX_ITEMS) {
                return;
            }

            String line = lines.get(i);
            String trim = line.trim();
            if (!"paranoid".equals(sourceScanProfile)
                    && (trim.startsWith("//") || trim.startsWith("*") || trim.startsWith("#"))) {
                continue;
            }
            if (!"paranoid".equals(sourceScanProfile) && trim.contains("Pattern.compile(")) {
                continue;
            }

            for (SecurityRule rule : CODE_RULES) {
                if (!rule.matchesExt(lower)) {
                    continue;
                }
                if (rule.pattern.matcher(line).find()) {
                    if (shouldSuppressFinding(rule.code, rel, trim)) {
                        continue;
                    }
                    Map<String, Object> row = new LinkedHashMap<>();
                    row.put("time", now);
                    row.put("module", module);
                    row.put("level", "STATIC");
                    row.put("grade", rule.grade);
                    row.put("category", rule.category);
                    row.put("message", "[" + rule.code + "] " + rel + ":" + (i + 1));
                    row.put("file", rel);
                    row.put("line", i + 1);
                    row.put("rule", rule.code);
                    row.put("snippet", trimSnippet(line));
                    row.put("engine", "internal-coderay-compatible");
                    out.add(row);
                }
            }
        }
    }

    private String extractModule(String rel) {
        if (rel == null || rel.isEmpty()) {
            return "unknown";
        }
        int idx = rel.indexOf('/');
        if (idx <= 0) {
            return rel;
        }
        return rel.substring(0, idx);
    }

    private List<Map<String, Object>> fetchExternalSecurityFindings() {
        String urlCsv = str(System.getenv(EXTERNAL_URLS_ENV));
        if (urlCsv.isEmpty()) {
            return Collections.emptyList();
        }

        String token = str(System.getenv(EXTERNAL_TOKEN_ENV));
        List<Map<String, Object>> rows = new ArrayList<>();

        String[] urls = urlCsv.split(",");
        for (String rawUrl : urls) {
            String endpoint = rawUrl == null ? "" : rawUrl.trim();
            if (endpoint.isEmpty()) {
                continue;
            }

            Map<String, Object> payload = fetchExternalPayload(endpoint, token);
            if (payload == null) {
                continue;
            }

            Object itemsObj = payload.get("items");
            List<Map<String, Object>> items = new ArrayList<>();
            if (itemsObj instanceof List) {
                for (Object item : (List<?>) itemsObj) {
                    if (item instanceof Map) {
                        items.add((Map<String, Object>) item);
                    }
                }
            }

            if (items.isEmpty() && payload.get("item") instanceof Map) {
                items.add((Map<String, Object>) payload.get("item"));
            }

            String now = LocalDateTime.now().format(TS_FMT);
            for (Map<String, Object> item : items) {
                String message = pick(item, "message", "title", "description", "detail");
                if (message.isEmpty()) {
                    continue;
                }

                String gradeRaw = pick(item, "grade", "severity", "risk");
                String grade = normalizeGrade(gradeRaw.isEmpty() ? classifyGrade(message) : gradeRaw);
                String category = pick(item, "category", "type", "family");
                if (category.isEmpty()) {
                    category = classifyCategory(message);
                }

                Map<String, Object> row = new LinkedHashMap<>();
                row.put("time", strOrDefault(pick(item, "time", "timestamp", "detectedAt"), now));
                row.put("module", strOrDefault(pick(item, "module", "service", "project"), "external"));
                row.put("level", "EXTERNAL");
                row.put("grade", grade);
                row.put("category", category);
                row.put("message", message);
                row.put("file", pick(item, "file", "path", "location"));
                row.put("line", parseInt(pick(item, "line", "lineNo")));
                row.put("rule", pick(item, "rule", "code", "id"));
                row.put("engine", "external-api");
                rows.add(row);
            }
        }

        return rows;
    }

    private Map<String, Object> fetchExternalPayload(String endpoint, String token) {
        HttpURLConnection conn = null;
        try {
            URL url = new URL(endpoint);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(EXTERNAL_TIMEOUT_MS);
            conn.setReadTimeout(EXTERNAL_TIMEOUT_MS);
            conn.setRequestProperty("Accept", "application/json");
            if (!token.isEmpty()) {
                conn.setRequestProperty("Authorization", "Bearer " + token);
            }

            int code = conn.getResponseCode();
            if (code < 200 || code >= 300) {
                return null;
            }

            try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = br.readLine()) != null) {
                    sb.append(line);
                }
                if (sb.length() == 0) {
                    return null;
                }

                Object parsed = objectMapper.readValue(sb.toString(), new TypeReference<Object>() {});
                if (parsed instanceof Map) {
                    return (Map<String, Object>) parsed;
                }
                if (parsed instanceof List) {
                    Map<String, Object> wrap = new LinkedHashMap<>();
                    wrap.put("items", parsed);
                    return wrap;
                }
            }
        } catch (Exception ignored) {
            return null;
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
        return null;
    }

    private List<Map<String, Object>> dedupeSecurityRows(List<Map<String, Object>> rows) {
        Map<String, Map<String, Object>> uniq = new LinkedHashMap<>();
        for (Map<String, Object> row : rows) {
            String key = String.join("|",
                    str(row.get("time")),
                    str(row.get("module")),
                    str(row.get("grade")),
                    str(row.get("category")),
                    str(row.get("message")),
                    str(row.get("file")),
                    str(row.get("line")),
                    str(row.get("rule")));
            if (!uniq.containsKey(key)) {
                uniq.put(key, row);
            }
        }
        return new ArrayList<>(uniq.values());
    }

    private String buildFingerprint(Map<String, Object> row) {
        if (row == null) {
            return "";
        }
        String module = str(row.get("module"));
        String rule = str(row.get("rule"));
        String file = str(row.get("file"));
        String line = str(row.get("line"));
        String msg = str(row.get("message"));
        String grade = normalizeGrade(str(row.get("grade")));
        String base = String.join("|", module, rule, file, line, grade, msg);
        if (base.replace("|", "").isEmpty()) {
            return "";
        }
        return Integer.toHexString(base.hashCode());
    }

    private Map<String, Integer> initGradeCounts() {
        Map<String, Integer> gradeCounts = new LinkedHashMap<>();
        gradeCounts.put("critical", 0);
        gradeCounts.put("high", 0);
        gradeCounts.put("medium", 0);
        gradeCounts.put("low", 0);
        return gradeCounts;
    }

    private Map<String, Integer> recalcGrades(List<Map<String, Object>> rows) {
        Map<String, Integer> out = initGradeCounts();
        for (Map<String, Object> row : rows) {
            bumpGrade(out, str(row.get("grade")));
        }
        return out;
    }

    private boolean shouldSuppressFinding(String ruleCode, String rel, String trim) {
        if (!"balanced".equals(sourceScanProfile)) {
            return false;
        }
        String t = trim == null ? "" : trim.toLowerCase(Locale.ROOT);
        String file = rel == null ? "" : rel.toLowerCase(Locale.ROOT);
        if (file.endsWith("/opsinsightservice.java")) {
            return true;
        }

        if ("HTTP_CLIENT_WITHOUT_TLS".equals(ruleCode)) {
            return t.contains("http://localhost")
                    || t.contains("http://127.0.0.1")
                    || t.contains("defaultzone: http://localhost")
                    || t.contains("optional:configserver:http://localhost");
        }
        if ("COOKIE_SECURE_FALSE".equals(ruleCode)) {
            return file.contains("jwtprovider") || file.contains("/uat/uia/util/");
        }
        if ("POTENTIAL_CREDENTIAL_LOGGING".equals(ruleCode)) {
            return !(t.contains("+") || t.contains("{}") || t.contains("getparameter") || t.contains("authorization"));
        }
        if ("FILE_UPLOAD_NO_EXTENSION_VALIDATION".equals(ruleCode)) {
            return t.startsWith("import ")
                    || t.contains("multipartfile;")
                    || (t.contains("multipartfile") && !t.contains("getoriginalfilename"));
        }
        if ("SQL_SELECT_STAR_PRODUCTION".equals(ruleCode)) {
            return file.contains("/mapper/") && t.contains("rownum");
        }
        if ("YAML_UNSAFE_LOAD".equals(ruleCode)) {
            return file.contains("msascanner.java") || file.contains("opsinsightservice.java");
        }
        return false;
    }

    private int computeActionPriority(Map<String, Object> row) {
        String grade = normalizeGrade(str(row.get("grade")));
        String category = str(row.get("category")).toLowerCase(Locale.ROOT);
        String rule = str(row.get("rule")).toUpperCase(Locale.ROOT);
        String message = str(row.get("message")).toLowerCase(Locale.ROOT);
        String file = str(row.get("file")).toLowerCase(Locale.ROOT);

        int score = 0;
        if ("critical".equals(grade)) score += 90;
        else if ("high".equals(grade)) score += 70;
        else if ("medium".equals(grade)) score += 45;
        else score += 20;

        if (containsAny(category, "secrets", "auth", "authorization", "rce", "command-exec", "xxe")) score += 12;
        if (containsAny(category, "file-upload", "web-threat", "path-traversal", "db/query")) score += 8;

        if (containsAny(rule, "HARDCODED_SECRET", "PRIVATE_KEY", "AWS_ACCESS_KEY", "SQL_INJECTION", "COMMAND_INJECTION", "PERMIT_ALL", "JWT_NONE", "SSRF", "OPEN_REDIRECT")) {
            score += 18;
        }
        if (containsAny(rule, "COOKIE_SECURE_FALSE", "HTTP_CLIENT_WITHOUT_TLS", "SQL_SELECT_STAR_PRODUCTION", "POTENTIAL_CREDENTIAL_LOGGING")) {
            score -= 8;
        }

        if (message.contains("localhost") || message.contains("127.0.0.1")) score -= 12;
        if (file.contains("/src/test/") || file.contains("opsinsightservice.java")) score -= 20;
        if (containsAny(message, "import ", "debug", "sample", "example")) score -= 6;

        if (score < 0) score = 0;
        if (score > 100) score = 100;
        return score;
    }

    private String computeConfidence(Map<String, Object> row, int score) {
        String rule = str(row.get("rule")).toUpperCase(Locale.ROOT);
        if (containsAny(rule, "HARDCODED_SECRET", "PRIVATE_KEY", "AWS_ACCESS_KEY")) {
            return "high";
        }
        if (score >= 80) return "high";
        if (score >= 55) return "medium";
        return "low";
    }

    private String suggestRemediation(Map<String, Object> row) {
        String rule = str(row.get("rule")).toUpperCase(Locale.ROOT);
        if (rule.contains("HARDCODED_SECRET") || rule.contains("PRIVATE_KEY") || rule.contains("AWS_ACCESS_KEY")) {
            return "시크릿을 코드에서 제거하고 Vault/환경변수로 이동";
        }
        if (rule.contains("FILE_UPLOAD")) {
            return "확장자/컨텐츠타입/매직넘버 검증 및 저장 경로 화이트리스트 적용";
        }
        if (rule.contains("COOKIE_SECURE_FALSE")) {
            return "운영 환경에서 Secure/HttpOnly/SameSite 설정 강화";
        }
        if (rule.contains("HTTP_CLIENT_WITHOUT_TLS")) {
            return "외부 통신 URL을 HTTPS로 전환하고 인증서 검증 적용";
        }
        if (rule.contains("SQL_INJECTION")) {
            return "문자열 결합 SQL 제거, PreparedStatement/바인딩 강제";
        }
        if (rule.contains("PERMIT_ALL")) {
            return "인가 정책 재검토 후 최소 권한 경로만 허용";
        }
        return "코드 맥락 확인 후 보안 가이드에 맞게 리팩터링";
    }

    private int gradeWeight(String grade) {
        String g = normalizeGrade(grade);
        if ("critical".equals(g)) return 4;
        if ("high".equals(g)) return 3;
        if ("medium".equals(g)) return 2;
        return 1;
    }

    private int intVal(Object v) {
        if (v instanceof Number) return ((Number) v).intValue();
        try {
            return Integer.parseInt(str(v));
        } catch (Exception e) {
            return 0;
        }
    }

    private boolean bool(Object v) {
        if (v instanceof Boolean) return (Boolean) v;
        return "true".equalsIgnoreCase(str(v));
    }

    private void bumpGrade(Map<String, Integer> gradeCounts, String grade) {
        String g = normalizeGrade(grade);
        if (!gradeCounts.containsKey(g)) {
            gradeCounts.put(g, 0);
        }
        gradeCounts.put(g, gradeCounts.get(g) + 1);
    }

    private String normalizeGrade(String raw) {
        String g = str(raw).toLowerCase(Locale.ROOT);
        if ("critical".equals(g) || "high".equals(g) || "medium".equals(g) || "low".equals(g)) {
            return g;
        }
        if ("severe".equals(g)) {
            return "high";
        }
        if ("moderate".equals(g)) {
            return "medium";
        }
        return "low";
    }

    private String pick(Map<String, Object> src, String... keys) {
        if (src == null) {
            return "";
        }
        for (String key : keys) {
            if (src.containsKey(key) && src.get(key) != null) {
                String v = String.valueOf(src.get(key)).trim();
                if (!v.isEmpty()) {
                    return v;
                }
            }
        }
        return "";
    }

    private int parseInt(String raw) {
        if (raw == null || raw.trim().isEmpty()) {
            return 0;
        }
        try {
            return Integer.parseInt(raw.trim());
        } catch (Exception ignored) {
            return 0;
        }
    }

    private String str(Object v) {
        return v == null ? "" : String.valueOf(v).trim();
    }

    private String strOrNow(Object v) {
        String s = str(v);
        if (!s.isEmpty()) {
            return s;
        }
        return LocalDateTime.now().format(TS_FMT);
    }

    private String strOrDefault(String v, String defaultValue) {
        if (v == null || v.trim().isEmpty()) {
            return defaultValue;
        }
        return v.trim();
    }

    public Map<String, Object> getTrafficOverview() {
        List<MsaScanner.ModuleInfo> modules = scanner.scan();
        List<Map<String, Object>> mappings = loadMappings();

        Map<String, List<Map<String, Object>>> pathByModule = new HashMap<>();
        for (Map<String, Object> m : mappings) {
            String module = String.valueOf(m.get("module"));
            pathByModule.computeIfAbsent(module, k -> new ArrayList<>()).add(m);
        }

        List<Map<String, Object>> moduleStats = new ArrayList<>();
        List<Map<String, Object>> controllers = new ArrayList<>();

        long totalMemMb = 0;
        double totalCpu = 0.0;
        int totalConn = 0;
        int runningCount = 0;
        int cpuCores = Runtime.getRuntime().availableProcessors();
        int cpuCapacityPct = cpuCores * 100;

        for (MsaScanner.ModuleInfo mod : modules) {
            String status = processManager.getStatus(mod.getId(), mod.getPort());
            boolean running = "running".equals(status);

            Integer rssMb = running ? readRssMbByPort(mod.getPort()) : null;
            Double cpuPct = running ? readCpuPctByPort(mod.getPort()) : null;
            Integer activeUsers = running ? readEstablishedConnByPort(mod.getPort()) : 0;

            if (rssMb != null) totalMemMb += rssMb;
            if (cpuPct != null) totalCpu += cpuPct;
            totalConn += activeUsers != null ? activeUsers : 0;
            if (running) runningCount++;

            Map<String, Object> row = new LinkedHashMap<>();
            row.put("module", mod.getId());
            row.put("port", mod.getPort());
            row.put("status", status);
            row.put("memoryMb", rssMb);
            row.put("cpuPct", cpuPct == null ? null : round2(cpuPct));
            row.put("activeUsers", activeUsers);
            row.put("controllerCount", pathByModule.getOrDefault(mod.getId(), Collections.emptyList()).size());
            moduleStats.add(row);

            List<Map<String, Object>> modPaths = pathByModule.getOrDefault(mod.getId(), Collections.emptyList());
            for (Map<String, Object> p : modPaths) {
                Map<String, Object> c = new LinkedHashMap<>();
                c.put("module", mod.getId());
                c.put("path", p.get("path"));
                c.put("method", p.get("method"));
                c.put("description", p.get("description"));
                c.put("status", status);
                controllers.add(c);
            }
        }

        moduleStats.sort(Comparator.comparing(o -> String.valueOf(o.get("module"))));
        controllers.sort(Comparator.comparing(o -> String.valueOf(o.get("path"))));

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("runningModules", runningCount);
        summary.put("totalModules", modules.size());
        summary.put("totalMemoryMb", totalMemMb);
        summary.put("totalCpuPct", round2(totalCpu));
        summary.put("cpuCores", cpuCores);
        summary.put("cpuCapacityPct", cpuCapacityPct);
        summary.put("totalActiveUsers", totalConn);
        summary.put("controllerCount", controllers.size());

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("time", LocalDateTime.now().format(TS_FMT));
        out.put("summary", summary);
        out.put("modules", moduleStats);
        out.put("controllers", controllers);
        return out;
    }

    public Map<String, Object> getTrafficLoadStatus() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("status", "ok");
        out.put("running", trafficLoadRunning);
        out.put("startedAt", lastTrafficLoadStartedAt);
        out.put("finishedAt", lastTrafficLoadFinishedAt);
        out.put("lastResult", lastTrafficLoadResult);
        return out;
    }

    public Map<String, Object> runTrafficLoadTest(Map<String, Object> req) {
        synchronized (trafficLoadLock) {
            if (trafficLoadRunning) {
                Map<String, Object> out = new LinkedHashMap<>();
                out.put("status", "busy");
                out.put("message", "이미 부하 테스트가 실행 중입니다.");
                out.put("startedAt", lastTrafficLoadStartedAt);
                return out;
            }
            trafficLoadRunning = true;
            lastTrafficLoadStartedAt = LocalDateTime.now().format(TS_FMT);
            lastTrafficLoadFinishedAt = "";
        }

        try {
            Map<String, Object> result = executeTrafficLoadTest(req == null ? Collections.emptyMap() : req);
            lastTrafficLoadResult = result;
            return result;
        } finally {
            trafficLoadRunning = false;
            lastTrafficLoadFinishedAt = LocalDateTime.now().format(TS_FMT);
        }
    }

    private Map<String, Object> executeTrafficLoadTest(Map<String, Object> req) {
        int maxUsers = boundedInt(req.get("maxUsers"), 120, 10, 500);
        int stepUsers = boundedInt(req.get("stepUsers"), 20, 5, 200);
        int stepSeconds = boundedInt(req.get("stepSeconds"), 3, 1, 20);
        int timeoutMs = boundedInt(req.get("timeoutMs"), 2500, 300, 15000);

        Map<String, Object> target = resolveTrafficTestTarget(req);
        String targetUrl = str(target.get("url"));
        if (targetUrl.isEmpty()) {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("status", "error");
            out.put("message", "부하 테스트 대상 URL을 찾지 못했습니다. 실행 중인 모듈/경로를 확인하세요.");
            return out;
        }

        long started = System.currentTimeMillis();
        List<Map<String, Object>> stages = new ArrayList<>();
        int maxStableUsers = 0;
        double peakRps = 0.0;
        double stableRps = 0.0;
        double stableAvgMs = 0.0;
        double stableP95Ms = 0.0;
        double stableErrorRate = 0.0;
        long totalRequests = 0L;
        long totalSuccess = 0L;
        long totalErrors = 0L;

        for (int users = stepUsers; users <= maxUsers; users += stepUsers) {
            Map<String, Object> row = runTrafficLoadStep(targetUrl, users, stepSeconds, timeoutMs);
            stages.add(row);

            double rps = num(row.get("rps"));
            double successRate = num(row.get("successRatePct"));
            double errorRate = num(row.get("errorRatePct"));
            double p95 = num(row.get("p95Ms"));
            totalRequests += (long) num(row.get("totalRequests"));
            totalSuccess += (long) num(row.get("success"));
            totalErrors += (long) num(row.get("errors"));
            if (rps > peakRps) {
                peakRps = rps;
            }

            boolean stable = successRate >= 97.0 && errorRate <= 3.0 && p95 <= 1500.0;
            row.put("stable", stable);

            if (stable) {
                maxStableUsers = users;
                stableRps = rps;
                stableAvgMs = num(row.get("avgMs"));
                stableP95Ms = p95;
                stableErrorRate = errorRate;
            }

            if (!stable && users > stepUsers && (errorRate >= 10.0 || p95 > 4000.0)) {
                break;
            }
        }

        long elapsedMs = Math.max(1L, System.currentTimeMillis() - started);
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("maxConcurrentUsers", maxStableUsers);
        summary.put("peakRps", round2(peakRps));
        summary.put("stableRps", round2(stableRps));
        summary.put("avgMsAtMax", round2(stableAvgMs));
        summary.put("p95MsAtMax", round2(stableP95Ms));
        summary.put("errorRatePctAtMax", round2(stableErrorRate));
        summary.put("totalRequests", totalRequests);
        summary.put("totalSuccess", totalSuccess);
        summary.put("totalErrors", totalErrors);
        summary.put("elapsedMs", elapsedMs);

        Map<String, Object> cfg = new LinkedHashMap<>();
        cfg.put("maxUsers", maxUsers);
        cfg.put("stepUsers", stepUsers);
        cfg.put("stepSeconds", stepSeconds);
        cfg.put("timeoutMs", timeoutMs);

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("status", "ok");
        out.put("time", LocalDateTime.now().format(TS_FMT));
        out.put("target", target);
        out.put("config", cfg);
        out.put("summary", summary);
        out.put("stages", stages);
        return out;
    }

    private Map<String, Object> runTrafficLoadStep(String targetUrl, int virtualUsers, int durationSec, int timeoutMs) {
        final long endAt = System.currentTimeMillis() + (durationSec * 1000L);
        final AtomicLong total = new AtomicLong(0L);
        final AtomicLong success = new AtomicLong(0L);
        final AtomicLong errors = new AtomicLong(0L);
        final AtomicLong totalLatencyMs = new AtomicLong(0L);
        final AtomicLong maxLatencyMs = new AtomicLong(0L);
        final List<Long> latencies = Collections.synchronizedList(new ArrayList<Long>());
        List<Thread> threads = new ArrayList<>();

        for (int i = 0; i < virtualUsers; i++) {
            Thread t = new Thread(() -> {
                while (System.currentTimeMillis() < endAt) {
                    long started = System.currentTimeMillis();
                    int code = doHttpGet(targetUrl, timeoutMs);
                    long elapsed = Math.max(1L, System.currentTimeMillis() - started);

                    total.incrementAndGet();
                    totalLatencyMs.addAndGet(elapsed);
                    latencies.add(elapsed);
                    while (true) {
                        long prev = maxLatencyMs.get();
                        if (elapsed <= prev || maxLatencyMs.compareAndSet(prev, elapsed)) {
                            break;
                        }
                    }

                    if (code >= 200 && code < 400) {
                        success.incrementAndGet();
                    } else {
                        errors.incrementAndGet();
                    }
                }
            }, "traffic-load-" + virtualUsers + "-" + i);
            t.setDaemon(true);
            threads.add(t);
            t.start();
        }

        for (Thread t : threads) {
            try {
                t.join();
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
        }

        long totalReq = total.get();
        long succ = success.get();
        long err = errors.get();
        double seconds = Math.max(1.0, durationSec);
        double rps = totalReq / seconds;
        double successRate = totalReq == 0 ? 0.0 : ((succ * 100.0) / totalReq);
        double errorRate = totalReq == 0 ? 100.0 : ((err * 100.0) / totalReq);
        double avgMs = totalReq == 0 ? 0.0 : (totalLatencyMs.get() * 1.0 / totalReq);
        double p95Ms = percentile(latencies, 0.95);

        Map<String, Object> row = new LinkedHashMap<>();
        row.put("virtualUsers", virtualUsers);
        row.put("durationSec", durationSec);
        row.put("totalRequests", totalReq);
        row.put("success", succ);
        row.put("errors", err);
        row.put("rps", round2(rps));
        row.put("successRatePct", round2(successRate));
        row.put("errorRatePct", round2(errorRate));
        row.put("avgMs", round2(avgMs));
        row.put("p95Ms", round2(p95Ms));
        row.put("maxMs", maxLatencyMs.get());
        return row;
    }

    private Map<String, Object> resolveTrafficTestTarget(Map<String, Object> req) {
        List<MsaScanner.ModuleInfo> modules = scanner.scan();
        Map<String, Integer> runningPorts = new HashMap<>();
        int gatewayPort = 0;
        for (MsaScanner.ModuleInfo m : modules) {
            String status = processManager.getStatus(m.getId(), m.getPort());
            if (!"running".equals(status) || m.getPort() == null) {
                continue;
            }
            runningPorts.put(m.getId(), m.getPort());
            String idLower = m.getId() == null ? "" : m.getId().toLowerCase(Locale.ROOT);
            if (idLower.contains("gateway")) {
                gatewayPort = m.getPort();
            }
        }

        String reqPath = str(req.get("path"));
        String reqModule = str(req.get("module"));
        String reqUrl = str(req.get("url"));
        String selectedPath = "";
        String selectedModule = "";
        String selectedUrl = "";

        if (!reqUrl.isEmpty()) {
            selectedUrl = reqUrl;
        } else if (!reqPath.isEmpty()) {
            selectedPath = reqPath.startsWith("/") ? reqPath : ("/" + reqPath);
            if (gatewayPort > 0) {
                selectedUrl = "http://127.0.0.1:" + gatewayPort + selectedPath;
                selectedModule = "EgovGateway";
            } else if (!reqModule.isEmpty() && runningPorts.containsKey(reqModule)) {
                selectedModule = reqModule;
                selectedUrl = "http://127.0.0.1:" + runningPorts.get(reqModule) + selectedPath;
            }
        }

        if (selectedUrl.isEmpty()) {
            List<String> preferredPaths = Arrays.asList("/actuator/health", "/health", "/", "/main.do", "/index.do");
            List<Map<String, Object>> mappings = loadMappings();
            List<Map<String, String>> candidates = new ArrayList<>();
            List<Map.Entry<String, Integer>> orderedRunning = new ArrayList<>(runningPorts.entrySet());
            orderedRunning.sort((a, b) -> Integer.compare(modulePriority(a.getKey()), modulePriority(b.getKey())));

            if (gatewayPort > 0) {
                for (String p : preferredPaths) {
                    Map<String, String> row = new LinkedHashMap<>();
                    row.put("module", "EgovGateway");
                    row.put("path", p);
                    row.put("url", "http://127.0.0.1:" + gatewayPort + p);
                    candidates.add(row);
                }
            }

            for (Map.Entry<String, Integer> e : orderedRunning) {
                String module = e.getKey();
                Integer port = e.getValue();
                if (isManagerModule(module)) continue;
                for (String p : preferredPaths) {
                    Map<String, String> row = new LinkedHashMap<>();
                    row.put("module", module);
                    row.put("path", p);
                    row.put("url", "http://127.0.0.1:" + port + p);
                    candidates.add(row);
                }
            }

            for (Map<String, Object> m : mappings) {
                String module = str(m.get("module"));
                String method = str(m.get("method")).toUpperCase(Locale.ROOT);
                String path = str(m.get("path"));
                if (isManagerModule(module)) continue;
                if (path.isEmpty() || !path.startsWith("/")) continue;
                if (!"GET".equals(method)) continue;
                if (path.contains("{") || path.contains("*")) continue;
                String low = path.toLowerCase(Locale.ROOT);
                if (low.startsWith("/admin/msa") || low.startsWith("/error")
                        || low.contains("swagger") || low.contains("api-docs")) continue;
                if (!runningPorts.containsKey(module)) continue;

                if (gatewayPort > 0) {
                    Map<String, String> viaGateway = new LinkedHashMap<>();
                    viaGateway.put("module", "EgovGateway");
                    viaGateway.put("path", path);
                    viaGateway.put("url", "http://127.0.0.1:" + gatewayPort + path);
                    candidates.add(viaGateway);
                }

                Map<String, String> direct = new LinkedHashMap<>();
                direct.put("module", module);
                direct.put("path", path);
                direct.put("url", "http://127.0.0.1:" + runningPorts.get(module) + path);
                candidates.add(direct);
            }

            for (Map<String, String> c : candidates) {
                String url = str(c.get("url"));
                int code = doHttpGet(url, 1500);
                if (code >= 200 && code < 400) {
                    selectedUrl = url;
                    selectedPath = str(c.get("path"));
                    selectedModule = str(c.get("module"));
                    break;
                }
            }
        }

        if (selectedUrl.isEmpty() && gatewayPort > 0) {
            selectedPath = "/";
            selectedModule = "EgovGateway";
            selectedUrl = "http://127.0.0.1:" + gatewayPort + "/";
        }

        if (selectedUrl.isEmpty() && !runningPorts.isEmpty()) {
            List<Map.Entry<String, Integer>> orderedRunning = new ArrayList<>(runningPorts.entrySet());
            orderedRunning.sort((a, b) -> Integer.compare(modulePriority(a.getKey()), modulePriority(b.getKey())));
            for (Map.Entry<String, Integer> first : orderedRunning) {
                if (isManagerModule(first.getKey())) continue;
                selectedPath = "/";
                selectedModule = first.getKey();
                selectedUrl = "http://127.0.0.1:" + first.getValue() + "/";
                break;
            }
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("module", selectedModule);
        out.put("path", selectedPath);
        out.put("url", selectedUrl);
        out.put("gatewayPort", gatewayPort);
        return out;
    }

    private boolean isManagerModule(String module) {
        String id = module == null ? "" : module.toLowerCase(Locale.ROOT);
        return id.contains("msamanager");
    }

    private int modulePriority(String module) {
        String id = module == null ? "" : module.toLowerCase(Locale.ROOT);
        if (id.contains("egovhome")) return 0;
        if (id.contains("gateway")) return 1;
        if (id.contains("config")) return 3;
        if (id.contains("eureka")) return 4;
        if (id.contains("msamanager")) return 9;
        return 2;
    }

    private int doHttpGet(String url, int timeoutMs) {
        HttpURLConnection conn = null;
        try {
            URL u = new URL(url);
            conn = (HttpURLConnection) u.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(timeoutMs);
            conn.setReadTimeout(timeoutMs);
            conn.setUseCaches(false);
            conn.setRequestProperty("Connection", "close");
            int code = conn.getResponseCode();
            if (code >= 400) {
                if (conn.getErrorStream() != null) {
                    conn.getErrorStream().close();
                }
            } else {
                if (conn.getInputStream() != null) {
                    conn.getInputStream().close();
                }
            }
            return code;
        } catch (Exception ignored) {
            return -1;
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    private int boundedInt(Object v, int defaultValue, int min, int max) {
        int n = defaultValue;
        try {
            if (v != null) {
                n = Integer.parseInt(String.valueOf(v).trim());
            }
        } catch (Exception ignored) {
        }
        if (n < min) return min;
        if (n > max) return max;
        return n;
    }

    private double num(Object v) {
        if (v == null) return 0.0;
        try {
            return Double.parseDouble(String.valueOf(v));
        } catch (Exception e) {
            return 0.0;
        }
    }

    private double percentile(List<Long> values, double p) {
        if (values == null || values.isEmpty()) return 0.0;
        List<Long> copy = new ArrayList<>(values);
        Collections.sort(copy);
        int idx = (int) Math.ceil(copy.size() * p) - 1;
        idx = Math.max(0, Math.min(copy.size() - 1, idx));
        return copy.get(idx);
    }

    public Map<String, Object> getAccessibilityIssues() {
        List<Map<String, Object>> issues = new ArrayList<>();
        Map<String, Integer> severity = new LinkedHashMap<>();
        severity.put("high", 0);
        severity.put("medium", 0);
        severity.put("low", 0);

        Path root = Paths.get(MODULE_ROOT);
        if (!Files.isDirectory(root)) {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("total", 0);
            out.put("severity", severity);
            out.put("items", issues);
            return out;
        }

        AtomicInteger fileCount = new AtomicInteger();
        try (Stream<Path> stream = Files.walk(root, 12)) {
            stream.filter(Files::isRegularFile)
                    .filter(p -> p.toString().endsWith(".html"))
                    .filter(p -> p.toString().contains("/src/main/resources/"))
                    .forEach(path -> {
                        fileCount.incrementAndGet();
                        scanHtml(path, root, issues, severity);
                    });
        } catch (Exception ignored) {
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("scannedFiles", fileCount.get());
        out.put("total", issues.size());
        out.put("severity", severity);
        out.put("items", issues);
        return out;
    }

    private void scanHtml(Path path, Path root, List<Map<String, Object>> issues, Map<String, Integer> severity) {
        List<String> lines;
        try {
            lines = Files.readAllLines(path, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return;
        }

        String rel = root.relativize(path).toString().replace('\\', '/');
        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i);
            String lower = line.toLowerCase(Locale.ROOT);
            int lineNo = i + 1;

            if (lower.contains("<html") && !lower.contains("lang=")) {
                addIssue(issues, severity, "low", "LANG_MISSING", rel, lineNo,
                        "html 태그에 lang 속성이 없습니다.", line);
            }
            if (IMG_NO_ALT.matcher(line).find()) {
                addIssue(issues, severity, "high", "IMG_ALT_MISSING", rel, lineNo,
                        "img 태그에 alt 속성이 없습니다.", line);
            }
            Matcher inputMat = INPUT_TAG.matcher(line);
            while (inputMat.find()) {
                String tag = inputMat.group();
                String t = tag.toLowerCase(Locale.ROOT);
                if (t.contains("type=\"hidden\"") || t.contains(" type='hidden'")) {
                    continue;
                }
                boolean hasId = t.contains(" id=");
                boolean hasAria = t.contains(" aria-label=") || t.contains(" aria-labelledby=");
                if (!hasId && !hasAria) {
                    addIssue(issues, severity, "medium", "FORM_LABEL_WEAK", rel, lineNo,
                            "폼 요소에 id/aria-label이 없어 접근성 라벨 연결이 약합니다.", line);
                }
            }
            if (BUTTON_EMPTY.matcher(line).find()) {
                String t = line.toLowerCase(Locale.ROOT);
                if (!(t.contains("aria-label=") || t.contains("title="))) {
                    addIssue(issues, severity, "medium", "BUTTON_TEXT_MISSING", rel, lineNo,
                            "버튼에 텍스트 또는 aria-label이 없습니다.", line);
                }
            }
            if (A_EMPTY.matcher(line).find()) {
                addIssue(issues, severity, "medium", "LINK_TEXT_MISSING", rel, lineNo,
                        "링크 텍스트가 비어 있습니다.", line);
            }
        }
    }

    private void addIssue(List<Map<String, Object>> issues,
                          Map<String, Integer> severity,
                          String level,
                          String code,
                          String file,
                          int line,
                          String message,
                          String snippet) {
        Map<String, Object> item = new LinkedHashMap<>();
        item.put("severity", level);
        item.put("code", code);
        item.put("file", file);
        item.put("line", line);
        item.put("message", message);
        item.put("snippet", trimSnippet(snippet));
        issues.add(item);
        severity.put(level, severity.get(level) + 1);
    }

    private String trimSnippet(String s) {
        if (s == null) return "";
        String t = s.trim();
        return t.length() > 180 ? t.substring(0, 180) + "..." : t;
    }

    private String classifyGrade(String message) {
        String m = normalize(message);
        if (containsAny(m, "sql injection", "command injection", "rce", "privilege escalation", "authentication bypass")) {
            return "critical";
        }
        if (containsAny(m, "unauthorized", "forbidden", "csrf", "xss", "jwt", "token", "access denied", "bad credentials")) {
            return "high";
        }
        if (containsAny(m, "failed login", "invalid", "timeout", "warn", "suspicious")) {
            return "medium";
        }
        return "low";
    }

    private String classifyCategory(String message) {
        String m = normalize(message);
        if (containsAny(m, "sql", "query", "badsqlgrammar")) return "db/query";
        if (containsAny(m, "jwt", "token", "oauth", "auth", "login")) return "auth";
        if (containsAny(m, "xss", "csrf", "script")) return "web-threat";
        if (containsAny(m, "forbidden", "unauthorized", "access denied")) return "authorization";
        if (containsAny(m, "secret", "password", "api key", "private key")) return "secrets";
        return "general";
    }

    private String normalize(String s) {
        return s == null ? "" : s.toLowerCase(Locale.ROOT);
    }

    private boolean containsAny(String src, String... needles) {
        if (src == null) return false;
        for (String n : needles) {
            if (src.contains(n)) {
                return true;
            }
        }
        return false;
    }

    private LocalDateTime parseTime(String raw) {
        if (raw == null || raw.trim().isEmpty()) return null;
        try {
            return LocalDateTime.parse(raw.trim(), TS_FMT);
        } catch (Exception e) {
            return null;
        }
    }

    private List<Map<String, Object>> loadMappings() {
        File file = resolveFirstExisting(MAPPING_FILE_CANDIDATES);
        if (!file.exists()) {
            return Collections.emptyList();
        }
        try {
            Yaml yaml = new Yaml();
            Map<String, Object> obj = yaml.load(new FileInputStream(file));
            Object raw = obj.get("mappings");
            if (!(raw instanceof List)) {
                return Collections.emptyList();
            }
            List<Map<String, Object>> out = new ArrayList<>();
            for (Object o : (List<?>) raw) {
                if (o instanceof Map) {
                    out.add(new LinkedHashMap<>((Map<String, Object>) o));
                }
            }
            return out;
        } catch (Exception e) {
            return Collections.emptyList();
        }
    }

    private File resolveFirstExisting(List<String> candidates) {
        for (String path : candidates) {
            File f = new File(path);
            if (f.exists()) {
                return f;
            }
        }
        return new File(candidates.get(0));
    }

    private Integer readRssMbByPort(Integer port) {
        if (port == null || port == 0) return null;
        String line = readFirstLine(Arrays.asList("sh", "-c",
                "ps -eo pid,rss,args --no-headers | awk '$3==\"java\" && index($0,\"--server.port=" + port + "\")>0 {print $0; exit}'"));
        if (line == null || line.trim().isEmpty()) return null;
        String[] arr = line.trim().split("\\s+", 3);
        if (arr.length < 2) return null;
        try {
            long kb = Long.parseLong(arr[1]);
            return (int) (kb / 1024L);
        } catch (Exception e) {
            return null;
        }
    }

    private Double readCpuPctByPort(Integer port) {
        if (port == null || port == 0) return null;
        String line = readFirstLine(Arrays.asList("sh", "-c",
                "ps -eo pcpu,args --no-headers | awk '$2==\"java\" && index($0,\"--server.port=" + port + "\")>0 {print $1; exit}'"));
        if (line == null || line.trim().isEmpty()) return null;
        try {
            return Double.parseDouble(line.trim());
        } catch (Exception e) {
            return null;
        }
    }

    private Integer readEstablishedConnByPort(Integer port) {
        if (port == null || port == 0) return 0;
        String line = readFirstLine(Arrays.asList("sh", "-c",
                "ss -tan | awk '$1==\"ESTAB\" && $4 ~ /:" + port + "$/ {c++} END{print c+0}'"));
        if (line == null || line.trim().isEmpty()) return 0;
        try {
            return Integer.parseInt(line.trim());
        } catch (Exception e) {
            return 0;
        }
    }

    private String readFirstLine(List<String> cmd) {
        try {
            Process p = new ProcessBuilder(cmd).start();
            try (BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                String line = br.readLine();
                p.waitFor();
                return line;
            }
        } catch (Exception e) {
            return null;
        }
    }

    private double round2(double v) {
        return Math.round(v * 100.0) / 100.0;
    }

    private static final class SecurityRule {
        private final String level;
        private final String code;
        private final String grade;
        private final String category;
        private final Pattern pattern;
        private final List<String> exts;

        private SecurityRule(String level, String code, String grade, String category, Pattern pattern, String... exts) {
            this.level = level;
            this.code = code;
            this.grade = grade;
            this.category = category;
            this.pattern = pattern;
            this.exts = exts == null ? Collections.emptyList() : Arrays.asList(exts);
        }

        private boolean matchesExt(String pathLower) {
            if (exts.isEmpty()) {
                return true;
            }
            for (String ext : exts) {
                if (pathLower.endsWith(ext)) {
                    return true;
                }
            }
            return false;
        }
    }
}
