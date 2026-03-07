package egovframework.com.msa.manager;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Stream;

@Service
public class ChangeMonitorService {
    private static final Path LOG_DIR = AppPaths.logsDir();
    private static final Path AI_EDIT_LOCK_FILE = AppPaths.resolvePath(".ai-edit.lock");
    private static final Path STATE_FILE = LOG_DIR.resolve("msa-autodeploy-state.properties");
    private static final Path HISTORY_LOG_FILE = LOG_DIR.resolve("change-history.jsonl");
    private static final Path RUNTIME_CONFIG_FILE = LOG_DIR.resolve("msa-runtime.properties");
    private static final String MODE_DEV = "development";
    private static final String MODE_PROD = "production";
    private static final int MAX_HISTORY = 300;
    private static final long SCAN_INTERVAL_MS = 8000L;
    private static final long MODULE_COOLDOWN_MS = 45000L;
    private static final int MAX_DIFF_LINES = 240;
    private static final int MAX_TEXT_FILE_BYTES = 512 * 1024;
    private static final int MAX_TEXT_LINES = 2500;

    @Autowired
    private MsaProcessManager processManager;

    private final MsaScanner scanner = new MsaScanner();
    private final AtomicBoolean autoDeployEnabled = new AtomicBoolean(false); // 운영 기본: OFF
    private final AtomicBoolean managerAutoDeployEnabled = new AtomicBoolean(false); // self-loop 위험으로 기본 OFF
    private final AtomicBoolean running = new AtomicBoolean(true);
    private final ExecutorService loopExec = Executors.newSingleThreadExecutor();
    private final ExecutorService deployExec = Executors.newSingleThreadExecutor();

    private final Map<String, Map<String, FileMeta>> fileStateByModule = new ConcurrentHashMap<>();
    private final Map<String, Long> lastDeployAt = new ConcurrentHashMap<>();
    private final Set<String> deployingModules = ConcurrentHashMap.newKeySet();
    private final Deque<Map<String, Object>> history = new ArrayDeque<>();
    private final AtomicBoolean aiEditSessionActive = new AtomicBoolean(false);
    private volatile boolean aiPrevAutoDeployEnabled = false;
    private volatile boolean aiPrevManagerAutoDeployEnabled = false;
    private final Map<String, Map<String, FileMeta>> aiBaselineByModule = new ConcurrentHashMap<>();
    private static final DateTimeFormatter HISTORY_TS_FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private static class FileMeta {
        long modified;
        long size;
        boolean text;
        String digest;
        List<String> lines;
    }

    private static class ChangeSet {
        List<String> summary = new ArrayList<>();
        List<String> details = new ArrayList<>();
    }

    @PostConstruct
    public void init() {
        loadState();
        loopExec.submit(() -> {
            while (running.get()) {
                try {
                    syncAiEditSessionByLockFile();
                    scanOnce();
                    Thread.sleep(SCAN_INTERVAL_MS);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    break;
                } catch (Exception ignored) {
                }
            }
        });
    }

    @PreDestroy
    public void shutdown() {
        running.set(false);
        loopExec.shutdownNow();
        deployExec.shutdownNow();
    }

    public boolean isAutoDeployEnabled() {
        return autoDeployEnabled.get();
    }

    public boolean isManagerAutoDeployEnabled() {
        return managerAutoDeployEnabled.get();
    }

    public void setAutoDeployEnabled(boolean enabled) {
        autoDeployEnabled.set(enabled);
        saveState();
        addHistory("system", "AUTO_DEPLOY_" + (enabled ? "ON" : "OFF"), "자동 무중단 배포 " + (enabled ? "활성화" : "비활성화"),
                new ArrayList<>(), "ok");
    }

    public void setManagerAutoDeployEnabled(boolean enabled) {
        managerAutoDeployEnabled.set(enabled);
        saveState();
        addHistory("system", "AUTO_DEPLOY_MANAGER_" + (enabled ? "ON" : "OFF"),
                "MsaManager 자동 무중단 배포 대상 " + (enabled ? "포함" : "제외"),
                new ArrayList<>(), "ok");
    }

    public Map<String, Object> startAiEditSession() {
        Map<String, Object> out = new LinkedHashMap<>();
        if (!aiEditSessionActive.compareAndSet(false, true)) {
            out.put("status", "already_running");
            out.put("message", "AI 편집 세션이 이미 실행 중입니다.");
            out.put("autoDeployEnabled", autoDeployEnabled.get());
            out.put("managerEnabled", managerAutoDeployEnabled.get());
            return out;
        }

        aiPrevAutoDeployEnabled = autoDeployEnabled.get();
        aiPrevManagerAutoDeployEnabled = managerAutoDeployEnabled.get();

        List<MsaScanner.ModuleInfo> modules = scanner.scan();
        aiBaselineByModule.clear();
        for (MsaScanner.ModuleInfo mod : modules) {
            if (!mod.isJavaRunnable()) {
                continue;
            }
            Map<String, FileMeta> snap = collectModuleFiles(mod.getDir());
            aiBaselineByModule.put(mod.getId(), snap);
            fileStateByModule.put(mod.getId(), snap);
        }

        autoDeployEnabled.set(false);
        saveState();
        addHistory("system", "AI_EDIT_START",
                "AI 수정 시작: 자동 무중단 배포 일시 비활성화",
                new ArrayList<>(), "running");

        out.put("status", "ok");
        out.put("message", "AI 편집 세션 시작");
        out.put("autoDeployEnabled", autoDeployEnabled.get());
        out.put("managerEnabled", managerAutoDeployEnabled.get());
        out.put("prevAutoDeployEnabled", aiPrevAutoDeployEnabled);
        out.put("prevManagerEnabled", aiPrevManagerAutoDeployEnabled);
        out.put("baselineModules", aiBaselineByModule.size());
        return out;
    }

    public Map<String, Object> endAiEditSession(Boolean buildRequested) {
        Map<String, Object> out = new LinkedHashMap<>();
        if (!aiEditSessionActive.compareAndSet(true, false)) {
            out.put("status", "not_running");
            out.put("message", "실행 중인 AI 편집 세션이 없습니다.");
            out.put("autoDeployEnabled", autoDeployEnabled.get());
            out.put("managerEnabled", managerAutoDeployEnabled.get());
            return out;
        }

        List<MsaScanner.ModuleInfo> modules = scanner.scan();
        Map<String, MsaScanner.ModuleInfo> modById = new LinkedHashMap<>();
        List<String> changedModuleIds = new ArrayList<>();
        for (MsaScanner.ModuleInfo mod : modules) {
            if (!mod.isJavaRunnable()) {
                continue;
            }
            if ("EgovMsaManager".equals(mod.getId()) && !aiPrevManagerAutoDeployEnabled) {
                continue;
            }
            Map<String, FileMeta> baseline = aiBaselineByModule.get(mod.getId());
            Map<String, FileMeta> now = collectModuleFiles(mod.getDir());
            fileStateByModule.put(mod.getId(), now);
            if (baseline == null) {
                continue;
            }
            ChangeSet cs = diff(baseline, now);
            if (!cs.summary.isEmpty()) {
                changedModuleIds.add(mod.getId());
                modById.put(mod.getId(), mod);
                addHistory(mod.getId(), "AI_EDIT_CHANGE",
                        "AI 세션 변경 감지 (" + cs.summary.size() + "건)", cs.details, "detected");
            }
        }

        boolean buildAllowed = isBuildAllowed();
        boolean useBuild = (buildRequested == null) ? buildAllowed : buildRequested.booleanValue();
        List<Map<String, String>> deployResults = new ArrayList<>();

        for (String id : changedModuleIds) {
            MsaScanner.ModuleInfo mod = modById.get(id);
            if (mod == null) {
                continue;
            }
            Map<String, String> row = new LinkedHashMap<>();
            row.put("module", id);
            if (!deployingModules.add(id)) {
                row.put("status", "skipped");
                row.put("message", "이미 배포 중");
                deployResults.add(row);
                continue;
            }
            try {
                addHistory(id, "AI_EDIT_DEPLOY_START",
                        "AI 수정 종료 배포 시작 (" + (useBuild ? "build+무중단" : "deploy-only+무중단") + ")",
                        new ArrayList<>(), "running");
                String res = useBuild
                        ? processManager.buildDeployZeroDowntimeModule(mod)
                        : processManager.deployZeroDowntimeModule(mod);
                if ("ok".equals(res)) {
                    lastDeployAt.put(id, System.currentTimeMillis());
                    row.put("status", "ok");
                    row.put("message", "배포 완료");
                    addHistory(id, "AI_EDIT_DEPLOY_DONE", "AI 수정 종료 자동 무중단 배포 완료",
                            new ArrayList<>(), "ok");
                } else {
                    row.put("status", "error");
                    row.put("message", res);
                    addHistory(id, "AI_EDIT_DEPLOY_FAIL", res, new ArrayList<>(), "error");
                }
            } finally {
                deployingModules.remove(id);
                deployResults.add(row);
            }
        }

        autoDeployEnabled.set(aiPrevAutoDeployEnabled);
        managerAutoDeployEnabled.set(aiPrevManagerAutoDeployEnabled);
        saveState();
        aiBaselineByModule.clear();
        addHistory("system", "AI_EDIT_END",
                "AI 수정 종료: 자동 무중단 배포 설정 복구 (enabled=" + aiPrevAutoDeployEnabled + ")",
                new ArrayList<>(), "ok");

        out.put("status", "ok");
        out.put("message", "AI 편집 세션 종료");
        out.put("changedModules", changedModuleIds);
        out.put("deployMode", useBuild ? "build+zero-downtime" : "deploy-only+zero-downtime");
        out.put("buildAllowed", buildAllowed);
        out.put("results", deployResults);
        out.put("autoDeployEnabled", autoDeployEnabled.get());
        out.put("managerEnabled", managerAutoDeployEnabled.get());
        return out;
    }

    private void syncAiEditSessionByLockFile() {
        boolean lockExists = Files.exists(AI_EDIT_LOCK_FILE);
        boolean active = aiEditSessionActive.get();
        if (lockExists && !active) {
            startAiEditSession();
            return;
        }
        if (!lockExists && active) {
            endAiEditSession(null);
        }
    }

    public List<Map<String, Object>> getHistory() {
        return getHistory(null, null);
    }

    public List<Map<String, Object>> getHistory(LocalDateTime from, LocalDateTime to) {
        synchronized (history) {
            if (from == null && to == null) {
                return new ArrayList<>(history);
            }
            List<Map<String, Object>> filtered = new ArrayList<>();
            for (Map<String, Object> row : history) {
                if (inRange(row, from, to)) {
                    filtered.add(row);
                }
            }
            return filtered;
        }
    }

    private boolean inRange(Map<String, Object> row, LocalDateTime from, LocalDateTime to) {
        LocalDateTime t = parseRowTime(row);
        if (t == null) {
            return true;
        }
        if (from != null && t.isBefore(from)) {
            return false;
        }
        if (to != null && t.isAfter(to)) {
            return false;
        }
        return true;
    }

    private LocalDateTime parseRowTime(Map<String, Object> row) {
        String raw = String.valueOf(row.get("time"));
        if (raw == null || raw.trim().isEmpty() || "null".equals(raw)) {
            return null;
        }
        try {
            return LocalDateTime.parse(raw.trim(), HISTORY_TS_FMT);
        } catch (Exception ignored) {
            return null;
        }
    }

    private void scanOnce() {
        List<MsaScanner.ModuleInfo> modules = scanner.scan();
        for (MsaScanner.ModuleInfo mod : modules) {
            if (!mod.isJavaRunnable()) {
                continue;
            }
            if ("EgovMsaManager".equals(mod.getId()) && !managerAutoDeployEnabled.get()) {
                // Manager self-redeploy loop risk: keep manual control for this module.
                continue;
            }
            Map<String, FileMeta> prev = fileStateByModule.get(mod.getId());
            Map<String, FileMeta> now = collectModuleFiles(mod.getDir());
            if (prev == null) {
                fileStateByModule.put(mod.getId(), now);
                continue;
            }

            ChangeSet changes = diff(prev, now);
            fileStateByModule.put(mod.getId(), now);
            if (changes.summary.isEmpty()) {
                continue;
            }

            addHistory(mod.getId(), "FILE_CHANGE", "수정 감지 (" + changes.summary.size() + "건)", changes.details, "detected");
            triggerAutoDeployIfEnabled(mod, changes.summary.size());
        }
    }

    private void triggerAutoDeployIfEnabled(MsaScanner.ModuleInfo mod, int changeCount) {
        if (!autoDeployEnabled.get()) {
            return;
        }
        String id = mod.getId();
        long now = System.currentTimeMillis();
        long last = lastDeployAt.getOrDefault(id, 0L);
        if (now - last < MODULE_COOLDOWN_MS) {
            return;
        }
        if (!deployingModules.add(id)) {
            return;
        }

        deployExec.submit(() -> {
            try {
                addHistory(id, "AUTO_DEPLOY_START",
                        "자동 무중단 배포 시작 (변경 " + changeCount + "건)", new ArrayList<>(), "running");
                boolean buildAllowed = isBuildAllowed();
                addHistory(id, "AUTO_DEPLOY_MODE",
                        buildAllowed ? "전략: build+deploy+무중단" : "전략: deploy-only+무중단(운영 보호)",
                        new ArrayList<>(), "running");
                String res = buildAllowed
                        ? processManager.buildDeployZeroDowntimeModule(mod)
                        : processManager.deployZeroDowntimeModule(mod);
                if ("ok".equals(res)) {
                    lastDeployAt.put(id, System.currentTimeMillis());
                    addHistory(id, "AUTO_DEPLOY_DONE", "자동 무중단 배포 완료", new ArrayList<>(), "ok");
                } else {
                    addHistory(id, "AUTO_DEPLOY_FAIL", res, new ArrayList<>(), "error");
                }
            } finally {
                deployingModules.remove(id);
            }
        });
    }

    private Map<String, FileMeta> collectModuleFiles(String moduleDir) {
        Path root = Paths.get(moduleDir);
        Map<String, FileMeta> map = new HashMap<>();
        if (!Files.isDirectory(root)) {
            return map;
        }
        try (Stream<Path> s = Files.walk(root, 8)) {
            s.filter(Files::isRegularFile)
                    .filter(p -> !isIgnoredPath(root, p))
                    .filter(p -> isDockerCopiedRelevantPath(root, p))
                    .forEach(p -> {
                        try {
                            String rel = root.relativize(p).toString().replace('\\', '/');
                            map.put(rel, readFileMeta(p, rel));
                        } catch (Exception ignored) {
                        }
                    });
        } catch (Exception ignored) {
        }
        return map;
    }

    private boolean isIgnoredPath(Path root, Path p) {
        String rel = root.relativize(p).toString().replace('\\', '/');
        String l = rel.toLowerCase();
        if (l.startsWith("target/") || l.startsWith(".git/") || l.startsWith("node_modules/")
                || l.startsWith(".idea/") || l.startsWith(".vscode/") || l.startsWith(".settings/")
                || l.startsWith(".metadata/") || l.startsWith("logs/") || l.startsWith("log/")
                || l.startsWith("tmp/") || l.startsWith("temp/") || l.startsWith("run/")
                || l.startsWith("data/") || l.startsWith("backup/")) {
            return true;
        }
        if (l.endsWith(".log") || l.endsWith(".out") || l.endsWith(".pid") || l.endsWith(".lock")
                || l.endsWith(".tmp") || l.endsWith(".swp") || l.endsWith(".swo")
                || l.endsWith(".class")) {
            return true;
        }
        return l.contains("/.ds_store")
                || l.contains("/.git/")
                || l.contains("/.svn/")
                || l.contains("/.cache/")
                || l.contains("/.mvn/wrapper/maven-wrapper.jar")
                || l.contains("/startup.log");
    }

    private boolean isDockerCopiedRelevantPath(Path root, Path p) {
        // Root Dockerfile copies /opt/carbosys/module into image.
        // Track files that impact runtime/build, exclude system noise.
        String rel = root.relativize(p).toString().replace('\\', '/');
        String l = rel.toLowerCase();
        if ("pom.xml".equals(l) || "dockerfile".equals(l) || "mvnw".equals(l) || "mvnw.cmd".equals(l)
                || "build.gradle".equals(l) || "build.gradle.kts".equals(l)
                || "settings.gradle".equals(l) || "settings.gradle.kts".equals(l)
                || "package.json".equals(l) || "package-lock.json".equals(l) || "yarn.lock".equals(l)) {
            return true;
        }
        return l.startsWith("src/") || l.startsWith(".mvn/") || l.startsWith("gradle/");
    }

    private FileMeta readFileMeta(Path p, String rel) {
        FileMeta m = new FileMeta();
        try {
            m.modified = Files.getLastModifiedTime(p).toMillis();
            m.size = Files.size(p);
        } catch (Exception ignored) {
        }
        m.text = isTextFile(rel) && m.size <= MAX_TEXT_FILE_BYTES;
        if (m.text) {
            List<String> lines = new ArrayList<>();
            try (BufferedReader br = new BufferedReader(new InputStreamReader(Files.newInputStream(p), StandardCharsets.UTF_8))) {
                String line;
                while ((line = br.readLine()) != null) {
                    lines.add(line);
                    if (lines.size() >= MAX_TEXT_LINES) {
                        break;
                    }
                }
            } catch (Exception ignored) {
                m.text = false;
                lines.clear();
            }
            if (m.text) {
                m.lines = lines;
                m.digest = sha256(String.join("\n", lines));
            }
        }
        return m;
    }

    private boolean isTextFile(String rel) {
        String l = rel.toLowerCase();
        return l.endsWith(".java") || l.endsWith(".js") || l.endsWith(".ts") || l.endsWith(".jsx")
                || l.endsWith(".tsx") || l.endsWith(".xml") || l.endsWith(".yml") || l.endsWith(".yaml")
                || l.endsWith(".properties") || l.endsWith(".html") || l.endsWith(".css")
                || l.endsWith(".md") || l.endsWith(".txt") || l.endsWith(".sql") || l.endsWith(".json")
                || l.endsWith(".sh");
    }

    private String sha256(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest(s.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : d) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    private ChangeSet diff(Map<String, FileMeta> prev, Map<String, FileMeta> now) {
        ChangeSet cs = new ChangeSet();

        for (Map.Entry<String, FileMeta> e : now.entrySet()) {
            String path = e.getKey();
            FileMeta newer = e.getValue();
            FileMeta older = prev.get(path);
            if (older == null) {
                cs.summary.add("+ " + path);
                appendAddDeleteDetail(cs.details, "ADD", path, null, newer);
                continue;
            }
            if (isChanged(older, newer)) {
                cs.summary.add("~ " + path);
                appendModifyDetail(cs.details, path, older, newer);
            }
        }
        for (Map.Entry<String, FileMeta> e : prev.entrySet()) {
            String path = e.getKey();
            if (!now.containsKey(path)) {
                cs.summary.add("- " + path);
                appendAddDeleteDetail(cs.details, "DELETE", path, e.getValue(), null);
            }
        }

        if (cs.summary.size() > 50) {
            cs.summary = cs.summary.subList(0, 50);
        }
        if (cs.details.size() > MAX_DIFF_LINES) {
            cs.details = new ArrayList<>(cs.details.subList(0, MAX_DIFF_LINES));
            cs.details.add("... (상세 diff 생략)");
        }
        return cs;
    }

    private boolean isChanged(FileMeta older, FileMeta newer) {
        if (older.text && newer.text && older.digest != null && newer.digest != null) {
            return !older.digest.equals(newer.digest);
        }
        return older.size != newer.size || older.modified != newer.modified;
    }

    private void appendAddDeleteDetail(List<String> out, String kind, String path, FileMeta older, FileMeta newer) {
        out.add("[" + kind + "] " + path);
        FileMeta m = "ADD".equals(kind) ? newer : older;
        if (m != null && m.text && m.lines != null) {
            int max = Math.min(12, m.lines.size());
            for (int i = 0; i < max; i++) {
                out.add(("ADD".equals(kind) ? "+ " : "- ") + m.lines.get(i));
            }
            if (m.lines.size() > max) {
                out.add("... (" + (m.lines.size() - max) + " lines more)");
            }
        } else if (m != null) {
            out.add("  (binary/large file, size=" + m.size + ")");
        }
    }

    private void appendModifyDetail(List<String> out, String path, FileMeta older, FileMeta newer) {
        out.add("[MOD] " + path);
        if (!(older.text && newer.text) || older.lines == null || newer.lines == null) {
            out.add("  size: " + older.size + " -> " + newer.size + ", mtime changed");
            return;
        }
        appendLineDiff(out, older.lines, newer.lines);
    }

    private void appendLineDiff(List<String> out, List<String> oldLines, List<String> newLines) {
        int i = 0;
        int j = 0;
        int hunks = 0;
        while (i < oldLines.size() || j < newLines.size()) {
            if (i < oldLines.size() && j < newLines.size() && oldLines.get(i).equals(newLines.get(j))) {
                i++;
                j++;
                continue;
            }
            if (hunks >= 6) {
                out.add("  ... (추가 변경 생략)");
                return;
            }
            out.add(String.format("@@ old:%d new:%d @@", i + 1, j + 1));
            for (int k = 0; k < 4 && i < oldLines.size(); k++, i++) {
                out.add("- " + oldLines.get(i));
            }
            for (int k = 0; k < 4 && j < newLines.size(); k++, j++) {
                out.add("+ " + newLines.get(j));
            }
            hunks++;
        }
    }

    private void addHistory(String moduleId, String type, String message, List<String> details, String status) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("time", LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
        row.put("module", moduleId);
        row.put("type", type);
        row.put("message", message);
        row.put("details", details);
        row.put("status", status);
        synchronized (history) {
            history.addFirst(row);
            while (history.size() > MAX_HISTORY) {
                history.removeLast();
            }
        }
        appendHistoryFile(row);
    }

    private void appendHistoryFile(Map<String, Object> row) {
        try {
            Files.createDirectories(HISTORY_LOG_FILE.getParent());
            String line = toJsonLine(row) + System.lineSeparator();
            Files.write(HISTORY_LOG_FILE, line.getBytes(StandardCharsets.UTF_8),
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (Exception ignored) {
        }
    }

    private String toJsonLine(Map<String, Object> row) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"time\":\"").append(esc(String.valueOf(row.get("time")))).append("\",");
        sb.append("\"module\":\"").append(esc(String.valueOf(row.get("module")))).append("\",");
        sb.append("\"type\":\"").append(esc(String.valueOf(row.get("type")))).append("\",");
        sb.append("\"message\":\"").append(esc(String.valueOf(row.get("message")))).append("\",");
        sb.append("\"status\":\"").append(esc(String.valueOf(row.get("status")))).append("\",");
        sb.append("\"details\":[");
        @SuppressWarnings("unchecked")
        List<String> details = (List<String>) row.get("details");
        for (int i = 0; i < details.size(); i++) {
            if (i > 0) {
                sb.append(",");
            }
            sb.append("\"").append(esc(details.get(i))).append("\"");
        }
        sb.append("]}");
        return sb.toString();
    }

    private String esc(String s) {
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    private void loadState() {
        Properties p = new Properties();
        if (!Files.exists(STATE_FILE)) {
            return;
        }
        try (FileInputStream in = new FileInputStream(STATE_FILE.toFile())) {
            p.load(in);
            autoDeployEnabled.set(Boolean.parseBoolean(p.getProperty("autoDeployEnabled", "false")));
            managerAutoDeployEnabled.set(Boolean.parseBoolean(p.getProperty("managerAutoDeployEnabled", "false")));
        } catch (Exception ignored) {
        }
    }

    private void saveState() {
        Properties p = new Properties();
        p.setProperty("autoDeployEnabled", String.valueOf(autoDeployEnabled.get()));
        p.setProperty("managerAutoDeployEnabled", String.valueOf(managerAutoDeployEnabled.get()));
        try {
            Files.createDirectories(LOG_DIR);
        } catch (IOException ignored) {
        }
        try (FileOutputStream out = new FileOutputStream(STATE_FILE.toFile())) {
            p.store(out, "msa manager runtime state");
        } catch (IOException ignored) {
        }
    }

    private boolean isBuildAllowed() {
        Properties p = new Properties();
        if (Files.exists(RUNTIME_CONFIG_FILE)) {
            try (FileInputStream in = new FileInputStream(RUNTIME_CONFIG_FILE.toFile())) {
                p.load(in);
            } catch (Exception ignored) {
            }
        }
        String mode = normalizeMode(p.getProperty("serverMode", ""));
        if (mode.isEmpty()) {
            mode = normalizeMode(System.getenv("MSA_SERVER_MODE"));
        }
        if (mode.isEmpty()) {
            String profile = String.valueOf(System.getenv("SPRING_PROFILES_ACTIVE")).toLowerCase();
            if (profile.contains("prod") || profile.contains("release")) {
                mode = MODE_PROD;
            } else {
                mode = MODE_DEV;
            }
        }
        return !MODE_PROD.equals(mode);
    }

    private String normalizeMode(String raw) {
        String v = raw == null ? "" : raw.trim().toLowerCase();
        if ("prod".equals(v) || "production".equals(v) || "운영".equals(v)) {
            return MODE_PROD;
        }
        if ("dev".equals(v) || "development".equals(v) || "개발".equals(v)) {
            return MODE_DEV;
        }
        return "";
    }
}
