package egovframework.com.msa.manager;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Collectors;

@Service
public class MsaProcessManager {
    private static final String APP_ROOT = AppPaths.root();
    private static final String DEFAULT_XMS = "64m";
    private static final String DEFAULT_XMX = "256m";
    private final Map<String, ProcessEntry> processMap = new ConcurrentHashMap<>();
    private final RestTemplate restTemplate = new RestTemplate();

    public static class ProcessEntry {
        public Process process;
        public List<String> logs = new CopyOnWriteArrayList<>();
        public String status = "stopped";
        public Long pid;

        public void addLog(String line) {
            logs.add(line);
            if (logs.size() > 500)
                logs.remove(0);
        }
    }

    private static class LaunchSpec {
        final List<String> command;
        final File workDir;
        final String mode;

        LaunchSpec(List<String> command, File workDir, String mode) {
            this.command = command;
            this.workDir = workDir;
            this.mode = mode;
        }
    }

    public synchronized void startModule(MsaScanner.ModuleInfo mod) {
        if (mod == null || mod.getId() == null) {
            return;
        }
        if (mod.getPort() != null && mod.getPort() != 0 && isPortInUse(mod.getPort())) {
            return;
        }
        if (processMap.containsKey(mod.getId())) {
            ProcessEntry existing = processMap.get(mod.getId());
            if (existing != null && ("starting".equals(existing.status) || "running".equals(existing.status))) {
                return;
            }
            processMap.remove(mod.getId());
        }

        ProcessEntry entry = new ProcessEntry();
        entry.status = "starting";
        processMap.put(mod.getId(), entry);

        new Thread(() -> {
            try {
                LaunchSpec spec = resolveLaunchSpec(mod, mod.getPort());
                ProcessBuilder pb = new ProcessBuilder(spec.command);
                pb.directory(spec.workDir);
                pb.redirectErrorStream(true);
                pb.environment().put("JAVA_OPTS", "-Djava.awt.headless=true");
                entry.addLog("[System] launch mode=" + spec.mode + " cmd=" + String.join(" ", spec.command));

                Process proc = pb.start();
                entry.process = proc;
                entry.pid = getPid(proc);

                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(proc.getInputStream(), StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        entry.addLog(line);
                        appendToStartupLog(mod.getDir(), line);

                        if ((line.contains("Started ") && line.contains("seconds"))
                                || (mod.getPort() != null && mod.getPort() != 0 && isPortInUse(mod.getPort()))) {
                            entry.status = "running";
                        }
                    }
                }
                int rc = proc.waitFor();
                if (!"stopped".equals(entry.status)) {
                    entry.addLog("[System] process exited code=" + rc);
                }
            } catch (Exception e) {
                entry.addLog("Error: " + e.getMessage());
                entry.status = "error";
            } finally {
                entry.status = "stopped";
                processMap.remove(mod.getId());
            }
        }).start();
    }

    public synchronized void restartModule(MsaScanner.ModuleInfo mod) {
        stopModule(mod.getId(), mod.getPort());
        try {
            Thread.sleep(1200);
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        }
        startModule(mod);
    }

    public synchronized String deployAndRestartModule(MsaScanner.ModuleInfo mod) {
        if (!mod.isJavaRunnable()) {
            return "이 모듈은 Java 실행 대상이 아닙니다.";
        }
        if (isSelfModule(mod)) {
            String deployResult = deployModuleJar(mod);
            if (!"ok".equals(deployResult)) {
                return deployResult;
            }
            return scheduleSelfRestart(mod);
        }
        String deployResult = deployModuleJar(mod);
        if (!"ok".equals(deployResult)) {
            return deployResult;
        }
        restartModule(mod);
        return "ok";
    }

    public synchronized String buildDeployAndRestartModule(MsaScanner.ModuleInfo mod) {
        if (!mod.isJavaRunnable()) {
            return "이 모듈은 Java 실행 대상이 아닙니다.";
        }

        String buildResult = buildModule(mod);
        if (!"ok".equals(buildResult)) {
            return buildResult;
        }

        return deployAndRestartModule(mod);
    }

    public synchronized String buildDeployZeroDowntimeModule(MsaScanner.ModuleInfo mod) {
        if (!mod.isJavaRunnable()) {
            return "이 모듈은 Java 실행 대상이 아닙니다.";
        }
        if (mod.getPort() == null || mod.getPort() == 0) {
            return "무중단 배포 실패: 기본 포트가 설정되어 있지 않습니다.";
        }

        String buildResult = buildModule(mod);
        if (!"ok".equals(buildResult)) {
            return buildResult;
        }
        return deployZeroDowntimeModule(mod);
    }

    public synchronized String deployZeroDowntimeModule(MsaScanner.ModuleInfo mod) {
        if (!mod.isJavaRunnable()) {
            return "이 모듈은 Java 실행 대상이 아닙니다.";
        }
        // Self zero-downtime is not safe: control process can terminate mid-switch.
        // Fallback to normal deploy+restart for manager itself.
        if (isSelfModule(mod)) {
            appendToStartupLog(mod.getDir(), "[ZD] self module fallback -> deploy+restart");
            return deployAndRestartModule(mod);
        }
        if (mod.getPort() == null || mod.getPort() == 0) {
            return "무중단 배포 실패: 기본 포트가 설정되어 있지 않습니다.";
        }

        String deployResult = deployModuleJar(mod);
        if (!"ok".equals(deployResult)) {
            return deployResult;
        }

        int basePort = mod.getPort();
        int shadowPort = pickShadowPort(basePort);
        if (shadowPort <= 0) {
            return "무중단 배포 실패: 임시 포트를 찾지 못했습니다.";
        }

        Process shadowProc = null;
        try {
            appendToStartupLog(mod.getDir(), "[ZD] shadow start: port=" + shadowPort);
            shadowProc = startUntrackedProcess(mod, shadowPort, "[ZD-SHADOW]");

            if (!waitForHealthy(shadowPort, 70000)) {
                if (shadowProc != null && shadowProc.isAlive()) {
                    shadowProc.destroyForcibly();
                }
                return "무중단 배포 실패: 임시 포트(" + shadowPort + ") 헬스체크 실패";
            }

            appendToStartupLog(mod.getDir(), "[ZD] shadow healthy: port=" + shadowPort);
            stopModule(mod.getId(), basePort);
            waitUntilPortClosed(basePort, 20000);

            // Avoid start race when old tracked entry is not yet removed from processMap.
            waitUntilEntryCleared(mod.getId(), 10000);
            startModule(mod);

            if (!waitForHealthy(basePort, 70000)) {
                if (shadowProc != null && shadowProc.isAlive()) {
                    appendToStartupLog(mod.getDir(), "[ZD] rollback: base unhealthy, shadow kept alive");
                    return "무중단 배포 실패: 기본 포트(" + basePort + ") 재기동 헬스체크 실패";
                }
                return "무중단 배포 실패: 기본 포트 헬스체크 실패";
            }

            // Promotion completed, stop shadow instance.
            stopByPort(shadowPort);
            appendToStartupLog(mod.getDir(), "[ZD] completed: base=" + basePort + ", shadowStopped=" + shadowPort);
            return "ok";
        } catch (Exception e) {
            if (shadowProc != null && shadowProc.isAlive()) {
                try {
                    shadowProc.destroyForcibly();
                } catch (Exception ignored) {
                }
            }
            return "무중단 배포 실패: " + e.getMessage();
        }
    }

    private void forceJdkForBuild(ProcessBuilder pb) {
        // Some base images run manager with JAVA_HOME pointing to JRE.
        // Build must run with JDK (javac/tools available).
        String[] candidates = {
                "/usr/lib/jvm/java-21-openjdk-amd64",
                "/usr/lib/jvm/java-17-openjdk-amd64",
                "/usr/lib/jvm/default-java"
        };
        for (String home : candidates) {
            File javac = new File(home + "/bin/javac");
            if (javac.exists()) {
                Map<String, String> env = pb.environment();
                env.put("JAVA_HOME", home);
                String path = env.getOrDefault("PATH", "");
                env.put("PATH", home + "/bin" + (path.isEmpty() ? "" : ":" + path));
                return;
            }
        }
    }

    private String buildModule(MsaScanner.ModuleInfo mod) {
        File moduleDir = resolveBuildableModuleDir(mod);
        if (moduleDir == null) {
            return "빌드 실패: pom.xml이 없습니다 - " + mod.getDir();
        }

        List<String> buildCmd = Arrays.asList("sh", "-lc", "mvn -DskipTests package");
        try {
            ProcessBuilder pb = new ProcessBuilder(buildCmd);
            pb.directory(moduleDir);
            pb.redirectErrorStream(true);
            forceJdkForBuild(pb);
            Process p = pb.start();
            List<String> lines = new ArrayList<>();
            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = br.readLine()) != null) {
                    lines.add(line);
                }
            }
            int rc = p.waitFor();
            for (String l : lines) {
                appendToStartupLog(mod.getDir(), "[BUILD] " + l);
            }
            if (rc != 0) {
                return "빌드 실패: mvn 종료코드 " + rc;
            }
            return "ok";
        } catch (Exception e) {
            return "빌드 실패: " + e.getMessage();
        }
    }

    private String deployModuleJar(MsaScanner.ModuleInfo mod) {
        Path sourceJar = resolveSourceJar(mod);
        if (!Files.exists(sourceJar)) {
            return "배포 실패: 소스 JAR 없음 - " + sourceJar;
        }

        Path appJar = Paths.get(APP_ROOT, mod.getArtifactId() + ".jar");
        Path appTargetDir = Paths.get(APP_ROOT, mod.getArtifactId(), "target");
        Path appTargetJar = appTargetDir.resolve(mod.getArtifactId() + ".jar");

        try {
            Files.createDirectories(appTargetDir);
            Files.copy(sourceJar, appJar, StandardCopyOption.REPLACE_EXISTING);
            try {
                Files.deleteIfExists(appTargetJar);
                Files.createSymbolicLink(appTargetJar, appJar);
            } catch (Exception symlinkErr) {
                Files.copy(appJar, appTargetJar, StandardCopyOption.REPLACE_EXISTING);
            }
            return "ok";
        } catch (Exception e) {
            return "배포 실패: " + e.getMessage();
        }
    }

    private boolean isSelfModule(MsaScanner.ModuleInfo mod) {
        if (mod == null) {
            return false;
        }
        return "EgovMsaManager".equals(mod.getId()) || "EgovMsaManager".equals(mod.getArtifactId());
    }

    private String scheduleSelfRestart(MsaScanner.ModuleInfo mod) {
        long selfPid = ProcessHandle.current().pid();
        int basePort = (mod.getPort() != null && mod.getPort() != 0) ? mod.getPort() : 18030;
        int shadowPort = pickShadowPort(basePort);
        if (shadowPort <= 0) {
            return "자기 재기동 예약 실패: 임시 포트를 찾지 못했습니다.";
        }
        String jarArg = resolveRunnableJar(mod);
        String xms = resolveXms(mod);
        String xmx = resolveXmx(mod);
        String startupLog = mod.getDir() + "/startup.log";

        String script = "nohup sh -c '"
                + "echo \"[SELF-ZD] shadow start: port=" + shadowPort + "\" >> " + startupLog + "; "
                + "cd " + APP_ROOT + " || exit 1; "
                + "java -Xms" + xms + " -Xmx" + xmx + " -jar " + jarArg + " --server.port=" + shadowPort
                + " >> " + startupLog + " 2>&1 & "
                + "shadow_pid=$!; "
                + "for i in $(seq 1 90); do "
                + "  ss -ltn | grep -q \":" + shadowPort + " \" && break; "
                + "  sleep 1; "
                + "done; "
                + "if ! ss -ltn | grep -q \":" + shadowPort + " \"; then "
                + "  echo \"[SELF-ZD] shadow failed: port=" + shadowPort + "\" >> " + startupLog + "; "
                + "  exit 1; "
                + "fi; "
                + "for i in $(seq 1 90); do "
                + "  curl -fsS http://localhost:" + shadowPort + "/admin/msa/api/modules >/dev/null 2>&1 && break; "
                + "  sleep 1; "
                + "done; "
                + "if ! curl -fsS http://localhost:" + shadowPort + "/admin/msa/api/modules >/dev/null 2>&1; then "
                + "  echo \"[SELF-ZD] shadow api failed: port=" + shadowPort + "\" >> " + startupLog + "; "
                + "  kill -15 $shadow_pid 2>/dev/null || true; "
                + "  sleep 1; "
                + "  kill -0 $shadow_pid 2>/dev/null && kill -9 $shadow_pid 2>/dev/null || true; "
                + "  exit 1; "
                + "fi; "
                + "echo \"[SELF-ZD] shadow healthy: port=" + shadowPort + "\" >> " + startupLog + "; "
                + "sleep 1; "
                + "kill -15 " + selfPid + " 2>/dev/null || true; "
                + "for i in $(seq 1 90); do "
                + "  ps -p " + selfPid + " >/dev/null 2>&1 || break; "
                + "  sleep 1; "
                + "done; "
                + "for i in $(seq 1 90); do "
                + "  ss -ltn | grep -q \":" + basePort + " \" || break; "
                + "  sleep 1; "
                + "done; "
                + "echo \"[SELF-ZD] base start: port=" + basePort + "\" >> " + startupLog + "; "
                + "java -Xms" + xms + " -Xmx" + xmx + " -jar " + jarArg + " --server.port=" + basePort
                + " >> " + startupLog + " 2>&1 & "
                + "for i in $(seq 1 90); do "
                + "  ss -ltn | grep -q \":" + basePort + " \" && break; "
                + "  sleep 1; "
                + "done; "
                + "if ! ss -ltn | grep -q \":" + basePort + " \"; then "
                + "  echo \"[SELF-ZD] base failed, shadow kept: port=" + shadowPort + "\" >> " + startupLog + "; "
                + "  exit 1; "
                + "fi; "
                + "for i in $(seq 1 90); do "
                + "  curl -fsS http://localhost:" + basePort + "/admin/msa/api/modules >/dev/null 2>&1 && break; "
                + "  sleep 1; "
                + "done; "
                + "if ! curl -fsS http://localhost:" + basePort + "/admin/msa/api/modules >/dev/null 2>&1; then "
                + "  echo \"[SELF-ZD] base api failed, shadow kept: port=" + shadowPort + "\" >> " + startupLog + "; "
                + "  exit 1; "
                + "fi; "
                + "echo \"[SELF-ZD] base healthy: port=" + basePort + "\" >> " + startupLog + "; "
                + "kill -15 $shadow_pid 2>/dev/null || true; "
                + "sleep 1; "
                + "kill -0 $shadow_pid 2>/dev/null && kill -9 $shadow_pid 2>/dev/null || true; "
                + "echo \"[SELF-ZD] completed: base=" + basePort + ", shadowStopped=" + shadowPort + "\" >> " + startupLog + "; "
                + "' >/dev/null 2>&1 &";
        try {
            new ProcessBuilder("sh", "-lc", script).start();
            appendToStartupLog(mod.getDir(),
                    "[SELF] restart scheduled: pid=" + selfPid + ", basePort=" + basePort + ", shadowPort=" + shadowPort + ", jar=" + jarArg);
            return "ok";
        } catch (Exception e) {
            return "자기 재기동 예약 실패: " + e.getMessage();
        }
    }

    private File resolveBuildableModuleDir(MsaScanner.ModuleInfo mod) {
        for (File candidate : moduleDirCandidates(mod)) {
            if (candidate.exists() && candidate.isDirectory() && new File(candidate, "pom.xml").exists()) {
                return candidate;
            }
        }
        return null;
    }

    private Path resolveSourceJar(MsaScanner.ModuleInfo mod) {
        for (File candidate : moduleDirCandidates(mod)) {
            Path jar = candidate.toPath().resolve("target").resolve(mod.getArtifactId() + ".jar");
            if (Files.exists(jar)) {
                return jar;
            }
        }
        return Paths.get(mod.getDir(), "target", mod.getArtifactId() + ".jar");
    }

    private List<File> moduleDirCandidates(MsaScanner.ModuleInfo mod) {
        String artifact = mod.getArtifactId();
        List<File> out = new ArrayList<>();
        out.add(new File(mod.getDir()));
        if (artifact != null && !artifact.trim().isEmpty()) {
            out.add(new File(AppPaths.moduleRoot(), artifact));
            out.add(new File(AppPaths.root(), artifact));
        }
        return out;
    }

    private Process startUntrackedProcess(MsaScanner.ModuleInfo mod, int port, String logPrefix) throws IOException {
        LaunchSpec spec = resolveLaunchSpec(mod, port);
        ProcessBuilder pb = new ProcessBuilder(spec.command);
        pb.directory(spec.workDir);
        pb.redirectErrorStream(true);
        pb.environment().put("JAVA_OPTS", "-Djava.awt.headless=true");
        Process proc = pb.start();
        appendToStartupLog(mod.getDir(),
                logPrefix + " launch mode=" + spec.mode + " cmd=" + String.join(" ", spec.command));

        new Thread(() -> {
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(proc.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    appendToStartupLog(mod.getDir(), logPrefix + " " + line);
                }
            } catch (Exception e) {
                appendToStartupLog(mod.getDir(), logPrefix + " log-reader-error: " + e.getMessage());
            }
        }).start();

        return proc;
    }

    private int pickShadowPort(int basePort) {
        int[] preferred = new int[] { basePort + 1000, basePort + 2000, basePort + 3000 };
        for (int p : preferred) {
            if (p > 0 && !isPortInUse(p)) {
                return p;
            }
        }
        for (int p = 20000; p <= 20999; p++) {
            if (!isPortInUse(p)) {
                return p;
            }
        }
        return -1;
    }

    private void stopByPort(int port) {
        try {
            String killCmd = "pids=$(ps -ef | grep -- '--server.port=" + port
                    + "' | grep -v grep | awk '{print $2}' || true); "
                    + "if [ -n \"$pids\" ]; then kill -15 $pids || true; sleep 1; "
                    + "for p in $pids; do kill -0 $p 2>/dev/null && kill -9 $p || true; done; fi";
            new ProcessBuilder("sh", "-c", killCmd).start().waitFor();
        } catch (Exception ignored) {
        }
    }

    private void waitUntilPortClosed(int port, long timeoutMs) {
        long end = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < end) {
            if (!isPortInUse(port)) {
                return;
            }
            try {
                Thread.sleep(400);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

    private void waitUntilEntryCleared(String id, long timeoutMs) {
        long end = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < end) {
            if (!processMap.containsKey(id)) {
                return;
            }
            try {
                Thread.sleep(300);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

    private boolean waitForHealthy(int port, long timeoutMs) {
        long end = System.currentTimeMillis() + timeoutMs;
        int stable = 0;
        while (System.currentTimeMillis() < end) {
            // Security filters can block actuator URL checks in some services.
            // Use stable TCP listen checks to avoid false negatives/noisy 403 logs.
            if (isPortInUse(port)) {
                stable++;
                if (stable >= 3) {
                    return true;
                }
            } else {
                stable = 0;
            }
            try {
                Thread.sleep(800);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
        return false;
    }


    private void appendToStartupLog(String dir, String line) {
        try (FileWriter fw = new FileWriter(new File(dir, "startup.log"), true);
                BufferedWriter bw = new BufferedWriter(fw)) {
            bw.write(line);
            bw.newLine();
        } catch (IOException e) {
            // ignore
        }
    }

    public void stopModule(String id, Integer port) {
        ProcessEntry entry = processMap.get(id);
        if (entry != null && entry.process != null) {
            entry.process.destroy();
            new Thread(() -> {
                try {
                    Thread.sleep(2000);
                    if (entry.process.isAlive())
                        entry.process.destroyForcibly();
                } catch (Exception e) {
                }
            }).start();
        }

        // Fallback: Kill by port if the process wasn't started by this manager or is
        // hanging
        if (port != null && port != 0) {
            try {
                String safeId = (id == null ? "" : id).replaceAll("[^A-Za-z0-9._-]", "");
                String p1 = AppPaths.root() + "/" + safeId + ".jar";
                String p2 = AppPaths.root() + "/" + safeId + "/target/" + safeId + ".jar";
                String p3 = AppPaths.moduleRoot() + "/" + safeId;
                // Minimal environments often don't include fuser/lsof.
                // Kill by --server.port arg first, then by module JAR path.
                String killCmd = "pids_port=$(ps -ef | grep -- '--server.port=" + port
                        + "' | grep -v grep | awk '{print $2}' || true); "
                        + "pids_jar=$(ps -eo pid,args | awk '$2==\"java\" && (index($0,\"" + p1
                        + "\")>0 || index($0,\"" + p2 + "\")>0) {print $1}' || true); "
                        + "pids_mvn=$(ps -eo pid,args | awk '$2 ~ /java$/ && (index($0,\"-Dmaven.multiModuleProjectDirectory="
                        + p3 + "\")>0 || index($0,\"" + p3 + "/target/classes\")>0) {print $1}' || true); "
                        + "pids=\"$pids_port $pids_jar $pids_mvn\"; "
                        + "if [ -n \"$pids\" ]; then kill -15 $pids 2>/dev/null || true; sleep 1; "
                        + "for p in $pids; do kill -0 $p 2>/dev/null && kill -9 $p 2>/dev/null || true; done; fi";
                new ProcessBuilder("sh", "-c", killCmd).start().waitFor();
            } catch (Exception e) {
                // ignore
            }
        }
    }

    public void stopAllInstances(MsaScanner.ModuleInfo mod) {
        // Stop tracked/base instance first.
        stopModule(mod.getId(), mod.getPort());

        // Kill any remaining same-module java instances (e.g., shadow port instance).
        try {
            String artifact = mod.getArtifactId().replaceAll("[^A-Za-z0-9._-]", "");
            String p1 = AppPaths.root() + "/" + artifact + "/target/" + artifact + ".jar";
            String p2 = AppPaths.root() + "/" + artifact + ".jar";
            String p3 = AppPaths.moduleRoot() + "/" + artifact;
            String killCmd = "pids1=$(ps -eo pid,args | awk '$2==\"java\" && index($0,\"" + p1
                    + "\")>0 {print $1}'); "
                    + "pids2=$(ps -eo pid,args | awk '$2==\"java\" && index($0,\"" + p2 + "\")>0 {print $1}'); "
                    + "pids3=$(ps -eo pid,args | awk '$2 ~ /java$/ && (index($0,\"-Dmaven.multiModuleProjectDirectory="
                    + p3 + "\")>0 || index($0,\"" + p3 + "/target/classes\")>0) {print $1}'); "
                    + "pids=\"$pids1 $pids2 $pids3\"; "
                    + "if [ -n \"$pids\" ]; then kill -15 $pids 2>/dev/null || true; sleep 1; "
                    + "for p in $pids; do kill -0 $p 2>/dev/null && kill -9 $p 2>/dev/null || true; done; fi";
            new ProcessBuilder("sh", "-c", killCmd).start().waitFor();
        } catch (Exception ignored) {
        }
    }

    public List<String> getLogs(String id, String dir, Integer port) {
        ProcessEntry entry = processMap.get(id);
        if (entry != null) {
            return new ArrayList<>(entry.logs);
        }

        List<String> extLogs = new ArrayList<>();
        File logFile = new File(dir, "startup.log");
        if (logFile.exists()) {
            extLogs.add("[System] Reading from existing startup.log...");
            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(new FileInputStream(logFile), StandardCharsets.UTF_8))) {
                List<String> allLines = br.lines().collect(Collectors.toList());
                int start = Math.max(0, allLines.size() - 200);
                extLogs.addAll(allLines.subList(start, allLines.size()));
                return extLogs;
            } catch (Exception e) {
                extLogs.add("Error reading log file: " + e.getMessage());
            }
        }

        if (port != null && port != 0) {
            try {
                String url = "http://localhost:" + port + "/actuator/logfile";
                String actuatorLogs = restTemplate.getForObject(url, String.class);
                if (actuatorLogs != null) {
                    extLogs.add("[System] Fetched from Actuator (Port " + port + ")");
                    String[] lines = actuatorLogs.split("\n");
                    int start = Math.max(0, lines.length - 200);
                    for (int i = start; i < lines.length; i++)
                        extLogs.add(lines[i]);
                    return extLogs;
                }
            } catch (Exception e) {
            }
        }
        return extLogs;
    }

    public String getStatus(String id, Integer port) {
        if (processMap.containsKey(id)) {
            return processMap.get(id).status;
        }
        if (port != null && port != 0) {
            if (isPortInUse(port))
                return "running";
        }
        return "stopped";
    }

    public Long getPid(String id) {
        ProcessEntry entry = processMap.get(id);
        return entry != null ? entry.pid : null;
    }

    private boolean isPortInUse(int port) {
        try (Socket s = new Socket("localhost", port)) {
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    private Long getPid(Process p) {
        try {
            java.lang.reflect.Field field = p.getClass().getDeclaredField("pid");
            field.setAccessible(true);
            return (Long) field.get(p);
        } catch (Exception e) {
            return null;
        }
    }

    private String resolveRunnableJar(MsaScanner.ModuleInfo mod) {
        Path appTargetJar = Paths.get(APP_ROOT, mod.getArtifactId(), "target", mod.getArtifactId() + ".jar");
        if (Files.exists(appTargetJar)) {
            return appTargetJar.toString();
        }
        Path appJar = Paths.get(APP_ROOT, mod.getArtifactId() + ".jar");
        if (Files.exists(appJar)) {
            return appJar.toString();
        }
        Path sourceJar = Paths.get(mod.getDir(), "target", mod.getArtifactId() + ".jar");
        if (Files.exists(sourceJar)) {
            return sourceJar.toString();
        }
        return appTargetJar.toString();
    }

    private LaunchSpec resolveLaunchSpec(MsaScanner.ModuleInfo mod, Integer overridePort) {
        String jarArg = resolveRunnableJar(mod);
        if (jarArg != null && Files.exists(Paths.get(jarArg))) {
            List<String> cmd = new ArrayList<>(Arrays.asList(
                    "java",
                    "-Xms" + resolveXms(mod),
                    "-Xmx" + resolveXmx(mod),
                    "-jar",
                    jarArg));
            if (overridePort != null && overridePort != 0) {
                cmd.add("--server.port=" + overridePort);
            }
            return new LaunchSpec(cmd, new File(APP_ROOT), "jar");
        }

        File moduleDir = resolveBuildableModuleDir(mod);
        if (moduleDir == null) {
            throw new IllegalStateException("실행 실패: JAR/POM을 찾지 못했습니다 - " + mod.getDir());
        }

        List<String> cmd = new ArrayList<>();
        cmd.add("mvn");
        cmd.add("spring-boot:run");
        if (overridePort != null && overridePort != 0) {
            cmd.add("-Dspring-boot.run.arguments=--server.port=" + overridePort);
        }
        return new LaunchSpec(cmd, moduleDir, "mvn");
    }

    private String resolveXms(MsaScanner.ModuleInfo mod) {
        String moduleId = mod == null ? "" : mod.getId();
        String byModule = readHeapEnv("MSA_JVM_" + normalizeModuleKey(moduleId) + "_XMS");
        if (byModule != null) {
            return byModule;
        }
        String global = readHeapEnv("MSA_JVM_DEFAULT_XMS");
        if (global != null) {
            return global;
        }
        if ("EgovMsaManager".equals(moduleId)) {
            return "256m";
        }
        if ("EgovHome".equals(moduleId)) {
            return "128m";
        }
        return DEFAULT_XMS;
    }

    private String resolveXmx(MsaScanner.ModuleInfo mod) {
        String moduleId = mod == null ? "" : mod.getId();
        String byModule = readHeapEnv("MSA_JVM_" + normalizeModuleKey(moduleId) + "_XMX");
        if (byModule != null) {
            return byModule;
        }
        String global = readHeapEnv("MSA_JVM_DEFAULT_XMX");
        if (global != null) {
            return global;
        }
        if ("EgovMsaManager".equals(moduleId)) {
            return "512m";
        }
        if ("EgovHome".equals(moduleId)) {
            return "384m";
        }
        return DEFAULT_XMX;
    }

    private String normalizeModuleKey(String moduleId) {
        if (moduleId == null) {
            return "";
        }
        return moduleId.replaceAll("[^A-Za-z0-9]", "").toUpperCase(Locale.ROOT);
    }

    private String readHeapEnv(String key) {
        try {
            String v = System.getenv(key);
            if (v == null || v.trim().isEmpty()) {
                return null;
            }
            String s = v.trim().toLowerCase(Locale.ROOT);
            if (!s.matches("\\d+[mg]")) {
                return null;
            }
            return s;
        } catch (Exception ignored) {
            return null;
        }
    }
}
