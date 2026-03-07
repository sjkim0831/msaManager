package egovframework.com.msa.manager;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.http.ResponseEntity;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.DumperOptions;

import javax.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;

@Controller
@RequestMapping("/admin/msa")
public class MsaController {

    @Autowired
    private MsaProcessManager processManager;

    @Autowired
    private ChangeMonitorService changeMonitorService;

    @Autowired
    private LogAnalyticsService logAnalyticsService;

    @Autowired
    private OpsInsightService opsInsightService;

    private final MsaScanner scanner = new MsaScanner();
    private static final String APP_ROOT = AppPaths.root();
    private static final List<String> MAPPING_FILE_CANDIDATES = Arrays.asList(
            AppPaths.resolvePath("msa-mappings.yml").toString());
    private static final DateTimeFormatter LOG_TIME_FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final String WEBHOOK_RUN_SCRIPT = AppPaths.resolvePath("scripts", "ci", "run_changed_modules_pipeline.sh").toString();
    private static final String WEBHOOK_LOG_FILE = AppPaths.resolvePath("logs", "msa-webhook.log").toString();
    private static final String WEBHOOK_CONFIG_FILE = AppPaths.resolvePath("logs", "msa-webhook.properties").toString();
    private static final String RUNTIME_CONFIG_FILE = AppPaths.resolvePath("logs", "msa-runtime.properties").toString();
    private static final String REMOTE_DEPLOY_CONFIG_FILE = AppPaths.resolvePath("logs", "msa-remote-deploy.properties").toString();
    private static final String REMOTE_DEPLOY_LOG_FILE = AppPaths.resolvePath("logs", "msa-remote-deploy.log").toString();
    private static final String PROJECT_REGISTRY_FILE = AppPaths.resolvePath("logs", "msa-projects.yml").toString();
    private static final String SSH_EDIT_TOKEN_ENV = "MSA_SSH_EDIT_TOKEN";
    private static final String RUNTIME_MODE_KEY = "serverMode";
    private static final String MODE_DEV = "development";
    private static final String MODE_PROD = "production";
    private static final int WEBHOOK_LOG_LIMIT = 180;
    private final AtomicBoolean webhookRunning = new AtomicBoolean(false);
    private final AtomicBoolean webhookQueued = new AtomicBoolean(false);
    private final Deque<String> webhookTail = new ArrayDeque<>();
    private volatile String webhookLastStarted = "";
    private volatile String webhookLastFinished = "";
    private volatile String webhookLastRef = "";
    private volatile Integer webhookLastExitCode = null;
    private volatile Map<String, Object> queuedWebhookPayload = null;

    @GetMapping("")
    public String index() {
        return "redirect:/admin/msa/manager";
    }

    @GetMapping("/manager")
    public String managerView(Model model) {
        model.addAttribute("appRoot", APP_ROOT);
        return "msaManager";
    }

    @ResponseBody
    @GetMapping("/api/modules")
    public List<Map<String, Object>> getModules() {
        return scanner.scan().stream().map(m -> {
            Map<String, Object> map = new HashMap<>();
            map.put("id", m.getId());
            map.put("name", m.getName());
            map.put("dir", m.getDir());
            map.put("port", m.getPort());
            map.put("javaRunnable", m.isJavaRunnable());
            map.put("status", processManager.getStatus(m.getId(), m.getPort()));
            map.put("pid", processManager.getPid(m.getId()));
            return map;
        }).collect(Collectors.toList());
    }

    @ResponseBody
    @GetMapping("/api/mappings")
    public List<Map<String, Object>> getMappings() {
        List<Map<String, Object>> mappings = new ArrayList<>();
        try {
            File file = resolveFirstExisting(MAPPING_FILE_CANDIDATES);
            if (file.exists()) {
                Yaml yaml = new Yaml();
                Map<String, Object> obj = yaml.load(new FileInputStream(file));
                if (obj.get("mappings") instanceof List) {
                    List<Map<String, Object>> rawMappings = (List<Map<String, Object>>) obj.get("mappings");

                    // Enrich each mapping with current module running status
                    List<MsaScanner.ModuleInfo> modules = scanner.scan();
                    for (Map<String, Object> mapping : rawMappings) {
                        String targetModule = (String) mapping.get("module");
                        MsaScanner.ModuleInfo mod = modules.stream()
                                .filter(m -> m.getId().equals(targetModule))
                                .findFirst().orElse(null);
                        if (mod != null) {
                            mapping.put("status", processManager.getStatus(mod.getId(), mod.getPort()));
                            mapping.put("port", mod.getPort());
                        } else {
                            mapping.put("status", "unknown");
                        }
                        mappings.add(new java.util.LinkedHashMap<>(mapping));
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return mappings;
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

    @ResponseBody
    @PostMapping("/api/modules/{id}/start")
    public Map<String, Object> startModule(@PathVariable String id) {
        Map<String, Object> result = new HashMap<>();
        List<MsaScanner.ModuleInfo> modules = scanner.scan();
        MsaScanner.ModuleInfo mod = modules.stream().filter(m -> m.getId().equals(id)).findFirst().orElse(null);
        if (mod != null) {
            if (!mod.isJavaRunnable()) {
                result.put("status", "error");
                result.put("message", "등록된 모듈이지만 실행 가능한 JAR를 찾지 못했습니다.");
                return result;
            }
            processManager.startModule(mod);
            result.put("status", "ok");
        } else {
            result.put("status", "error");
            result.put("message", "Module not found");
        }
        return result;
    }

    @ResponseBody
    @PostMapping("/api/modules/{id}/stop")
    public Map<String, Object> stopModule(@PathVariable String id) {
        // Find module to get its port for robust killing
        MsaScanner.ModuleInfo mod = scanner.scan().stream()
                .filter(m -> m.getId().equals(id))
                .findFirst()
                .orElse(null);

        if (mod != null) {
            processManager.stopAllInstances(mod);
        } else {
            processManager.stopModule(id, null);
        }

        Map<String, Object> res = new HashMap<>();
        res.put("status", "ok");
        return res;
    }

    @ResponseBody
    @PostMapping("/api/modules/{id}/restart")
    public Map<String, Object> restartModule(@PathVariable String id) {
        Map<String, Object> result = new HashMap<>();
        MsaScanner.ModuleInfo mod = scanner.scan().stream()
                .filter(m -> m.getId().equals(id))
                .findFirst()
                .orElse(null);

        if (mod == null) {
            result.put("status", "error");
            result.put("message", "Module not found");
            return result;
        }
        if (!mod.isJavaRunnable()) {
            result.put("status", "error");
            result.put("message", "등록된 모듈이지만 실행 가능한 JAR를 찾지 못했습니다.");
            return result;
        }

        processManager.restartModule(mod);
        result.put("status", "ok");
        return result;
    }

    @ResponseBody
    @PostMapping("/api/modules/{id}/deploy-restart")
    public Map<String, Object> deployRestartModule(@PathVariable String id) {
        Map<String, Object> result = new HashMap<>();
        MsaScanner.ModuleInfo mod = scanner.scan().stream()
                .filter(m -> m.getId().equals(id))
                .findFirst()
                .orElse(null);

        if (mod == null) {
            result.put("status", "error");
            result.put("message", "Module not found");
            return result;
        }
        String deployResult = processManager.deployAndRestartModule(mod);
        if ("ok".equals(deployResult)) {
            result.put("status", "ok");
            return result;
        }
        result.put("status", "error");
        result.put("message", deployResult);
        return result;
    }

    @ResponseBody
    @PostMapping("/api/modules/{id}/build-deploy-restart")
    public Map<String, Object> buildDeployRestartModule(@PathVariable String id) {
        Map<String, Object> result = new HashMap<>();
        if (isBuildBlocked()) {
            result.put("status", "error");
            result.put("message", "운영 보호 모드에서는 빌드 기반 배포가 차단됩니다.");
            return result;
        }
        MsaScanner.ModuleInfo mod = scanner.scan().stream()
                .filter(m -> m.getId().equals(id))
                .findFirst()
                .orElse(null);

        if (mod == null) {
            result.put("status", "error");
            result.put("message", "Module not found");
            return result;
        }
        String opResult = processManager.buildDeployAndRestartModule(mod);
        if ("ok".equals(opResult)) {
            result.put("status", "ok");
            return result;
        }
        result.put("status", "error");
        result.put("message", opResult);
        return result;
    }

    @ResponseBody
    @PostMapping("/api/modules/{id}/build-deploy-zerodowntime")
    public Map<String, Object> buildDeployZeroDowntimeModule(@PathVariable String id) {
        Map<String, Object> result = new HashMap<>();
        if (isBuildBlocked()) {
            result.put("status", "error");
            result.put("message", "운영 보호 모드에서는 빌드 기반 배포가 차단됩니다.");
            return result;
        }
        MsaScanner.ModuleInfo mod = scanner.scan().stream()
                .filter(m -> m.getId().equals(id))
                .findFirst()
                .orElse(null);

        if (mod == null) {
            result.put("status", "error");
            result.put("message", "Module not found");
            return result;
        }
        String opResult = processManager.buildDeployZeroDowntimeModule(mod);
        if ("ok".equals(opResult)) {
            result.put("status", "ok");
            return result;
        }
        result.put("status", "error");
        result.put("message", opResult);
        return result;
    }

    @ResponseBody
    @PostMapping("/api/modules/{id}/deploy-zerodowntime")
    public Map<String, Object> deployZeroDowntimeModule(@PathVariable String id) {
        Map<String, Object> result = new HashMap<>();
        MsaScanner.ModuleInfo mod = scanner.scan().stream()
                .filter(m -> m.getId().equals(id))
                .findFirst()
                .orElse(null);

        if (mod == null) {
            result.put("status", "error");
            result.put("message", "Module not found");
            return result;
        }
        String opResult = processManager.deployZeroDowntimeModule(mod);
        if ("ok".equals(opResult)) {
            result.put("status", "ok");
            return result;
        }
        result.put("status", "error");
        result.put("message", opResult);
        return result;
    }

    @ResponseBody
    @GetMapping("/api/webhook/status")
    public Map<String, Object> getWebhookStatus() {
        Map<String, Object> out = new HashMap<>();
        Properties remote = loadRemoteDeployConfig();
        out.put("running", webhookRunning.get());
        out.put("queued", webhookQueued.get());
        out.put("lastStarted", webhookLastStarted);
        out.put("lastFinished", webhookLastFinished);
        out.put("lastExitCode", webhookLastExitCode);
        out.put("lastRef", webhookLastRef);
        out.put("secretConfigured", !resolveWebhookToken().isEmpty());
        out.put("scriptExists", new File(WEBHOOK_RUN_SCRIPT).exists());
        out.put("serverMode", getServerMode());
        out.put("buildAllowed", !isBuildBlocked());
        out.put("webhookRemoteBuildEnabled", boolProp(remote, "webhookRemoteBuildEnabled"));
        out.put("webhookRemoteDeployOnlyEnabled", boolProp(remote, "webhookRemoteDeployOnlyEnabled"));
        synchronized (webhookTail) {
            out.put("tail", new ArrayList<>(webhookTail));
        }
        return out;
    }

    @ResponseBody
    @GetMapping("/api/webhook/config")
    public Map<String, Object> getWebhookConfig() {
        Properties p = loadWebhookConfig();
        String repo = p.getProperty("repository", "");
        String token = p.getProperty("token", "");
        Map<String, Object> out = new HashMap<>();
        out.put("repository", repo);
        out.put("hasToken", !token.trim().isEmpty());
        out.put("tokenMasked", maskToken(token));
        out.put("scriptExists", new File(WEBHOOK_RUN_SCRIPT).exists());
        out.put("serverMode", getServerMode());
        out.put("buildAllowed", !isBuildBlocked());
        return out;
    }

    @ResponseBody
    @PostMapping("/api/webhook/config")
    public Map<String, Object> setWebhookConfig(@RequestBody(required = false) Map<String, Object> req) {
        String repository = req == null ? "" : str(req.get("repository"));
        String token = req == null ? "" : str(req.get("token"));
        Properties p = loadWebhookConfig();
        p.setProperty("repository", repository);
        if (!token.isEmpty()) {
            p.setProperty("token", token);
        }
        saveWebhookConfig(p);
        Map<String, Object> out = new HashMap<>();
        out.put("status", "ok");
        out.put("repository", repository);
        out.put("hasToken", !p.getProperty("token", "").trim().isEmpty());
        out.put("tokenMasked", maskToken(p.getProperty("token", "")));
        return out;
    }

    @ResponseBody
    @PostMapping("/api/webhook/check")
    public Map<String, Object> checkWebhookConfig() {
        Properties p = loadWebhookConfig();
        Map<String, Object> out = new HashMap<>();
        out.put("status", "ok");
        out.put("repository", p.getProperty("repository", ""));
        out.put("hasToken", !p.getProperty("token", "").trim().isEmpty());
        out.put("scriptExists", new File(WEBHOOK_RUN_SCRIPT).exists());
        out.put("running", webhookRunning.get());
        out.put("queued", webhookQueued.get());
        out.put("serverMode", getServerMode());
        out.put("buildAllowed", !isBuildBlocked());
        out.put("webhookAllowed", !isDangerousOpsBlocked());
        Properties remote = loadRemoteDeployConfig();
        out.put("webhookDeployMode", normalizeWebhookDeployMode(remote.getProperty("webhookDeployMode", "jar")));
        out.put("webhookRemoteBuildEnabled", boolProp(remote, "webhookRemoteBuildEnabled"));
        out.put("webhookRemoteDeployOnlyEnabled", boolProp(remote, "webhookRemoteDeployOnlyEnabled"));
        return out;
    }

    @ResponseBody
    @PostMapping("/api/webhook/token/generate")
    public Map<String, Object> generateWebhookToken() {
        String token = randomHex(24);
        Properties p = loadWebhookConfig();
        p.setProperty("token", token);
        saveWebhookConfig(p);

        Map<String, Object> out = new HashMap<>();
        out.put("status", "ok");
        out.put("token", token);
        out.put("tokenMasked", maskToken(token));
        out.put("hasToken", true);
        return out;
    }

    @ResponseBody
    @GetMapping("/api/runtime/config")
    public Map<String, Object> getRuntimeConfig() {
        Map<String, Object> out = new HashMap<>();
        out.put("status", "ok");
        out.put("serverMode", getServerMode());
        out.put("dangerousOpsBlocked", isDangerousOpsBlocked());
        out.put("buildAllowed", !isBuildBlocked());
        return out;
    }

    @ResponseBody
    @PostMapping("/api/runtime/config")
    public Map<String, Object> setRuntimeConfig(@RequestBody(required = false) Map<String, Object> req) {
        String mode = normalizeServerMode(req == null ? null : req.get("serverMode"));
        if (mode.isEmpty()) {
            mode = getServerMode();
        }
        Properties p = loadRuntimeConfig();
        p.setProperty(RUNTIME_MODE_KEY, mode);
        saveRuntimeConfig(p);

        Map<String, Object> out = new HashMap<>();
        out.put("status", "ok");
        out.put("serverMode", mode);
        out.put("dangerousOpsBlocked", MODE_PROD.equals(mode));
        out.put("buildAllowed", !MODE_PROD.equals(mode));
        return out;
    }

    @ResponseBody
    @GetMapping("/api/remote/config")
    public Map<String, Object> getRemoteDeployConfig() {
        Properties p = loadRemoteDeployConfig();
        Map<String, Object> out = new HashMap<>();
        out.put("host", p.getProperty("host", ""));
        out.put("port", p.getProperty("port", "22"));
        out.put("user", p.getProperty("user", ""));
        out.put("keyPath", p.getProperty("keyPath", ""));
        out.put("passwordMasked", maskToken(p.getProperty("password", "")));
        out.put("hasPassword", !str(p.getProperty("password", "")).isEmpty());
        out.put("remoteDir", p.getProperty("remoteDir", APP_ROOT));
        out.put("containerName", p.getProperty("containerName", "carbosys-app"));
        out.put("managerUrl", p.getProperty("managerUrl", "http://localhost:18030"));
        out.put("activeColor", p.getProperty("activeColor", "blue"));
        out.put("composeBlueFile", p.getProperty("composeBlueFile", "docker-compose.blue.yml"));
        out.put("composeGreenFile", p.getProperty("composeGreenFile", "docker-compose.green.yml"));
        out.put("nginxSwitchCmd", p.getProperty("nginxSwitchCmd", ""));
        out.put("nginxReloadCmd", p.getProperty("nginxReloadCmd", "nginx -s reload"));
        out.put("blueGatewayHealthUrl", p.getProperty("blueGatewayHealthUrl", "http://localhost:9000/actuator/health"));
        out.put("greenGatewayHealthUrl", p.getProperty("greenGatewayHealthUrl", "http://localhost:9001/actuator/health"));
        out.put("baseServices", p.getProperty("baseServices", "eureka-server config-server gateway-server"));
        out.put("homeService", p.getProperty("homeService", "egov-home"));
        out.put("managerService", p.getProperty("managerService", "egov-msa-manager"));
        out.put("webhookDeployMode", normalizeWebhookDeployMode(p.getProperty("webhookDeployMode", "jar")));
        out.put("webhookRemoteBuildEnabled", boolProp(p, "webhookRemoteBuildEnabled"));
        out.put("webhookRemoteDeployOnlyEnabled", boolProp(p, "webhookRemoteDeployOnlyEnabled"));
        out.put("serverMode", getServerMode());
        out.put("remoteAllowed", !isDangerousOpsBlocked());
        out.put("status", "ok");
        return out;
    }

    @ResponseBody
    @PostMapping("/api/remote/config")
    public Map<String, Object> setRemoteDeployConfig(@RequestBody(required = false) Map<String, Object> req) {
        Properties p = loadRemoteDeployConfig();
        String host = req == null ? "" : str(req.get("host"));
        String user = req == null ? "" : str(req.get("user"));
        String port = req == null ? "" : str(req.get("port"));
        String keyPath = req == null ? "" : str(req.get("keyPath"));
        String password = req == null ? "" : str(req.get("password"));
        String remoteDir = req == null ? "" : str(req.get("remoteDir"));
        String containerName = req == null ? "" : str(req.get("containerName"));
        String managerUrl = req == null ? "" : str(req.get("managerUrl"));
        String activeColor = req == null ? "" : str(req.get("activeColor"));
        String composeBlueFile = req == null ? "" : str(req.get("composeBlueFile"));
        String composeGreenFile = req == null ? "" : str(req.get("composeGreenFile"));
        String nginxSwitchCmd = req == null ? "" : str(req.get("nginxSwitchCmd"));
        String nginxReloadCmd = req == null ? "" : str(req.get("nginxReloadCmd"));
        String blueGatewayHealthUrl = req == null ? "" : str(req.get("blueGatewayHealthUrl"));
        String greenGatewayHealthUrl = req == null ? "" : str(req.get("greenGatewayHealthUrl"));
        String baseServices = req == null ? "" : str(req.get("baseServices"));
        String homeService = req == null ? "" : str(req.get("homeService"));
        String managerService = req == null ? "" : str(req.get("managerService"));
        String webhookDeployMode = req == null ? "" : str(req.get("webhookDeployMode"));
        String buildFlag = req == null ? "" : str(req.get("webhookRemoteBuildEnabled"));
        String deployOnlyFlag = req == null ? "" : str(req.get("webhookRemoteDeployOnlyEnabled"));

        if (req != null && req.containsKey("host")) p.setProperty("host", host);
        if (req != null && req.containsKey("user")) p.setProperty("user", user);
        if (req != null && req.containsKey("port")) p.setProperty("port", port.isEmpty() ? "22" : port);
        if (req != null && req.containsKey("keyPath")) p.setProperty("keyPath", keyPath);
        if (req != null && req.containsKey("password")) p.setProperty("password", password);
        if (req != null && req.containsKey("remoteDir")) p.setProperty("remoteDir", remoteDir.isEmpty() ? APP_ROOT : remoteDir);
        if (req != null && req.containsKey("containerName")) p.setProperty("containerName", containerName.isEmpty() ? "carbosys-app" : containerName);
        if (req != null && req.containsKey("managerUrl")) p.setProperty("managerUrl", managerUrl.isEmpty() ? "http://localhost:18030" : managerUrl);
        if (req != null && req.containsKey("activeColor")) p.setProperty("activeColor", normalizeColor(activeColor));
        if (req != null && req.containsKey("composeBlueFile")) p.setProperty("composeBlueFile", composeBlueFile.isEmpty() ? "docker-compose.blue.yml" : composeBlueFile);
        if (req != null && req.containsKey("composeGreenFile")) p.setProperty("composeGreenFile", composeGreenFile.isEmpty() ? "docker-compose.green.yml" : composeGreenFile);
        if (req != null && req.containsKey("nginxSwitchCmd")) p.setProperty("nginxSwitchCmd", nginxSwitchCmd);
        if (req != null && req.containsKey("nginxReloadCmd")) p.setProperty("nginxReloadCmd", nginxReloadCmd.isEmpty() ? "nginx -s reload" : nginxReloadCmd);
        if (req != null && req.containsKey("blueGatewayHealthUrl")) p.setProperty("blueGatewayHealthUrl", blueGatewayHealthUrl.isEmpty() ? "http://localhost:9000/actuator/health" : blueGatewayHealthUrl);
        if (req != null && req.containsKey("greenGatewayHealthUrl")) p.setProperty("greenGatewayHealthUrl", greenGatewayHealthUrl.isEmpty() ? "http://localhost:9001/actuator/health" : greenGatewayHealthUrl);
        if (req != null && req.containsKey("baseServices")) p.setProperty("baseServices", baseServices.isEmpty() ? "eureka-server config-server gateway-server" : baseServices);
        if (req != null && req.containsKey("homeService")) p.setProperty("homeService", homeService.isEmpty() ? "egov-home" : homeService);
        if (req != null && req.containsKey("managerService")) p.setProperty("managerService", managerService.isEmpty() ? "egov-msa-manager" : managerService);
        if (req != null && req.containsKey("webhookDeployMode")) p.setProperty("webhookDeployMode", normalizeWebhookDeployMode(webhookDeployMode));
        if (!buildFlag.isEmpty()) {
            p.setProperty("webhookRemoteBuildEnabled", String.valueOf(Boolean.parseBoolean(buildFlag)));
        }
        if (!deployOnlyFlag.isEmpty()) {
            p.setProperty("webhookRemoteDeployOnlyEnabled", String.valueOf(Boolean.parseBoolean(deployOnlyFlag)));
        }
        saveRemoteDeployConfig(p);

        Map<String, Object> out = new HashMap<>();
        out.put("status", "ok");
        out.put("webhookDeployMode", normalizeWebhookDeployMode(p.getProperty("webhookDeployMode", "jar")));
        out.put("webhookRemoteBuildEnabled", boolProp(p, "webhookRemoteBuildEnabled"));
        out.put("webhookRemoteDeployOnlyEnabled", boolProp(p, "webhookRemoteDeployOnlyEnabled"));
        return out;
    }

    @ResponseBody
    @GetMapping("/api/projects")
    public Map<String, Object> getProjectRegistry() {
        List<Map<String, Object>> projects = loadProjectRegistry().stream()
                .map(this::sanitizeProjectOutput)
                .collect(Collectors.toList());
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("status", "ok");
        out.put("count", projects.size());
        out.put("projects", projects);
        out.put("appRoot", APP_ROOT);
        return out;
    }

    @ResponseBody
    @PostMapping("/api/projects")
    public Map<String, Object> upsertProject(@RequestBody(required = false) Map<String, Object> req) {
        Map<String, Object> out = new LinkedHashMap<>();
        if (req == null) {
            out.put("status", "error");
            out.put("message", "요청 본문이 필요합니다.");
            return out;
        }
        String id = str(req.get("id")).replaceAll("[^A-Za-z0-9._-]", "");
        if (id.isEmpty()) {
            out.put("status", "error");
            out.put("message", "id는 영문/숫자/._- 만 허용됩니다.");
            return out;
        }
        List<Map<String, Object>> projects = loadProjectRegistry();
        Map<String, Object> normalized = normalizeProjectInput(id, req);
        boolean replaced = false;
        for (int i = 0; i < projects.size(); i++) {
            if (id.equals(str(projects.get(i).get("id")))) {
                projects.set(i, normalized);
                replaced = true;
                break;
            }
        }
        if (!replaced) {
            projects.add(normalized);
        }
        saveProjectRegistry(projects);
        out.put("status", "ok");
        out.put("action", replaced ? "updated" : "created");
        out.put("project", sanitizeProjectOutput(normalized));
        return out;
    }

    @ResponseBody
    @DeleteMapping("/api/projects/{id}")
    public Map<String, Object> deleteProject(@PathVariable String id) {
        String targetId = str(id).replaceAll("[^A-Za-z0-9._-]", "");
        List<Map<String, Object>> projects = loadProjectRegistry();
        int before = projects.size();
        projects = projects.stream()
                .filter(p -> !targetId.equals(str(p.get("id"))))
                .collect(Collectors.toList());
        saveProjectRegistry(projects);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("status", "ok");
        out.put("deleted", before - projects.size());
        return out;
    }

    @ResponseBody
    @PostMapping("/api/projects/{id}/ssh/test")
    public Map<String, Object> testProjectSsh(@PathVariable String id, HttpServletRequest request) {
        Map<String, Object> denied = verifySshPermission(request);
        if (denied != null) {
            return denied;
        }
        Map<String, Object> project = findProject(id);
        Map<String, Object> out = new LinkedHashMap<>();
        if (project == null) {
            out.put("status", "error");
            out.put("message", "프로젝트를 찾지 못했습니다: " + id);
            return out;
        }
        try {
            Map<String, Object> exec = runSshCapture(sshConfigFromProject(project), "pwd; ls -1");
            out.put("status", "ok");
            out.put("project", sanitizeProjectOutput(project));
            out.put("output", exec.get("output"));
            return out;
        } catch (Exception e) {
            out.put("status", "error");
            out.put("message", "SSH 테스트 실패: " + e.getMessage());
            return out;
        }
    }

    @ResponseBody
    @PostMapping("/api/projects/{id}/ssh/exec")
    public Map<String, Object> execProjectSsh(@PathVariable String id,
            @RequestBody(required = false) Map<String, Object> req,
            HttpServletRequest request) {
        Map<String, Object> denied = verifySshPermission(request);
        if (denied != null) {
            return denied;
        }
        String cmd = req == null ? "" : str(req.get("command"));
        Map<String, Object> out = new LinkedHashMap<>();
        if (cmd.isEmpty()) {
            out.put("status", "error");
            out.put("message", "command가 필요합니다.");
            return out;
        }
        if (cmd.length() > 4000) {
            out.put("status", "error");
            out.put("message", "command 길이가 너무 깁니다.");
            return out;
        }
        Map<String, Object> project = findProject(id);
        if (project == null) {
            out.put("status", "error");
            out.put("message", "프로젝트를 찾지 못했습니다: " + id);
            return out;
        }
        try {
            Map<String, Object> exec = runSshCapture(sshConfigFromProject(project), cmd);
            out.put("status", "ok");
            out.put("output", exec.get("output"));
            out.put("exitCode", exec.get("exitCode"));
            return out;
        } catch (Exception e) {
            out.put("status", "error");
            out.put("message", "원격 명령 실패: " + e.getMessage());
            return out;
        }
    }

    @ResponseBody
    @PostMapping("/api/projects/{id}/ssh/file/write")
    public Map<String, Object> writeProjectFile(@PathVariable String id,
            @RequestBody(required = false) Map<String, Object> req,
            HttpServletRequest request) {
        Map<String, Object> denied = verifySshPermission(request);
        if (denied != null) {
            return denied;
        }
        String path = req == null ? "" : str(req.get("path"));
        String content = req == null ? "" : String.valueOf(req.getOrDefault("content", ""));
        boolean backup = req != null && Boolean.parseBoolean(str(req.get("backup")));
        Map<String, Object> out = new LinkedHashMap<>();
        Map<String, Object> project = findProject(id);
        if (project == null) {
            out.put("status", "error");
            out.put("message", "프로젝트를 찾지 못했습니다: " + id);
            return out;
        }
        String rootDir = str(project.get("rootDir"));
        if (path.isEmpty()) {
            out.put("status", "error");
            out.put("message", "path가 필요합니다.");
            return out;
        }
        String normalizedPath = path.startsWith("/") ? path : (rootDir + "/" + path);
        if (!normalizedPath.startsWith(rootDir + "/") && !normalizedPath.equals(rootDir)) {
            out.put("status", "error");
            out.put("message", "path는 프로젝트 rootDir 하위만 허용됩니다.");
            return out;
        }
        String b64 = Base64.getEncoder().encodeToString(content.getBytes(StandardCharsets.UTF_8));
        String cmd = ""
                + "set -e; "
                + "target=" + shellQuote(normalizedPath) + "; "
                + "mkdir -p \"$(dirname \"$target\")\"; "
                + (backup ? "if [ -f \"$target\" ]; then cp \"$target\" \"$target.bak.$(date +%Y%m%d%H%M%S)\"; fi; " : "")
                + "printf %s " + shellQuote(b64) + " | base64 -d > \"$target\"; "
                + "echo OK";
        try {
            Map<String, Object> exec = runSshCapture(sshConfigFromProject(project), cmd);
            out.put("status", "ok");
            out.put("path", normalizedPath);
            out.put("exitCode", exec.get("exitCode"));
            out.put("output", exec.get("output"));
            return out;
        } catch (Exception e) {
            out.put("status", "error");
            out.put("message", "원격 파일 쓰기 실패: " + e.getMessage());
            return out;
        }
    }

    @ResponseBody
    @GetMapping("/api/projects/{id}/manager/modules")
    public ResponseEntity<?> getProjectManagerModules(@PathVariable String id, HttpServletRequest request) {
        Map<String, Object> denied = verifySshPermission(request);
        if (denied != null) {
            return ResponseEntity.status(403).body(denied);
        }
        Map<String, Object> project = findProject(id);
        if (project == null) {
            return ResponseEntity.badRequest().body(Map.of("status", "error", "message", "프로젝트를 찾지 못했습니다: " + id));
        }
        String managerUrl = str(project.get("managerUrl"));
        try {
            Map<String, Object> exec = runSshCapture(sshConfigFromProject(project),
                    "curl -fsS " + shellQuote(managerUrl + "/admin/msa/api/modules"));
            return ResponseEntity.ok()
                    .header("Content-Type", "application/json")
                    .body(exec.get("output"));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("status", "error", "message", "원격 매니저 조회 실패: " + e.getMessage()));
        }
    }

    @ResponseBody
    @PostMapping("/api/projects/{id}/manager/modules/{moduleId}/{action}")
    public Map<String, Object> invokeProjectManagerModuleAction(@PathVariable String id,
            @PathVariable String moduleId,
            @PathVariable String action,
            HttpServletRequest request) {
        Map<String, Object> denied = verifySshPermission(request);
        if (denied != null) {
            return denied;
        }
        Set<String> allowed = new LinkedHashSet<>(Arrays.asList(
                "start", "stop", "restart", "deploy-restart", "deploy-zerodowntime", "build-deploy-restart",
                "build-deploy-zerodowntime"));
        if (!allowed.contains(action)) {
            return Map.of("status", "error", "message", "지원하지 않는 action: " + action);
        }
        Map<String, Object> project = findProject(id);
        if (project == null) {
            return Map.of("status", "error", "message", "프로젝트를 찾지 못했습니다: " + id);
        }
        String managerUrl = str(project.get("managerUrl"));
        String call = "curl -fsS -X POST " + shellQuote(
                managerUrl + "/admin/msa/api/modules/" + moduleId + "/" + action);
        try {
            Map<String, Object> exec = runSshCapture(sshConfigFromProject(project), call);
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("status", "ok");
            out.put("output", exec.get("output"));
            out.put("exitCode", exec.get("exitCode"));
            return out;
        } catch (Exception e) {
            return Map.of("status", "error", "message", "원격 모듈 제어 실패: " + e.getMessage());
        }
    }

    @ResponseBody
    @PostMapping("/api/remote/bluegreen/deploy")
    public Map<String, Object> runRemoteBlueGreenDeploy(@RequestBody(required = false) Map<String, Object> req) {
        if (isDangerousOpsBlocked()) {
            Map<String, Object> blocked = new HashMap<>();
            blocked.put("status", "blocked");
            blocked.put("message", "운영 모드에서는 원격 Blue/Green 실행이 차단됩니다.");
            return blocked;
        }
        boolean includeManager = req != null && Boolean.parseBoolean(str(req.get("includeManager")));
        boolean homeOnly = req == null || !req.containsKey("homeOnly") || Boolean.parseBoolean(str(req.get("homeOnly")));
        boolean build = req != null && req.containsKey("build") && Boolean.parseBoolean(str(req.get("build")));
        boolean syncSources = req == null || !req.containsKey("syncSources") || Boolean.parseBoolean(str(req.get("syncSources")));
        return executeRemoteBlueGreenDeploy(includeManager, homeOnly, build, syncSources);
    }

    @ResponseBody
    @PostMapping("/api/remote/initial-deploy")
    public Map<String, Object> runRemoteInitialDeploy() {
        if (isDangerousOpsBlocked()) {
            Map<String, Object> blocked = new HashMap<>();
            blocked.put("status", "blocked");
            blocked.put("message", "운영 모드에서는 원격 초기 배포 실행이 차단됩니다.");
            return blocked;
        }
        return executeRemoteInitialDeploy();
    }

    @ResponseBody
    @PostMapping("/api/remote/auto-deploy-all")
    public Map<String, Object> runRemoteAutoDeployAll(@RequestBody(required = false) Map<String, Object> req) {
        if (isDangerousOpsBlocked()) {
            Map<String, Object> blocked = new HashMap<>();
            blocked.put("status", "blocked");
            blocked.put("message", "운영 모드에서는 원격 자동 배포 실행이 차단됩니다.");
            return blocked;
        }
        boolean build = req != null && Boolean.parseBoolean(str(req.get("build")));
        return executeRemoteAutoDeployAll(build);
    }

    @ResponseBody
    @PostMapping("/api/remote/source-deploy")
    public Map<String, Object> runRemoteSourceDeploy() {
        if (isDangerousOpsBlocked()) {
            Map<String, Object> blocked = new HashMap<>();
            blocked.put("status", "blocked");
            blocked.put("message", "운영 모드에서는 원격 소스코드 배포 실행이 차단됩니다.");
            return blocked;
        }
        return executeRemoteSourceDeploy();
    }

    @ResponseBody
    @PostMapping("/api/remote/build")
    public Map<String, Object> runRemoteBuildOnly() {
        if (isDangerousOpsBlocked()) {
            Map<String, Object> blocked = new HashMap<>();
            blocked.put("status", "blocked");
            blocked.put("message", "운영 모드에서는 원격 빌드 실행이 차단됩니다.");
            return blocked;
        }
        return executeRemoteBuildOnly();
    }

    @ResponseBody
    @PostMapping("/api/remote/docker/color-up")
    public Map<String, Object> runRemoteDockerColorUp(@RequestBody(required = false) Map<String, Object> req) {
        if (isDangerousOpsBlocked()) {
            Map<String, Object> blocked = new HashMap<>();
            blocked.put("status", "blocked");
            blocked.put("message", "운영 모드에서는 원격 도커 기동 실행이 차단됩니다.");
            return blocked;
        }
        String color = normalizeColor(str(req == null ? null : req.get("color")));
        boolean includeManager = req != null && Boolean.parseBoolean(str(req.get("includeManager")));
        boolean homeOnly = req == null || !req.containsKey("homeOnly") || Boolean.parseBoolean(str(req.get("homeOnly")));
        boolean build = req == null || !req.containsKey("build") || Boolean.parseBoolean(str(req.get("build")));
        return executeRemoteDockerColorUp(color, includeManager, homeOnly, build);
    }

    @ResponseBody
    @PostMapping("/api/remote/nginx")
    public Map<String, Object> runRemoteNginx(@RequestBody(required = false) Map<String, Object> req) {
        if (isDangerousOpsBlocked()) {
            Map<String, Object> blocked = new HashMap<>();
            blocked.put("status", "blocked");
            blocked.put("message", "운영 모드에서는 원격 nginx 명령 실행이 차단됩니다.");
            return blocked;
        }
        String action = str(req == null ? null : req.get("action")).toLowerCase();
        return executeRemoteNginxAction(action);
    }

    @ResponseBody
    @PostMapping("/api/remote/deploy-module")
    public Map<String, Object> runRemoteModuleDeploy(@RequestBody(required = false) Map<String, Object> req) {
        if (isDangerousOpsBlocked()) {
            Map<String, Object> blocked = new HashMap<>();
            blocked.put("status", "blocked");
            blocked.put("message", "운영 모드에서는 원격 배포 실행이 차단됩니다.");
            return blocked;
        }
        String moduleId = req == null ? "" : str(req.get("moduleId"));
        boolean build = req != null && Boolean.parseBoolean(str(req.get("build")));
        if (moduleId.isEmpty()) {
            Map<String, Object> out = new HashMap<>();
            out.put("status", "error");
            out.put("message", "moduleId is required");
            return out;
        }
        return runRemoteModuleDeployInternal(moduleId, build);
    }

    @ResponseBody
    @GetMapping("/api/remote/status")
    public Map<String, Object> getRemoteDeployStatus() {
        Map<String, Object> out = new HashMap<>();
        out.put("status", "ok");
        out.put("tail", readTail(REMOTE_DEPLOY_LOG_FILE, 120));
        return out;
    }

    @ResponseBody
    @PostMapping("/api/webhook/git")
    public Map<String, Object> runWebhook(@RequestBody(required = false) Map<String, Object> payload,
                                          @RequestParam(value = "token", required = false) String tokenParam,
                                          @RequestHeader(value = "X-Webhook-Token", required = false) String token,
                                          @RequestHeader(value = "X-Gitlab-Token", required = false) String gitlabToken) {
        Map<String, Object> out = new HashMap<>();
        if (isDangerousOpsBlocked()) {
            out.put("status", "blocked");
            out.put("message", "운영 모드에서는 웹훅 자동 배포가 차단됩니다.");
            return out;
        }
        String secret = resolveWebhookToken();
        String provided = firstNonEmpty(token, gitlabToken, tokenParam);
        if (!secret.isEmpty() && !secret.equals(provided)) {
            out.put("status", "forbidden");
            out.put("message", "webhook token mismatch");
            return out;
        }
        if (webhookRunning.get()) {
            queuedWebhookPayload = payload == null ? new HashMap<>() : payload;
            webhookQueued.set(true);
            appendWebhookTail("QUEUED webhook while running");
            out.put("status", "queued");
            out.put("message", "webhook queued while previous job is running");
            return out;
        }
        startWebhookWorker(payload == null ? new HashMap<>() : payload, "incoming");

        out.put("status", "accepted");
        out.put("running", true);
        out.put("ref", str(payload == null ? "" : payload.get("ref")));
        out.put("startedAt", webhookLastStarted);
        return out;
    }

    @ResponseBody
    @GetMapping("/api/modules/{id}/logs")
    public Map<String, Object> getLogs(@PathVariable String id) {
        Map<String, Object> result = new HashMap<>();
        List<MsaScanner.ModuleInfo> modules = scanner.scan();
        MsaScanner.ModuleInfo mod = modules.stream().filter(m -> m.getId().equals(id)).findFirst().orElse(null);

        if (mod != null) {
            result.put("logs", processManager.getLogs(id, mod.getDir(), mod.getPort()));
        } else {
            result.put("logs", java.util.Collections.singletonList("Module info not found"));
        }
        return result;
    }

    @ResponseBody
    @GetMapping("/api/changes")
    public List<Map<String, Object>> getChanges(@RequestParam(required = false) String from,
                                                 @RequestParam(required = false) String to) {
        return changeMonitorService.getHistory(parseTimeParam(from), parseTimeParam(to));
    }

    @ResponseBody
    @GetMapping("/api/autodeploy/status")
    public Map<String, Object> getAutoDeployStatus() {
        Map<String, Object> res = new HashMap<>();
        res.put("enabled", changeMonitorService.isAutoDeployEnabled());
        res.put("managerEnabled", changeMonitorService.isManagerAutoDeployEnabled());
        res.put("serverMode", getServerMode());
        res.put("dangerousOpsBlocked", isDangerousOpsBlocked());
        res.put("buildAllowed", !isBuildBlocked());
        return res;
    }

    @ResponseBody
    @PostMapping("/api/autodeploy/toggle")
    public Map<String, Object> setAutoDeploy(@RequestBody Map<String, Object> req) {
        boolean enabled = Boolean.parseBoolean(String.valueOf(req.get("enabled")));
        changeMonitorService.setAutoDeployEnabled(enabled);
        if (req != null && req.containsKey("managerEnabled")) {
            boolean managerEnabled = Boolean.parseBoolean(String.valueOf(req.get("managerEnabled")));
            changeMonitorService.setManagerAutoDeployEnabled(managerEnabled);
        }
        Map<String, Object> res = new HashMap<>();
        res.put("status", "ok");
        res.put("enabled", changeMonitorService.isAutoDeployEnabled());
        res.put("managerEnabled", changeMonitorService.isManagerAutoDeployEnabled());
        res.put("serverMode", getServerMode());
        res.put("buildAllowed", !isBuildBlocked());
        return res;
    }

    @ResponseBody
    @PostMapping("/api/autodeploy/ai/start")
    public Map<String, Object> startAiEditSession() {
        return changeMonitorService.startAiEditSession();
    }

    @ResponseBody
    @PostMapping("/api/autodeploy/ai/end")
    public Map<String, Object> endAiEditSession(@RequestBody(required = false) Map<String, Object> req) {
        Boolean build = null;
        if (req != null && req.containsKey("build")) {
            build = Boolean.parseBoolean(String.valueOf(req.get("build")));
        }
        return changeMonitorService.endAiEditSession(build);
    }

    @ResponseBody
    @GetMapping("/api/logs/modules")
    public Map<String, Object> getModuleLogs() {
        return logAnalyticsService.getModuleLogs();
    }

    @ResponseBody
    @GetMapping("/api/logs/critical")
    public List<Map<String, Object>> getCriticalLogs() {
        return logAnalyticsService.getCriticalEvents();
    }

    @ResponseBody
    @PostMapping("/api/logs/reset")
    public Map<String, Object> resetLiveLogs() {
        return logAnalyticsService.resetLiveMonitoring();
    }

    @ResponseBody
    @GetMapping("/api/stats/controllers")
    public List<Map<String, Object>> getControllerStats(@RequestParam(required = false) String from,
                                                         @RequestParam(required = false) String to) {
        return logAnalyticsService.getTopControllers(parseTimeParam(from), parseTimeParam(to));
    }

    @ResponseBody
    @GetMapping("/api/stats/errors")
    public List<Map<String, Object>> getErrorStats(@RequestParam(required = false) String from,
                                                    @RequestParam(required = false) String to) {
        return logAnalyticsService.getTopErrors(parseTimeParam(from), parseTimeParam(to));
    }

    @ResponseBody
    @GetMapping("/api/logs/archive/modules")
    public Map<String, Object> getArchiveModuleLogs(@RequestParam(required = false) String from,
                                                     @RequestParam(required = false) String to) {
        return logAnalyticsService.getArchiveModuleLogs(parseTimeParam(from), parseTimeParam(to));
    }

    @ResponseBody
    @GetMapping("/api/logs/archive/critical")
    public List<Map<String, Object>> getArchiveCriticalLogs(@RequestParam(required = false) String from,
                                                             @RequestParam(required = false) String to) {
        return logAnalyticsService.getArchiveCriticalEvents(parseTimeParam(from), parseTimeParam(to));
    }

    @ResponseBody
    @GetMapping("/api/stats/archive/controllers")
    public List<Map<String, Object>> getArchiveControllerStats(@RequestParam(required = false) String from,
                                                                @RequestParam(required = false) String to) {
        return logAnalyticsService.getArchiveTopControllers(parseTimeParam(from), parseTimeParam(to));
    }

    @ResponseBody
    @GetMapping("/api/stats/archive/errors")
    public List<Map<String, Object>> getArchiveErrorStats(@RequestParam(required = false) String from,
                                                           @RequestParam(required = false) String to) {
        return logAnalyticsService.getArchiveTopErrors(parseTimeParam(from), parseTimeParam(to));
    }

    @ResponseBody
    @GetMapping("/api/security/violations")
    public Map<String, Object> getSecurityViolations() {
        return opsInsightService.getSecurityViolations();
    }

    @ResponseBody
    @GetMapping("/api/security/source-scan/config")
    public Map<String, Object> getSourceScanConfig() {
        return opsInsightService.getSourceScanConfig();
    }

    @ResponseBody
    @PostMapping("/api/security/source-scan/config")
    public Map<String, Object> setSourceScanConfig(@RequestBody Map<String, Object> req) {
        boolean enabled = Boolean.parseBoolean(String.valueOf(req.get("enabled")));
        return opsInsightService.setSourceScanEnabled(enabled);
    }

    @ResponseBody
    @PostMapping("/api/security/source-scan/profile")
    public Map<String, Object> setSourceScanProfile(@RequestBody Map<String, Object> req) {
        String profile = req == null ? null : String.valueOf(req.get("profile"));
        return opsInsightService.setSourceScanProfile(profile);
    }

    @ResponseBody
    @PostMapping("/api/security/source-scan/options")
    public Map<String, Object> setSourceScanOptions(@RequestBody(required = false) Map<String, Object> req) {
        return opsInsightService.setSourceScanOptions(req);
    }

    @ResponseBody
    @GetMapping("/api/security/baseline/status")
    public Map<String, Object> getSecurityBaselineStatus() {
        return opsInsightService.getSecurityBaselineStatus();
    }

    @ResponseBody
    @PostMapping("/api/security/baseline/rebuild")
    public Map<String, Object> rebuildSecurityBaseline() {
        return opsInsightService.rebuildSecurityBaseline();
    }

    @ResponseBody
    @PostMapping("/api/security/explore/run")
    public Map<String, Object> runSecurityExplore(@RequestBody(required = false) Map<String, Object> req) {
        String mode = "source";
        if (req != null && req.get("mode") != null) {
            mode = String.valueOf(req.get("mode"));
        }
        return opsInsightService.startExplore(mode);
    }

    @ResponseBody
    @GetMapping("/api/security/explore/status")
    public Map<String, Object> getSecurityExploreStatus() {
        return opsInsightService.getExploreStatus();
    }

    @ResponseBody
    @GetMapping("/api/traffic/overview")
    public Map<String, Object> getTrafficOverview() {
        return opsInsightService.getTrafficOverview();
    }

    @ResponseBody
    @GetMapping("/api/traffic/load-test/status")
    public Map<String, Object> getTrafficLoadTestStatus() {
        return opsInsightService.getTrafficLoadStatus();
    }

    @ResponseBody
    @PostMapping("/api/traffic/load-test/run")
    public Map<String, Object> runTrafficLoadTest(@RequestBody(required = false) Map<String, Object> req) {
        return opsInsightService.runTrafficLoadTest(req);
    }

    @ResponseBody
    @GetMapping("/api/accessibility/issues")
    public Map<String, Object> getAccessibilityIssues() {
        return opsInsightService.getAccessibilityIssues();
    }

    private LocalDateTime parseTimeParam(String raw) {
        if (raw == null || raw.trim().isEmpty()) {
            return null;
        }
        String normalized = raw.trim().replace('T', ' ');
        if (normalized.length() == 16) {
            normalized = normalized + ":00";
        }
        try {
            return LocalDateTime.parse(normalized, LOG_TIME_FMT);
        } catch (Exception ignored) {
            return null;
        }
    }

    @ResponseBody
    @PostMapping("/api/killall")
    public Map<String, Object> killAll() {
        Map<String, Object> result = new HashMap<>();
        if (isDangerousOpsBlocked()) {
            result.put("status", "blocked");
            result.put("message", "운영 보호 모드에서는 전체 종료(killall)가 차단됩니다.");
            return result;
        }
        List<String> stopped = new ArrayList<>();
        List<String> errors = new ArrayList<>();
        final String managerId = "EgovMsaManager";

        // 1) Stop modules tracked by this manager (graceful destroy)
        List<MsaScanner.ModuleInfo> modules = scanner.scan();
        MsaScanner.ModuleInfo managerModule = modules.stream()
                .filter(m -> managerId.equals(m.getId()))
                .findFirst()
                .orElse(null);
        for (MsaScanner.ModuleInfo mod : modules) {
            if (managerId.equals(mod.getId())) {
                continue;
            }
            String status = processManager.getStatus(mod.getId(), mod.getPort());
            if ("running".equals(status) || "starting".equals(status)) {
                processManager.stopModule(mod.getId(), mod.getPort());
                stopped.add(mod.getId());
            }
        }

        // 2) Kill remaining Spring Boot / Maven wrapper processes EXCEPT current
        // manager
        // Java 8 compatible PID retrieval
        String jvmName = java.lang.management.ManagementFactory.getRuntimeMXBean().getName();
        long myPid = Long.parseLong(jvmName.split("@")[0]);
        try {
            // Give some time for graceful shutdown
            Thread.sleep(1000);

            // Kill other java processes matching spring-boot:run excluding current PID
            String[] killCmds = {
                    "pgrep -f 'spring-boot:run' | grep -v " + myPid + " | xargs -r kill -9",
                    "pgrep -f 'Dspring-boot.run' | grep -v " + myPid + " | xargs -r kill -9"
            };

            for (String cmd : killCmds) {
                new ProcessBuilder("sh", "-c", cmd).start().waitFor();
            }
        } catch (Exception e) {
            errors.add("Cleanup error: " + e.getMessage());
        }

        // 3) Schedule self-reboot
        try {
            Integer managerPort = managerModule != null ? managerModule.getPort() : null;
            if (managerPort == null || managerPort == 0) {
                managerPort = 18030;
            }
            String rebootLog = AppPaths.resolvePath("logs", "msa-manager-reboot.log").toString();
            String rebootCmd = "sleep 3; "
                    + "if [ -f " + shellQuote(APP_ROOT + "/EgovMsaManager.jar") + " ]; then "
                    + "nohup java -Xms256m -Xmx512m -jar " + shellQuote(APP_ROOT + "/EgovMsaManager.jar") + " --server.port=" + managerPort
                    + " > " + rebootLog + " 2>&1 & "
                    + "elif [ -f " + shellQuote(APP_ROOT + "/EgovMsaManager/target/EgovMsaManager.jar") + " ]; then "
                    + "nohup java -Xms256m -Xmx512m -jar " + shellQuote(APP_ROOT + "/EgovMsaManager/target/EgovMsaManager.jar") + " --server.port="
                    + managerPort + " > " + rebootLog + " 2>&1 & "
                    + "elif [ -d " + shellQuote(AppPaths.moduleRoot() + "/EgovMsaManager") + " ]; then "
                    + "cd " + shellQuote(AppPaths.moduleRoot() + "/EgovMsaManager") + " && "
                    + "nohup mvn -DskipTests spring-boot:run "
                    + "-Dspring-boot.run.arguments=--server.port=" + managerPort
                    + " > " + rebootLog + " 2>&1 & "
                    + "fi";
            new ProcessBuilder("sh", "-c", rebootCmd).start();
        } catch (Exception e) {
            errors.add("Reboot trigger error: " + e.getMessage());
        }

        result.put("status", "ok");
        result.put("stopped", stopped);
        result.put("message", "모든 모듈을 종료했습니다. Manager 모듈은 약 20초 후 자동으로 재시작됩니다.");

        // 4) Exit this process after a short delay to allow the response to reach the
        // browser
        new Thread(() -> {
            try {
                Thread.sleep(2000);
                System.out.println("[System] Self-Restart triggered. Exiting current process...");
                System.exit(0);
            } catch (Exception ignored) {
            }
        }).start();

        return result;
    }

    private void appendWebhookTail(String line) {
        String stamped = "[" + LocalDateTime.now().format(LOG_TIME_FMT) + "] " + line;
        synchronized (webhookTail) {
            webhookTail.addLast(stamped);
            while (webhookTail.size() > WEBHOOK_LOG_LIMIT) {
                webhookTail.removeFirst();
            }
        }
        try (BufferedWriter bw = new BufferedWriter(new FileWriter(WEBHOOK_LOG_FILE, true))) {
            bw.write(stamped);
            bw.newLine();
        } catch (Exception ignored) {
        }
    }

    private void startWebhookWorker(Map<String, Object> payload, String trigger) {
        final String ref = str(payload.get("ref"));
        webhookRunning.set(true);
        webhookLastStarted = LocalDateTime.now().format(LOG_TIME_FMT);
        webhookLastRef = ref;
        appendWebhookTail("START(" + trigger + ") ref=" + (ref.isEmpty() ? "-" : ref));

        new Thread(() -> {
            int rc = -1;
            try {
                if (!syncWebhookSource(payload)) {
                    rc = 3;
                    return;
                }
                Set<String> modules = resolveChangedModules(payload);
                if (modules.isEmpty()) {
                    appendWebhookTail("no target modules detected (payload paths)");
                    rc = 0;
                } else {
                    appendWebhookTail("target modules: " + String.join(",", modules));
                    rc = runModuleAutoDeploy(modules);
                }
            } catch (Exception e) {
                appendWebhookTail("ERROR " + e.getMessage());
                rc = 1;
            } finally {
                webhookLastExitCode = rc;
                webhookLastFinished = LocalDateTime.now().format(LOG_TIME_FMT);
                webhookRunning.set(false);
                if (webhookQueued.compareAndSet(true, false)) {
                    Map<String, Object> next = queuedWebhookPayload == null ? new HashMap<>() : queuedWebhookPayload;
                    queuedWebhookPayload = null;
                    appendWebhookTail("DEQUEUE next webhook");
                    startWebhookWorker(next, "queued");
                }
            }
        }, "msa-webhook-runner").start();
    }

    private boolean syncWebhookSource(Map<String, Object> payload) {
        String root = APP_ROOT;
        appendWebhookTail("git sync start: branch=pass(current tracking)");
        try {
            runWebhookCommand(Arrays.asList("sh", "-lc", "git -C " + shellQuote(root) + " fetch --all --prune"));
            runWebhookCommand(Arrays.asList("sh", "-lc", "git -C " + shellQuote(root) + " pull --ff-only"));
            appendWebhookTail("git sync done");
            return true;
        } catch (Exception e) {
            appendWebhookTail("git sync fail: " + e.getMessage());
            return false;
        }
    }

    private void runWebhookCommand(List<String> cmd) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        Process p = pb.start();
        List<String> lines = new ArrayList<>();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = br.readLine()) != null) {
                lines.add(line);
            }
        }
        int rc = p.waitFor();
        int start = Math.max(0, lines.size() - 40);
        for (int i = start; i < lines.size(); i++) {
            appendWebhookTail("git> " + lines.get(i));
        }
        if (rc != 0) {
            throw new RuntimeException("rc=" + rc);
        }
    }

    private int runModuleAutoDeploy(Set<String> moduleIds) {
        Properties remoteCfg = loadRemoteDeployConfig();
        String webhookMode = normalizeWebhookDeployMode(remoteCfg.getProperty("webhookDeployMode", "jar"));
        boolean remoteBuildEnabled = boolProp(remoteCfg, "webhookRemoteBuildEnabled");
        boolean remoteDeployOnlyEnabled = boolProp(remoteCfg, "webhookRemoteDeployOnlyEnabled");
        boolean remoteActive = !isDangerousOpsBlocked() && (remoteBuildEnabled || remoteDeployOnlyEnabled);
        if (remoteActive) {
            boolean build = remoteBuildEnabled;
            if ("bluegreen".equals(webhookMode)) {
                appendWebhookTail("remote webhook strategy: " + (build ? "build+bluegreen switch" : "sync+bluegreen switch"));
                Map<String, Object> res = executeRemoteBlueGreenDeploy(true, true, build, true);
                if ("ok".equals(str(res.get("status")))) {
                    appendWebhookTail("remote bluegreen ok");
                    return 0;
                }
                appendWebhookTail("remote bluegreen fail: " + str(res.get("message")));
                return 2;
            }
            appendWebhookTail("remote webhook strategy: " + (build ? "build+jar deploy+zero-downtime" : "jar deploy+zero-downtime"));
            return runRemoteWebhookAutoDeploy(moduleIds, build);
        }

        List<MsaScanner.ModuleInfo> modules = scanner.scan();
        Map<String, MsaScanner.ModuleInfo> byId = modules.stream()
                .collect(Collectors.toMap(MsaScanner.ModuleInfo::getId, m -> m, (a, b) -> a));
        boolean buildAllowed = !isBuildBlocked();
        appendWebhookTail("deploy strategy: " + (buildAllowed ? "build+zero-downtime" : "deploy-only zero-downtime"));
        int fail = 0;
        for (String moduleId : moduleIds) {
            MsaScanner.ModuleInfo mod = byId.get(moduleId);
            if (mod == null) {
                appendWebhookTail("skip unknown module: " + moduleId);
                continue;
            }
            if ("EgovMsaManager".equals(mod.getId())) {
                appendWebhookTail("skip self module auto deploy: EgovMsaManager");
                continue;
            }
            appendWebhookTail("deploy start: " + mod.getId());
            String res = buildAllowed
                    ? processManager.buildDeployZeroDowntimeModule(mod)
                    : processManager.deployZeroDowntimeModule(mod);
            if (!"ok".equals(res)) {
                fail++;
                appendWebhookTail("deploy fail: " + mod.getId() + " -> " + res);
            } else {
                appendWebhookTail("deploy ok: " + mod.getId());
            }
        }
        appendWebhookTail("DONE deploy failures=" + fail);
        return fail == 0 ? 0 : 2;
    }

    private int runRemoteWebhookAutoDeploy(Set<String> moduleIds, boolean build) {
        int fail = 0;
        for (String moduleId : moduleIds) {
            if ("EgovMsaManager".equals(moduleId)) {
                appendWebhookTail("skip remote self module: EgovMsaManager");
                continue;
            }
            Map<String, Object> res = runRemoteModuleDeployInternal(moduleId, build);
            if (!"ok".equals(str(res.get("status")))) {
                fail++;
                appendWebhookTail("remote deploy fail: " + moduleId + " -> " + str(res.get("message")));
            } else {
                appendWebhookTail("remote deploy ok: " + moduleId);
            }
        }
        appendWebhookTail("DONE remote deploy failures=" + fail);
        return fail == 0 ? 0 : 2;
    }

    private Set<String> resolveChangedModules(Map<String, Object> payload) {
        Set<String> files = extractChangedFiles(payload);
        Set<String> modules = new LinkedHashSet<>();
        for (String raw : files) {
            String f = raw.replace("\\", "/");
            if (f.startsWith("/")) {
                f = f.substring(1);
            }
            if (f.startsWith("module/")) {
                String rest = f.substring("module/".length());
                int slash = rest.indexOf('/');
                String module = slash > 0 ? rest.substring(0, slash) : rest;
                if (!module.trim().isEmpty()) {
                    modules.add(module.trim());
                }
            }
        }
        return modules;
    }

    private Set<String> extractChangedFiles(Map<String, Object> payload) {
        if (payload == null) {
            return Collections.emptySet();
        }
        Set<String> out = new LinkedHashSet<>();
        addPathArray(out, payload.get("added"));
        addPathArray(out, payload.get("modified"));
        addPathArray(out, payload.get("removed"));
        Object headCommit = payload.get("head_commit");
        if (headCommit instanceof Map) {
            Map<?, ?> m = (Map<?, ?>) headCommit;
            addPathArray(out, m.get("added"));
            addPathArray(out, m.get("modified"));
            addPathArray(out, m.get("removed"));
        }
        Object commits = payload.get("commits");
        if (commits instanceof List) {
            for (Object c : (List<?>) commits) {
                if (c instanceof Map) {
                    Map<?, ?> m = (Map<?, ?>) c;
                    addPathArray(out, m.get("added"));
                    addPathArray(out, m.get("modified"));
                    addPathArray(out, m.get("removed"));
                }
            }
        }
        return out;
    }

    private void addPathArray(Set<String> out, Object src) {
        if (!(src instanceof List)) {
            return;
        }
        for (Object v : (List<?>) src) {
            String s = str(v);
            if (!s.isEmpty()) {
                out.add(s);
            }
        }
    }

    private Map<String, Object> executeRemoteInitialDeploy() {
        Map<String, Object> out = new HashMap<>();
        Properties cfg = loadRemoteDeployConfig();
        String validate = validateRemoteConfig(cfg);
        if (!validate.isEmpty()) {
            out.put("status", "error");
            out.put("message", validate);
            return out;
        }
        try {
            appendRemoteLog("INIT start");
            String remoteDir = cfg.getProperty("remoteDir", APP_ROOT);
            String pack = "/tmp/carbosys-initial-" + System.currentTimeMillis() + ".tar.gz";
            runLocalOrThrow(Arrays.asList("sh", "-lc",
                    "tar -czf " + shellQuote(pack)
                            + " -C " + shellQuote(APP_ROOT) + " Dockerfile docker-compose.yml entrypoint.sh msa-mappings.yml msa-ports.yml module"));
            runSshOrThrow(cfg, "mkdir -p " + shellQuote(remoteDir));
            runScpOrThrow(cfg, pack, remoteDir + "/carbosys-initial.tar.gz");
            runSshOrThrow(cfg, "cd " + shellQuote(remoteDir)
                    + " && tar -xzf carbosys-initial.tar.gz && rm -f carbosys-initial.tar.gz && docker compose up -d --build");
            try {
                Files.deleteIfExists(Paths.get(pack));
            } catch (Exception ignored) {
            }
            appendRemoteLog("INIT done");
            out.put("status", "ok");
            out.put("message", "원격 초기 배포 완료");
            return out;
        } catch (Exception e) {
            appendRemoteLog("INIT fail: " + e.getMessage());
            out.put("status", "error");
            out.put("message", "원격 초기 배포 실패: " + e.getMessage());
            return out;
        }
    }

    private Map<String, Object> executeRemoteAutoDeployAll(boolean build) {
        Map<String, Object> out = new HashMap<>();
        Properties cfg = loadRemoteDeployConfig();
        String validate = validateRemoteConfig(cfg);
        if (!validate.isEmpty()) {
            out.put("status", "error");
            out.put("message", validate);
            return out;
        }
        try {
            appendRemoteLog("AUTO-ALL start build=" + build);
            if (build) {
                appendRemoteLog("AUTO-ALL local build start");
                runLocalOrThrow(Arrays.asList("sh", "-lc", "cd " + shellQuote(APP_ROOT) + " && mvn -DskipTests package"));
                appendRemoteLog("AUTO-ALL local build done");
            }
            String remoteDir = cfg.getProperty("remoteDir", APP_ROOT);
            String pack = "/tmp/carbosys-auto-all-" + System.currentTimeMillis() + ".tar.gz";
            runLocalOrThrow(Arrays.asList("sh", "-lc",
                    "tar -czf " + shellQuote(pack)
                            + " -C " + shellQuote(APP_ROOT) + " Dockerfile docker-compose.yml entrypoint.sh msa-mappings.yml msa-ports.yml module"));
            runSshOrThrow(cfg, "mkdir -p " + shellQuote(remoteDir));
            runScpOrThrow(cfg, pack, remoteDir + "/carbosys-auto-all.tar.gz");
            runSshOrThrow(cfg, "cd " + shellQuote(remoteDir)
                    + " && tar -xzf carbosys-auto-all.tar.gz && rm -f carbosys-auto-all.tar.gz && docker compose up -d --build");
            try {
                Files.deleteIfExists(Paths.get(pack));
            } catch (Exception ignored) {
            }
            appendRemoteLog("AUTO-ALL done");
            out.put("status", "ok");
            out.put("message", "원격 전체 자동배포 완료" + (build ? " (빌드 포함)" : " (빌드 제외)"));
            return out;
        } catch (Exception e) {
            appendRemoteLog("AUTO-ALL fail: " + e.getMessage());
            out.put("status", "error");
            out.put("message", "원격 전체 자동배포 실패: " + e.getMessage());
            return out;
        }
    }

    private Map<String, Object> executeRemoteSourceDeploy() {
        Map<String, Object> out = new HashMap<>();
        Properties cfg = loadRemoteDeployConfig();
        String validate = validateRemoteConfig(cfg);
        if (!validate.isEmpty()) {
            out.put("status", "error");
            out.put("message", validate);
            return out;
        }
        try {
            appendRemoteLog("SOURCE sync start");
            String remoteDir = cfg.getProperty("remoteDir", APP_ROOT);
            String pack = "/tmp/carbosys-source-" + System.currentTimeMillis() + ".tar.gz";
            runLocalOrThrow(Arrays.asList("sh", "-lc",
                    "tar -czf " + shellQuote(pack)
                            + " -C " + shellQuote(APP_ROOT) + " Dockerfile docker-compose.yml entrypoint.sh msa-mappings.yml msa-ports.yml module"));
            runSshOrThrow(cfg, "mkdir -p " + shellQuote(remoteDir));
            runScpOrThrow(cfg, pack, remoteDir + "/carbosys-source.tar.gz");
            runSshOrThrow(cfg, "cd " + shellQuote(remoteDir)
                    + " && tar -xzf carbosys-source.tar.gz && rm -f carbosys-source.tar.gz");
            try {
                Files.deleteIfExists(Paths.get(pack));
            } catch (Exception ignored) {
            }
            appendRemoteLog("SOURCE sync done");
            out.put("status", "ok");
            out.put("message", "소스코드 배포 완료");
            return out;
        } catch (Exception e) {
            appendRemoteLog("SOURCE sync fail: " + e.getMessage());
            out.put("status", "error");
            out.put("message", "소스코드 배포 실패: " + e.getMessage());
            return out;
        }
    }

    private Map<String, Object> executeRemoteBuildOnly() {
        Map<String, Object> out = new HashMap<>();
        try {
            appendRemoteLog("BUILD-ONLY start");
            runLocalOrThrow(Arrays.asList("sh", "-lc", "cd " + shellQuote(APP_ROOT) + " && mvn -DskipTests package"));
            appendRemoteLog("BUILD-ONLY done");
            out.put("status", "ok");
            out.put("message", "로컬 빌드 완료");
            return out;
        } catch (Exception e) {
            appendRemoteLog("BUILD-ONLY fail: " + e.getMessage());
            out.put("status", "error");
            out.put("message", "로컬 빌드 실패: " + e.getMessage());
            return out;
        }
    }

    private Map<String, Object> executeRemoteDockerColorUp(String color, boolean includeManager, boolean homeOnly, boolean build) {
        Map<String, Object> out = new HashMap<>();
        Properties cfg = loadRemoteDeployConfig();
        String validate = validateRemoteConfig(cfg);
        if (!validate.isEmpty()) {
            out.put("status", "error");
            out.put("message", validate);
            return out;
        }
        String target = "green".equals(color) ? "green" : "blue";
        String composeFile = "green".equals(target)
                ? cfg.getProperty("composeGreenFile", "docker-compose.green.yml")
                : cfg.getProperty("composeBlueFile", "docker-compose.blue.yml");
        String healthUrl = "green".equals(target)
                ? cfg.getProperty("greenGatewayHealthUrl", "http://localhost:9001/actuator/health")
                : cfg.getProperty("blueGatewayHealthUrl", "http://localhost:9000/actuator/health");
        String remoteDir = cfg.getProperty("remoteDir", APP_ROOT);
        try {
            String services = composeServiceArgs(cfg, includeManager, homeOnly);
            appendRemoteLog("COLOR-UP start color=" + target + ", build=" + build + ", services=" + services);
            String upCmd = "cd " + shellQuote(remoteDir) + " && docker compose -f " + shellQuote(composeFile)
                    + " up -d " + (build ? "--build " : "") + services;
            runSshOrThrow(cfg, upCmd);
            runSshOrThrow(cfg, "for i in $(seq 1 45); do curl -fsS " + shellQuote(healthUrl)
                    + " >/dev/null && exit 0; sleep 2; done; exit 1");
            appendRemoteLog("COLOR-UP health ok color=" + target + " url=" + healthUrl);

            cfg.setProperty("activeColor", target);
            saveRemoteDeployConfig(cfg);

            out.put("status", "ok");
            out.put("message", "도커 " + target + " 기동 완료 (" + healthUrl + ")");
            out.put("activeColor", target);
            return out;
        } catch (Exception e) {
            appendRemoteLog("COLOR-UP fail color=" + target + ": " + e.getMessage());
            out.put("status", "error");
            out.put("message", "도커 " + target + " 기동 실패: " + e.getMessage());
            out.put("activeColor", cfg.getProperty("activeColor", "blue"));
            return out;
        }
    }

    private Map<String, Object> executeRemoteNginxAction(String action) {
        Map<String, Object> out = new HashMap<>();
        Properties cfg = loadRemoteDeployConfig();
        String validate = validateRemoteConfig(cfg);
        if (!validate.isEmpty()) {
            out.put("status", "error");
            out.put("message", validate);
            return out;
        }
        String switchCmd = cfg.getProperty("nginxSwitchCmd", "").trim();
        String reloadCmd = cfg.getProperty("nginxReloadCmd", "nginx -s reload").trim();
        try {
            if ("blue".equals(action) || "green".equals(action)) {
                if (switchCmd.isEmpty()) {
                    out.put("status", "error");
                    out.put("message", "nginxSwitchCmd 설정이 필요합니다.");
                    return out;
                }
                runSshOrThrow(cfg, switchCmd.replace("{color}", action));
                appendRemoteLog("NGINX switch -> " + action);
                if (!reloadCmd.isEmpty()) {
                    runSshOrThrow(cfg, reloadCmd);
                    appendRemoteLog("NGINX reload after switch");
                }
                cfg.setProperty("activeColor", action);
                saveRemoteDeployConfig(cfg);
                out.put("status", "ok");
                out.put("message", "nginx 전환 완료: " + action);
                out.put("activeColor", action);
                return out;
            }
            if ("reload".equals(action)) {
                if (reloadCmd.isEmpty()) {
                    out.put("status", "error");
                    out.put("message", "nginxReloadCmd 설정이 필요합니다.");
                    return out;
                }
                runSshOrThrow(cfg, reloadCmd);
                appendRemoteLog("NGINX reload");
                out.put("status", "ok");
                out.put("message", "nginx reload 완료");
                out.put("activeColor", cfg.getProperty("activeColor", "blue"));
                return out;
            }
            out.put("status", "error");
            out.put("message", "action은 blue|green|reload 중 하나여야 합니다.");
            return out;
        } catch (Exception e) {
            appendRemoteLog("NGINX action fail(" + action + "): " + e.getMessage());
            out.put("status", "error");
            out.put("message", "nginx 명령 실패: " + e.getMessage());
            out.put("activeColor", cfg.getProperty("activeColor", "blue"));
            return out;
        }
    }

    private Map<String, Object> executeRemoteBlueGreenDeploy(boolean includeManager, boolean homeOnly, boolean build, boolean syncSources) {
        Map<String, Object> out = new HashMap<>();
        Properties cfg = loadRemoteDeployConfig();
        String validate = validateRemoteConfig(cfg);
        if (!validate.isEmpty()) {
            out.put("status", "error");
            out.put("message", validate);
            return out;
        }
        String blueCompose = cfg.getProperty("composeBlueFile", "docker-compose.blue.yml");
        String greenCompose = cfg.getProperty("composeGreenFile", "docker-compose.green.yml");
        String blueHealthUrl = cfg.getProperty("blueGatewayHealthUrl", "http://localhost:9000/actuator/health");
        String greenHealthUrl = cfg.getProperty("greenGatewayHealthUrl", "http://localhost:9001/actuator/health");
        String switchCmd = cfg.getProperty("nginxSwitchCmd", "").trim();
        String reloadCmd = cfg.getProperty("nginxReloadCmd", "nginx -s reload").trim();
        String remoteDir = cfg.getProperty("remoteDir", APP_ROOT);
        try {
            appendRemoteLog("BG deploy start (final port=9000 blue), includeManager=" + includeManager + ", homeOnly=" + homeOnly + ", build=" + build + ", syncSources=" + syncSources);
            if (build) {
                appendRemoteLog("BG local build start");
                runLocalOrThrow(Arrays.asList("sh", "-lc", "cd " + shellQuote(APP_ROOT) + " && mvn -DskipTests package"));
                appendRemoteLog("BG local build done");
            }
            if (syncSources) {
                String pack = "/tmp/carbosys-bg-" + System.currentTimeMillis() + ".tar.gz";
                runLocalOrThrow(Arrays.asList("sh", "-lc",
                        "tar -czf " + shellQuote(pack)
                                + " -C " + shellQuote(APP_ROOT) + " Dockerfile docker-compose.yml entrypoint.sh msa-mappings.yml msa-ports.yml module"));
                runSshOrThrow(cfg, "mkdir -p " + shellQuote(remoteDir));
                runScpOrThrow(cfg, pack, remoteDir + "/carbosys-bg.tar.gz");
                runSshOrThrow(cfg, "cd " + shellQuote(remoteDir)
                        + " && tar -xzf carbosys-bg.tar.gz && rm -f carbosys-bg.tar.gz");
                try {
                    Files.deleteIfExists(Paths.get(pack));
                } catch (Exception ignored) {
                }
            }
            String services = composeServiceArgs(cfg, includeManager, homeOnly);
            String upGreen = "cd " + shellQuote(remoteDir)
                    + " && docker compose -f " + shellQuote(greenCompose) + " up -d "
                    + ((build || syncSources) ? "--build " : "") + services;
            runSshOrThrow(cfg, upGreen);

            runSshOrThrow(cfg, "for i in $(seq 1 45); do curl -fsS " + shellQuote(greenHealthUrl)
                    + " >/dev/null && exit 0; sleep 2; done; exit 1");
            appendRemoteLog("BG green health ok: " + greenHealthUrl);
            if (!switchCmd.isEmpty()) {
                runSshOrThrow(cfg, switchCmd.replace("{color}", "green"));
            }
            if (!reloadCmd.isEmpty()) {
                runSshOrThrow(cfg, reloadCmd);
            }
            appendRemoteLog("BG nginx switched to green");

            runSshOrThrow(cfg, "cd " + shellQuote(remoteDir) + " && docker compose -f " + shellQuote(blueCompose) + " stop");
            appendRemoteLog("BG blue stopped");
            String upBlue = "cd " + shellQuote(remoteDir)
                    + " && docker compose -f " + shellQuote(blueCompose) + " up -d "
                    + ((build || syncSources) ? "--build " : "") + services;
            runSshOrThrow(cfg, upBlue);
            runSshOrThrow(cfg, "for i in $(seq 1 45); do curl -fsS " + shellQuote(blueHealthUrl)
                    + " >/dev/null && exit 0; sleep 2; done; exit 1");
            appendRemoteLog("BG blue health ok: " + blueHealthUrl);

            cfg.setProperty("activeColor", "blue");
            saveRemoteDeployConfig(cfg);

            out.put("status", "ok");
            out.put("message", "Blue/Green 전환 완료 (최종 blue:9000 유지, green:9001 자동 종료)"
                    + (build ? " (빌드 포함)" : (syncSources ? " (빌드 제외+전송)" : " (전송/빌드 없이 스위치)")));
            out.put("activeColor", "blue");
            return out;
        } catch (Exception e) {
            appendRemoteLog("BG deploy fail: " + e.getMessage());
            out.put("status", "error");
            out.put("message", "Blue/Green 전환 실패: " + e.getMessage());
            out.put("activeColor", "blue");
            return out;
        } finally {
            // Always converge to blue(9000) and stop green(9001), even on failure.
            try {
                if (!switchCmd.isEmpty()) {
                    runSshOrThrow(cfg, switchCmd.replace("{color}", "blue"));
                }
                if (!reloadCmd.isEmpty()) {
                    runSshOrThrow(cfg, reloadCmd);
                }
                appendRemoteLog("BG finalizer: nginx switched to blue");
            } catch (Exception e) {
                appendRemoteLog("BG finalizer warn(nginx): " + e.getMessage());
            }
            try {
                runSshOrThrow(cfg, "cd " + shellQuote(remoteDir) + " && docker compose -f " + shellQuote(greenCompose) + " stop");
                appendRemoteLog("BG finalizer: green stopped");
            } catch (Exception e) {
                appendRemoteLog("BG finalizer warn(green stop): " + e.getMessage());
            }
        }
    }

    private String composeServiceArgs(Properties cfg, boolean includeManager, boolean homeOnly) {
        String base = str(cfg.getProperty("baseServices", "eureka-server config-server gateway-server"));
        String home = str(cfg.getProperty("homeService", "egov-home"));
        String manager = str(cfg.getProperty("managerService", "egov-msa-manager"));
        StringBuilder sb = new StringBuilder();
        if (!base.isEmpty()) {
            sb.append(base);
        }
        if (homeOnly) {
            if (!home.isEmpty()) {
                if (sb.length() > 0) sb.append(" ");
                sb.append(home);
            }
        }
        if (includeManager && !manager.isEmpty()) {
            if (sb.length() > 0) sb.append(" ");
            sb.append(manager);
        }
        return sb.toString();
    }

    private Map<String, Object> runRemoteModuleDeployInternal(String moduleId, boolean build) {
        Map<String, Object> out = new HashMap<>();
        Properties cfg = loadRemoteDeployConfig();
        String validate = validateRemoteConfig(cfg);
        if (!validate.isEmpty()) {
            out.put("status", "error");
            out.put("message", validate);
            return out;
        }
        try {
            MsaScanner.ModuleInfo mod = scanner.scan().stream()
                    .filter(m -> moduleId.equals(m.getId()))
                    .findFirst().orElse(null);
            if (mod == null || !mod.isJavaRunnable()) {
                out.put("status", "error");
                out.put("message", "모듈을 찾을 수 없거나 Java 실행 대상이 아닙니다: " + moduleId);
                return out;
            }
            if (build) {
                appendRemoteLog("BUILD start: " + moduleId);
                runLocalOrThrow(Arrays.asList("sh", "-lc",
                        "cd " + shellQuote(mod.getDir()) + " && mvn -DskipTests package"));
                appendRemoteLog("BUILD done: " + moduleId);
            }

            String jarLocal = mod.getDir() + "/target/" + moduleId + ".jar";
            if (!new File(jarLocal).exists()) {
                out.put("status", "error");
                out.put("message", "배포할 jar가 없습니다: " + jarLocal);
                return out;
            }

            String remoteTmp = "/tmp/" + moduleId + "-" + System.currentTimeMillis() + ".jar";
            String containerName = cfg.getProperty("containerName", "carbosys-app");
            String managerUrl = cfg.getProperty("managerUrl", "http://localhost:18030");

            appendRemoteLog("UPLOAD start: " + moduleId);
            runScpOrThrow(cfg, jarLocal, remoteTmp);
            runSshOrThrow(cfg, "docker cp " + shellQuote(remoteTmp) + " "
                    + shellQuote(containerName + ":" + APP_ROOT + "/" + moduleId + ".jar")
                    + " && rm -f " + shellQuote(remoteTmp));

            appendRemoteLog("RELOAD start: " + moduleId);
            String call = "curl -sS -X POST " + shellQuote(managerUrl + "/admin/msa/api/modules/" + moduleId + "/deploy-zerodowntime");
            runSshOrThrow(cfg, "docker exec " + shellQuote(containerName) + " sh -lc " + shellQuote(call));

            appendRemoteLog("RELOAD done: " + moduleId);
            out.put("status", "ok");
            out.put("message", "원격 배포 완료: " + moduleId + (build ? " (build 포함)" : " (build 제외)"));
            return out;
        } catch (Exception e) {
            appendRemoteLog("DEPLOY fail " + moduleId + ": " + e.getMessage());
            out.put("status", "error");
            out.put("message", "원격 배포 실패: " + e.getMessage());
            return out;
        }
    }

    private Properties loadRemoteDeployConfig() {
        Properties p = new Properties();
        File f = new File(REMOTE_DEPLOY_CONFIG_FILE);
        if (!f.exists()) {
            return p;
        }
        try (FileInputStream in = new FileInputStream(f)) {
            p.load(in);
        } catch (Exception ignored) {
        }
        return p;
    }

    private void saveRemoteDeployConfig(Properties p) {
        ensureLogsDir();
        try (FileOutputStream out = new FileOutputStream(REMOTE_DEPLOY_CONFIG_FILE)) {
            p.store(out, "msa remote deploy config");
        } catch (Exception ignored) {
        }
    }

    private List<Map<String, Object>> loadProjectRegistry() {
        File f = new File(PROJECT_REGISTRY_FILE);
        if (!f.exists()) {
            return new ArrayList<>();
        }
        try (FileInputStream in = new FileInputStream(f)) {
            Yaml yaml = new Yaml();
            Object root = yaml.load(in);
            if (!(root instanceof Map)) {
                return new ArrayList<>();
            }
            Object listObj = ((Map<?, ?>) root).get("projects");
            if (!(listObj instanceof List)) {
                return new ArrayList<>();
            }
            List<Map<String, Object>> out = new ArrayList<>();
            for (Object item : (List<?>) listObj) {
                if (!(item instanceof Map)) {
                    continue;
                }
                Map<String, Object> row = new LinkedHashMap<>();
                ((Map<?, ?>) item).forEach((k, v) -> row.put(String.valueOf(k), v));
                String id = str(row.get("id")).replaceAll("[^A-Za-z0-9._-]", "");
                if (id.isEmpty()) {
                    continue;
                }
                out.add(normalizeProjectInput(id, row));
            }
            return out;
        } catch (Exception ignored) {
            return new ArrayList<>();
        }
    }

    private synchronized void saveProjectRegistry(List<Map<String, Object>> projects) {
        ensureLogsDir();
        DumperOptions opts = new DumperOptions();
        opts.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        opts.setPrettyFlow(true);
        Yaml yaml = new Yaml(opts);
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("projects", projects == null ? new ArrayList<>() : projects);
        try (FileWriter fw = new FileWriter(PROJECT_REGISTRY_FILE)) {
            yaml.dump(root, fw);
        } catch (Exception ignored) {
        }
    }

    private Map<String, Object> normalizeProjectInput(String id, Map<String, Object> src) {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("id", id);
        p.put("name", firstNonEmpty(str(src.get("name")), id));
        p.put("enabled", !"false".equalsIgnoreCase(str(src.get("enabled"))));
        p.put("host", str(src.get("host")));
        p.put("port", firstNonEmpty(str(src.get("port")), "22"));
        p.put("user", str(src.get("user")));
        p.put("keyPath", str(src.get("keyPath")));
        p.put("password", str(src.get("password")));
        p.put("rootDir", firstNonEmpty(str(src.get("rootDir")), APP_ROOT));
        p.put("managerUrl", firstNonEmpty(str(src.get("managerUrl")), "http://localhost:18030"));
        p.put("containerName", firstNonEmpty(str(src.get("containerName")), "carbosys-app"));
        p.put("updatedAt", LocalDateTime.now().format(LOG_TIME_FMT));
        return p;
    }

    private Map<String, Object> sanitizeProjectOutput(Map<String, Object> p) {
        Map<String, Object> out = new LinkedHashMap<>(p);
        String pwd = str(p.get("password"));
        out.put("passwordMasked", maskToken(pwd));
        out.put("hasPassword", !pwd.isEmpty());
        out.remove("password");
        return out;
    }

    private Map<String, Object> findProject(String id) {
        String target = str(id).replaceAll("[^A-Za-z0-9._-]", "");
        if (target.isEmpty()) {
            return null;
        }
        for (Map<String, Object> p : loadProjectRegistry()) {
            if (target.equals(str(p.get("id")))) {
                return p;
            }
        }
        return null;
    }

    private Properties sshConfigFromProject(Map<String, Object> p) {
        Properties cfg = new Properties();
        cfg.setProperty("host", str(p.get("host")));
        cfg.setProperty("port", firstNonEmpty(str(p.get("port")), "22"));
        cfg.setProperty("user", str(p.get("user")));
        cfg.setProperty("keyPath", str(p.get("keyPath")));
        cfg.setProperty("password", str(p.get("password")));
        return cfg;
    }

    private Map<String, Object> verifySshPermission(HttpServletRequest request) {
        String required = firstNonEmpty(System.getenv(SSH_EDIT_TOKEN_ENV), "");
        if (required.isEmpty()) {
            return Map.of(
                    "status", "error",
                    "message", "원격 SSH 수정 기능이 비활성화되어 있습니다. 환경변수 " + SSH_EDIT_TOKEN_ENV + " 설정이 필요합니다.");
        }
        String provided = firstNonEmpty(request.getHeader("X-MSA-SSH-TOKEN"), request.getParameter("token"));
        if (!required.equals(provided)) {
            return Map.of("status", "error", "message", "원격 SSH 권한 토큰이 유효하지 않습니다.");
        }
        return null;
    }

    private boolean boolProp(Properties p, String key) {
        return Boolean.parseBoolean(str(p.getProperty(key, "false")));
    }

    private String validateRemoteConfig(Properties p) {
        if (str(p.getProperty("host")).isEmpty()) return "원격 host 설정이 필요합니다.";
        if (str(p.getProperty("user")).isEmpty()) return "원격 user 설정이 필요합니다.";
        return "";
    }

    private void appendRemoteLog(String line) {
        String stamped = "[" + LocalDateTime.now().format(LOG_TIME_FMT) + "] " + line;
        try (BufferedWriter bw = new BufferedWriter(new FileWriter(REMOTE_DEPLOY_LOG_FILE, true))) {
            bw.write(stamped);
            bw.newLine();
        } catch (Exception ignored) {
        }
    }

    private List<String> readTail(String file, int maxLines) {
        File f = new File(file);
        if (!f.exists()) {
            return new ArrayList<>();
        }
        List<String> lines = new ArrayList<>();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(f), StandardCharsets.UTF_8))) {
            String line;
            while ((line = br.readLine()) != null) {
                lines.add(line);
            }
        } catch (Exception ignored) {
        }
        if (lines.size() <= maxLines) {
            return lines;
        }
        return lines.subList(lines.size() - maxLines, lines.size());
    }

    private void runLocalOrThrow(List<String> cmd) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        Process p = pb.start();
        List<String> out = new ArrayList<>();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = br.readLine()) != null) {
                out.add(line);
            }
        }
        int rc = p.waitFor();
        for (String line : out) {
            appendRemoteLog(line);
        }
        if (rc != 0) {
            throw new RuntimeException("command failed rc=" + rc);
        }
    }

    private void runSshOrThrow(Properties cfg, String remoteCmd) throws Exception {
        runLocalOrThrow(buildSshCommand(cfg, remoteCmd));
    }

    private Map<String, Object> runSshCapture(Properties cfg, String remoteCmd) throws Exception {
        return runLocalCapture(buildSshCommand(cfg, remoteCmd));
    }

    private void runScpOrThrow(Properties cfg, String localPath, String remotePath) throws Exception {
        runLocalOrThrow(buildScpCommand(cfg, localPath, remotePath));
    }

    private List<String> buildSshCommand(Properties cfg, String remoteCmd) {
        String host = cfg.getProperty("host", "");
        String user = cfg.getProperty("user", "");
        String port = cfg.getProperty("port", "22");
        String keyPath = cfg.getProperty("keyPath", "");
        String password = cfg.getProperty("password", "");

        String base = "ssh -o StrictHostKeyChecking=no -p " + shellQuote(port) + " ";
        if (!keyPath.trim().isEmpty()) {
            base += "-i " + shellQuote(keyPath) + " ";
        }
        base += shellQuote(user + "@" + host) + " " + shellQuote(remoteCmd);
        if (!password.trim().isEmpty()) {
            base = "sshpass -p " + shellQuote(password) + " " + base;
        }
        return Arrays.asList("sh", "-lc", base);
    }

    private List<String> buildScpCommand(Properties cfg, String localPath, String remotePath) {
        String host = cfg.getProperty("host", "");
        String user = cfg.getProperty("user", "");
        String port = cfg.getProperty("port", "22");
        String keyPath = cfg.getProperty("keyPath", "");
        String password = cfg.getProperty("password", "");

        String base = "scp -o StrictHostKeyChecking=no -P " + shellQuote(port) + " ";
        if (!keyPath.trim().isEmpty()) {
            base += "-i " + shellQuote(keyPath) + " ";
        }
        base += shellQuote(localPath) + " " + shellQuote(user + "@" + host + ":" + remotePath);
        if (!password.trim().isEmpty()) {
            base = "sshpass -p " + shellQuote(password) + " " + base;
        }
        return Arrays.asList("sh", "-lc", base);
    }

    private String shellQuote(String s) {
        String v = s == null ? "" : s;
        return "'" + v.replace("'", "'\"'\"'") + "'";
    }

    private Map<String, Object> runLocalCapture(List<String> cmd) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        Process p = pb.start();
        StringBuilder out = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = br.readLine()) != null) {
                out.append(line).append('\n');
            }
        }
        int rc = p.waitFor();
        Map<String, Object> res = new LinkedHashMap<>();
        res.put("exitCode", rc);
        res.put("output", out.toString());
        if (rc != 0) {
            throw new RuntimeException("command failed rc=" + rc + ", output=" + out);
        }
        return res;
    }

    private String resolveWebhookToken() {
        Properties p = loadWebhookConfig();
        String saved = p.getProperty("token", "").trim();
        if (!saved.isEmpty()) {
            return saved;
        }
        try {
            String env = System.getenv("MSA_WEBHOOK_SECRET");
            if (env != null && !env.trim().isEmpty()) {
                return env.trim();
            }
        } catch (Exception ignored) {
        }
        return "";
    }

    private Properties loadWebhookConfig() {
        Properties p = new Properties();
        File f = new File(WEBHOOK_CONFIG_FILE);
        if (!f.exists()) {
            return p;
        }
        try (FileInputStream in = new FileInputStream(f)) {
            p.load(in);
        } catch (Exception ignored) {
        }
        return p;
    }

    private Properties loadRuntimeConfig() {
        Properties p = new Properties();
        File f = new File(RUNTIME_CONFIG_FILE);
        if (!f.exists()) {
            return p;
        }
        try (FileInputStream in = new FileInputStream(f)) {
            p.load(in);
        } catch (Exception ignored) {
        }
        return p;
    }

    private void saveWebhookConfig(Properties p) {
        ensureLogsDir();
        try (FileOutputStream out = new FileOutputStream(WEBHOOK_CONFIG_FILE)) {
            p.store(out, "msa webhook config");
        } catch (Exception ignored) {
        }
    }

    private void saveRuntimeConfig(Properties p) {
        ensureLogsDir();
        try (FileOutputStream out = new FileOutputStream(RUNTIME_CONFIG_FILE)) {
            p.store(out, "msa runtime config");
        } catch (Exception ignored) {
        }
    }

    private void ensureLogsDir() {
        try {
            Path dir = AppPaths.logsDir();
            if (!Files.exists(dir)) {
                Files.createDirectories(dir);
            }
        } catch (Exception ignored) {
        }
    }

    private String maskToken(String token) {
        String t = token == null ? "" : token.trim();
        if (t.isEmpty()) {
            return "";
        }
        if (t.length() <= 6) {
            return "***";
        }
        return t.substring(0, 3) + "..." + t.substring(t.length() - 3);
    }

    private String firstNonEmpty(String... vals) {
        if (vals == null) {
            return "";
        }
        for (String v : vals) {
            if (v != null && !v.trim().isEmpty()) {
                return v.trim();
            }
        }
        return "";
    }

    private String str(Object v) {
        return v == null ? "" : String.valueOf(v).trim();
    }

    private String getServerMode() {
        Properties p = loadRuntimeConfig();
        String configured = normalizeServerMode(p.getProperty(RUNTIME_MODE_KEY, ""));
        if (!configured.isEmpty()) {
            return configured;
        }
        String env = normalizeServerMode(System.getenv("MSA_SERVER_MODE"));
        if (!env.isEmpty()) {
            return env;
        }
        String profile = str(System.getenv("SPRING_PROFILES_ACTIVE")).toLowerCase();
        if (profile.contains("prod") || profile.contains("release")) {
            return MODE_PROD;
        }
        return MODE_DEV;
    }

    private boolean isDangerousOpsBlocked() {
        return MODE_PROD.equals(getServerMode());
    }

    private boolean isBuildBlocked() {
        return MODE_PROD.equals(getServerMode());
    }

    private String normalizeServerMode(Object raw) {
        String v = str(raw).toLowerCase();
        if ("prod".equals(v) || "production".equals(v) || "운영".equals(v)) {
            return MODE_PROD;
        }
        if ("dev".equals(v) || "development".equals(v) || "개발".equals(v)) {
            return MODE_DEV;
        }
        return "";
    }

    private String normalizeColor(String raw) {
        String v = str(raw).toLowerCase();
        return "green".equals(v) ? "green" : "blue";
    }

    private String normalizeWebhookDeployMode(String raw) {
        String v = str(raw).toLowerCase();
        return "bluegreen".equals(v) ? "bluegreen" : "jar";
    }

    private String randomHex(int bytes) {
        byte[] b = new byte[Math.max(16, bytes)];
        new SecureRandom().nextBytes(b);
        StringBuilder sb = new StringBuilder();
        for (byte x : b) {
            sb.append(String.format("%02x", x));
        }
        return sb.toString();
    }
}
