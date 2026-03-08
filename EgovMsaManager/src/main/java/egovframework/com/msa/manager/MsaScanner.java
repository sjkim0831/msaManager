package egovframework.com.msa.manager;

import lombok.Builder;
import lombok.Data;
import org.yaml.snakeyaml.Yaml;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.io.File;
import java.io.FileInputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class MsaScanner {
    private static final String ROOT_PATH = AppPaths.root();
    private static final String MODULE_ROOT = AppPaths.moduleRoot();
    private static final List<String> PORT_REGISTRY_CANDIDATES = List.of(
            AppPaths.resolvePath("msa-ports.yml").toString());
    private static final List<String> MAPPING_FILE_CANDIDATES = List.of(
            AppPaths.resolvePath("msa-mappings.yml").toString());
    private static final Pattern ARTIFACT_ID_PATTERN = Pattern.compile("<artifactId>\\s*([^<\\s]+)\\s*</artifactId>");
    @Data
    @Builder
    public static class ModuleInfo {
        private String id;
        private String name;
        private String dir;
        private Integer port;
        private String artifactId;
        private boolean registered; // Indicates if port comes from the central registry
        private boolean javaRunnable;
    }

    public List<ModuleInfo> scan() {
        Map<String, Integer> registry = loadPortRegistry();
        Map<String, ModuleInfo> modules = new LinkedHashMap<>();
        List<String> moduleIds = new ArrayList<>();
        moduleIds.addAll(registry.keySet());
        for (String fromMapping : loadMappingModuleIds()) {
            if (!moduleIds.contains(fromMapping)) {
                moduleIds.add(fromMapping);
            }
        }
        for (String fromDir : discoverModuleIdsFromDirectory()) {
            if (!moduleIds.contains(fromDir)) {
                moduleIds.add(fromDir);
            }
        }

        for (String id : moduleIds) {
            Integer port = registry.get(id);

            File moduleDir = new File(MODULE_ROOT, id);
            File rootDir = new File(ROOT_PATH);
            File rootChildDir = new File(ROOT_PATH, id);
            boolean rootAsModule = shouldUseRootAsModuleDir(id);
            String dirPath = moduleDir.exists()
                    ? moduleDir.getAbsolutePath()
                    : (rootChildDir.exists()
                            ? rootChildDir.getAbsolutePath()
                            : (rootAsModule ? rootDir.getAbsolutePath() : rootChildDir.getAbsolutePath()));
            File resolvedDir = new File(dirPath);
            boolean hasJarInModule = new File(moduleDir, "target/" + id + ".jar").exists()
                    || new File(resolvedDir, "target/" + id + ".jar").exists();
            boolean hasJarInApp = new File(ROOT_PATH, id + ".jar").exists()
                    || new File(ROOT_PATH, id + "/target/" + id + ".jar").exists();
            boolean hasPom = new File(moduleDir, "pom.xml").exists()
                    || new File(resolvedDir, "pom.xml").exists();
            // In local mvn mode, module can be runnable even when target jar has not been built yet.
            boolean javaRunnable = hasJarInModule || hasJarInApp || hasPom;

            modules.put(id, ModuleInfo.builder()
                    .id(id)
                    .name(id)
                    .dir(dirPath)
                    .port(port)
                    .artifactId(id)
                    .registered(port != null)
                    .javaRunnable(javaRunnable)
                    .build());
        }

        return new ArrayList<>(modules.values());
    }

    private Map<String, Integer> loadPortRegistry() {
        Map<String, Integer> ports = new HashMap<>();
        try {
            File file = resolveFirstExisting(PORT_REGISTRY_CANDIDATES);
            if (file.exists()) {
                Yaml yaml = new Yaml();
                Map<String, Object> obj = yaml.load(new FileInputStream(file));
                if (obj.get("ports") instanceof Map) {
                    Map<String, Object> pMap = (Map<String, Object>) obj.get("ports");
                    for (Map.Entry<String, Object> entry : pMap.entrySet()) {
                        ports.put(entry.getKey(), Integer.parseInt(entry.getValue().toString()));
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Failed to load port registry: " + e.getMessage());
        }
        return ports;
    }

    private List<String> loadMappingModuleIds() {
        List<String> ids = new ArrayList<>();
        try {
            File file = resolveFirstExisting(MAPPING_FILE_CANDIDATES);
            if (!file.exists()) {
                return ids;
            }
            Yaml yaml = new Yaml();
            Map<String, Object> obj = yaml.load(new FileInputStream(file));
            if (!(obj.get("mappings") instanceof List)) {
                return ids;
            }
            List<Map<String, Object>> mappings = (List<Map<String, Object>>) obj.get("mappings");
            for (Map<String, Object> mapping : mappings) {
                Object mod = mapping.get("module");
                if (mod == null) {
                    continue;
                }
                String id = mod.toString().trim();
                if (!id.isEmpty() && !ids.contains(id)) {
                    ids.add(id);
                }
            }
        } catch (Exception e) {
            System.err.println("Failed to load mapping modules: " + e.getMessage());
        }
        return ids;
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

    private List<String> discoverModuleIdsFromDirectory() {
        List<String> ids = new ArrayList<>();
        File moduleRoot = new File(MODULE_ROOT);
        File[] children = moduleRoot.listFiles(File::isDirectory);
        if (children != null) {
            for (File dir : children) {
                if (dir == null) {
                    continue;
                }
                String name = dir.getName();
                if (name == null || name.trim().isEmpty()) {
                    continue;
                }
                if (name.startsWith(".")) {
                    continue;
                }
                ids.add(name.trim());
            }
        }
        if (ids.isEmpty()) {
            String rootModuleId = detectRootModuleId();
            if (!rootModuleId.isEmpty()) {
                ids.add(rootModuleId);
            }
        }
        return ids;
    }

    private boolean shouldUseRootAsModuleDir(String moduleId) {
        String id = moduleId == null ? "" : moduleId.trim();
        if (id.isEmpty()) {
            return false;
        }
        File moduleDir = new File(MODULE_ROOT, id);
        if (moduleDir.isDirectory()) {
            return false;
        }
        String rootModuleId = detectRootModuleId();
        return id.equals(rootModuleId);
    }

    private String detectRootModuleId() {
        try {
            Path root = Path.of(ROOT_PATH);
            Path pom = root.resolve("pom.xml");
            if (!Files.exists(pom) || !Files.isDirectory(root.resolve("src"))) {
                return "";
            }
            String xml = Files.readString(pom, StandardCharsets.UTF_8);
            Matcher m = ARTIFACT_ID_PATTERN.matcher(xml);
            while (m.find()) {
                String artifact = m.group(1) == null ? "" : m.group(1).trim();
                if (!artifact.isEmpty() && !"parent".equalsIgnoreCase(artifact)) {
                    return artifact;
                }
            }
            Path fileName = root.getFileName();
            return fileName == null ? "" : fileName.toString();
        } catch (Exception ignored) {
            return "";
        }
    }

}
