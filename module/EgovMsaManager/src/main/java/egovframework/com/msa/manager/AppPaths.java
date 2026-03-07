package egovframework.com.msa.manager;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

final class AppPaths {
    private static final String DEFAULT_ROOT = "/opt/carbosys";
    private static final Path ROOT = resolveRoot();

    private AppPaths() {
    }

    static String root() {
        return ROOT.toString();
    }

    static Path rootPath() {
        return ROOT;
    }

    static String moduleRoot() {
        return ROOT.resolve("module").toString();
    }

    static Path logsDir() {
        return ROOT.resolve("logs");
    }

    static Path resolvePath(String... segments) {
        Path p = ROOT;
        if (segments != null) {
            for (String seg : segments) {
                if (seg != null && !seg.isEmpty()) {
                    p = p.resolve(seg);
                }
            }
        }
        return p;
    }

    private static Path resolveRoot() {
        String byProp = safeTrim(System.getProperty("carbosys.root"));
        if (!byProp.isEmpty()) {
            return Paths.get(byProp).toAbsolutePath().normalize();
        }
        String byEnv = safeTrim(System.getenv("CARBOSYS_ROOT"));
        if (!byEnv.isEmpty()) {
            return Paths.get(byEnv).toAbsolutePath().normalize();
        }
        Path found = findWorkspaceRoot(Paths.get("").toAbsolutePath().normalize());
        if (found != null) {
            return found;
        }
        return Paths.get(DEFAULT_ROOT);
    }

    private static Path findWorkspaceRoot(Path from) {
        Path cur = from;
        for (int i = 0; i < 8 && cur != null; i++) {
            if (Files.exists(cur.resolve("msa-ports.yml")) || Files.exists(cur.resolve("msa-mappings.yml"))) {
                return cur;
            }
            if (Files.isDirectory(cur.resolve("module")) && Files.isDirectory(cur.resolve("scripts"))) {
                return cur;
            }
            cur = cur.getParent();
        }
        return null;
    }

    private static String safeTrim(String v) {
        return v == null ? "" : v.trim();
    }
}
