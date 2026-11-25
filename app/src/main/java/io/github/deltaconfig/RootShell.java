package io.github.deltaconfig;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/** A bounded, binary-safe su transport. Commands and input bytes are never included in diagnostics. */
public final class RootShell {
    private RootShell() { }

    /** An immutable route pinned before any game read, backup or write is performed. */
    public static final class Access {
        private final Route route;
        private final String namespace, initNamespace;
        private Access(Route route, Probe probe) {
            this.route = route; namespace = probe.namespace; initNamespace = probe.initNamespace;
        }
        public String description() { return route.name() + "; self=" + namespace + "; init=" + initNamespace; }
        public Result run(String command, byte[] input, int maxOutput, long timeoutMs)
                throws IOException, InterruptedException {
            // This preamble never consumes stdin or writes to stdout, keeping config bytes binary-safe.
            // Fail closed if a root manager later gives this process another mount context.
            return execute(route.arguments(guard(namespace) + command), input, maxOutput, timeoutMs);
        }
    }

    /** Probe output includes identities and paths, never configuration contents or shell command text. */
    public static final class SelectionFailure extends IOException {
        public final String diagnostic;
        public final Integer exitCode;
        private SelectionFailure(String diagnostic, Integer exitCode, Throwable cause) {
            super("所有 root 访问路径均未能读取目标普通文件；" + diagnostic, cause);
            this.diagnostic = diagnostic; this.exitCode = exitCode;
        }
        public String getDiagnostic() { return diagnostic; }
        public Integer getExitCode() { return exitCode; }
    }

    /** Select only for the installed application's exact current-user Engine path. No files are changed. */
    public static Access selectForFile(String path, long timeoutMs) throws IOException, InterruptedException {
        if (path == null || !path.startsWith("/") || path.indexOf('\0') >= 0)
            throw new IllegalArgumentException("Invalid root probe path");
        List<String> diagnostics = new ArrayList<>();
        List<Route> sources = new ArrayList<>();
        Route ordinary = new Route(null, null);
        sources.add(ordinary);
        Access access = probe(ordinary, path, timeoutMs, diagnostics);
        if (access != null) return access;

        try {
            Result help = execute(new String[]{"su", "--help"}, null, 65536, Math.min(timeoutMs, 15000));
            String option = advertisedMountOption(help.text() + "\n" + help.stderr);
            if (option != null) {
                Route master = new Route(option, null);
                sources.add(master);
                access = probe(master, path, timeoutMs, diagnostics);
                if (access != null) return access;
            } else diagnostics.add("su-help: 未声明 --mount-master/-M，未盲目传入全局挂载参数");
        } catch (IOException failed) { diagnostics.add("su-help: " + concise(failed)); }

        // Some root managers can enter PID 1 only from the ordinary route, some only from master.
        for (Route source : sources) {
            Result tools;
            try {
                tools = execute(source.arguments("if command -v nsenter >/dev/null 2>&1 && nsenter --help >/dev/null 2>&1; then printf 'NSENTER\\n'; fi; "
                        + "if [ -x /system/bin/toybox ] && /system/bin/toybox nsenter --help >/dev/null 2>&1; then printf 'TOYBOX\\n'; fi"),
                        null, 4096, timeoutMs);
            } catch (IOException failed) {
                diagnostics.add(source.name() + " nsenter 探测: " + concise(failed)); continue;
            }
            if (tools.exitCode != 0) {
                diagnostics.add(source.name() + " nsenter 探测 exit=" + tools.exitCode + ": " + safe(tools.stderr)); continue;
            }
            boolean available = false;
            for (String tool : tools.text().trim().split("\\r?\\n")) {
                String executable;
                if ("NSENTER".equals(tool)) executable = "nsenter";
                else if ("TOYBOX".equals(tool)) executable = "/system/bin/toybox nsenter";
                else continue;
                available = true;
                access = probe(new Route(source.mountOption, executable), path, timeoutMs, diagnostics);
                if (access != null) return access;
            }
            if (!available) diagnostics.add(source.name() + ": 系统未提供可用 nsenter");
        }
        String detail = String.join("\n", diagnostics);
        throw new SelectionFailure("目标=" + path + "\n" + detail, 51, null);
    }

    private static Access probe(Route route, String path, long timeoutMs, List<String> diagnostics)
            throws InterruptedException {
        try {
            Result result = execute(route.arguments(probeCommand(path)), null, 8192, timeoutMs);
            Probe probe;
            try { probe = parseProbe(result.text(), route.namespaceTool != null); }
            catch (IOException invalid) {
                diagnostics.add(route.name() + "; path=" + path + "; exit=" + result.exitCode
                        + "; probe=" + safe(result.text()) + "; " + concise(invalid) + "; " + safe(result.stderr)); return null;
            }
            String detail = route.name() + "; self=" + probe.namespace + "; init=" + probe.initNamespace
                    + "; path=" + path + "; exit=" + result.exitCode + "; file=" + probe.fileState;
            if (result.exitCode != 0 || !"OK".equals(probe.fileState)) {
                diagnostics.add(detail + "; " + safe(result.stderr)); return null;
            }
            Access selected = new Access(route, probe);
            // Verify that this route can be repeated in the same namespace before choosing it.
            Result stable = selected.run("true", null, 1024, timeoutMs);
            if (stable.exitCode != 0) {
                diagnostics.add(detail + "; 重复验证失败 exit=" + stable.exitCode + "; " + safe(stable.stderr)); return null;
            }
            return selected;
        } catch (IOException failure) {
            diagnostics.add(route.name() + "; path=" + path + "; " + concise(failure)); return null;
        }
    }

    private static String advertisedMountOption(String help) {
        // Capability must be advertised by this installed su, not inferred from a vendor name.
        if (help.matches("(?s).*(?<![A-Za-z0-9_-])--mount-master(?![A-Za-z0-9_-]).*")) return "--mount-master";
        return help.matches("(?s).*(?<![A-Za-z0-9_-])-M(?=[\\s,]|$).*") ? "-M" : null;
    }

    private static String probeCommand(String path) {
        String quoted = quote(path);
        return "id -u; readlink /proc/$$/ns/mnt; readlink /proc/1/ns/mnt || printf 'unavailable\\n'; "
                + "if [ -L " + quoted + " ]; then printf 'SYMLINK\\n'; exit 47; "
                + "elif [ ! -e " + quoted + " ]; then printf 'MISSING\\n'; exit 44; "
                + "elif [ ! -f " + quoted + " ]; then printf 'NOT_REGULAR\\n'; exit 45; "
                + "elif [ ! -r " + quoted + " ]; then printf 'UNREADABLE\\n'; exit 46; "
                + "elif ! ( : < " + quoted + " ) 2>/dev/null; then printf 'UNREADABLE\\n'; exit 46; "
                + "else printf 'OK\\n'; fi";
    }

    private static Probe parseProbe(String output, boolean requireInit) throws IOException {
        String[] lines = output.replace("\r\n", "\n").trim().split("\n", -1);
        if (lines.length != 4 || !"0".equals(lines[0]) || !lines[1].matches("mnt:\\[[0-9]+\\]")
                || !(lines[2].matches("mnt:\\[[0-9]+\\]") || "unavailable".equals(lines[2]))
                || !lines[3].matches("OK|MISSING|NOT_REGULAR|UNREADABLE|SYMLINK"))
            throw new IOException("root UID/命名空间/文件状态探测格式无效（须 UID 0）");
        if (requireInit && !lines[1].equals(lines[2]))
            throw new IOException("nsenter 未进入 PID 1 挂载命名空间；self=" + lines[1] + "; init=" + lines[2]);
        return new Probe(lines[1], lines[2], lines[3]);
    }

    private static String guard(String namespace) {
        return "[ \"$(id -u)\" = 0 ] || { echo 'root UID 已变化，需要 UID 0' >&2; exit 49; }; "
                + "[ \"$(readlink /proc/$$/ns/mnt)\" = " + quote(namespace)
                + " ] || { echo 'root 挂载命名空间已变化，已停止当前操作；请重新读取配置' >&2; exit 50; }; ";
    }

    private static final class Probe {
        final String namespace, initNamespace, fileState;
        Probe(String namespace, String initNamespace, String fileState) {
            this.namespace = namespace; this.initNamespace = initNamespace; this.fileState = fileState;
        }
    }

    private static final class Route {
        final String mountOption, namespaceTool;
        Route(String mountOption, String namespaceTool) { this.mountOption = mountOption; this.namespaceTool = namespaceTool; }
        String name() { return (mountOption == null ? "su-default" : "su " + mountOption)
                + (namespaceTool == null ? "" : " + " + namespaceTool + " PID1-mount"); }
        String[] arguments(String command) {
            List<String> args = new ArrayList<>(); args.add("su");
            if (mountOption != null) args.add(mountOption);
            args.add("-c");
            args.add(namespaceTool == null ? command : namespaceTool + " --mount=/proc/1/ns/mnt -- /system/bin/sh -c " + quote(command));
            return args.toArray(new String[0]);
        }
    }

    private static String concise(IOException failed) {
        return safe(failed.getClass().getSimpleName() + ": " + failed.getMessage());
    }

    private static String safe(String text) {
        if (text == null) return "";
        String clean = text.replaceAll("[\\p{Cntrl}]", " ").trim();
        clean = clean.replaceAll("(?i)\\b(token|hash|password|passwd|secret|key)\\b(?:\\s*[:=]|\\s+).*", "$1=[REDACTED]")
                .replaceAll("[A-Za-z0-9+/=_-]{64,}", "[REDACTED]");
        return clean.length() > 500 ? clean.substring(0, 500) : clean;
    }

    public static final class Result {
        public final int exitCode;
        public final byte[] stdout;
        public final String stderr;
        private Result(int code, byte[] out, byte[] err) {
            exitCode = code; stdout = out;
            stderr = new String(err, StandardCharsets.UTF_8);
        }
        public String text() { return new String(stdout, StandardCharsets.UTF_8); }
    }

    /** The caller adds the operation and file path; this exception describes only the failed channel. */
    public static final class TransportFailure extends IOException {
        public final String stage, stderr;
        public final Integer exitCode;
        private TransportFailure(String stage, String reason, Integer exitCode, String stderr, Throwable cause) {
            super(reason, cause); this.stage = stage; this.exitCode = exitCode;
            this.stderr = stderr == null ? "" : stderr;
        }
        public Integer getExitCode() { return exitCode; }
        public String getDiagnostic() { return stderr; }
    }

    public static String quote(String value) {
        if (value == null || value.indexOf('\0') >= 0) throw new IllegalArgumentException("Invalid shell argument");
        return "'" + value.replace("'", "'\\''") + "'";
    }

    public static Result run(String command, byte[] input, int maxOutput, long timeoutMs)
            throws IOException, InterruptedException {
        return execute(new String[]{"su", "-c", command}, input, maxOutput, timeoutMs);
    }

    private static Result execute(String[] arguments, byte[] input, int maxOutput, long timeoutMs)
            throws IOException, InterruptedException {
        if (maxOutput < 0 || maxOutput > 64 * 1024 * 1024 || timeoutMs <= 0)
            throw new IllegalArgumentException("Invalid process limits");
        final Process process;
        try { process = new ProcessBuilder(arguments).start(); }
        catch (IOException failure) {
            throw new TransportFailure("启动 su 进程", "无法启动 su；请确认手机已 root，且 root 管理器提供 su", null, "", failure);
        }
        Capture out = new Capture(process.getInputStream(), maxOutput);
        Capture err = new Capture(process.getErrorStream(), 32768);
        Thread outputThread = daemon("root-stdout", out);
        Thread errorThread = daemon("root-stderr", err);
        final IOException[] writeError = new IOException[1];
        Thread inputThread = daemon("root-stdin", () -> {
            try (OutputStream stream = process.getOutputStream()) {
                if (input != null) stream.write(input);
                stream.flush();
            } catch (IOException e) { writeError[0] = e; }
        });
        try {
            if (!process.waitFor(timeoutMs, TimeUnit.MILLISECONDS)) {
                process.destroy();
                if (!process.waitFor(500, TimeUnit.MILLISECONDS)) process.destroyForcibly();
                errorThread.join(500);
                TransportFailure failure = transport("等待 su 命令结束", "root 命令超过 " + timeoutMs
                        + " 毫秒仍未结束；请检查 root 授权窗口和存储状态", process, err, null);
                addFailures(failure, out, err, writeError[0]);
                throw failure;
            }
            outputThread.join(2000); errorThread.join(2000); inputThread.join(2000);
            if (outputThread.isAlive() || errorThread.isAlive() || inputThread.isAlive()) {
                String channel = (inputThread.isAlive() ? "stdin " : "")
                        + (outputThread.isAlive() ? "stdout " : "") + (errorThread.isAlive() ? "stderr" : "");
                TransportFailure failure = transport("关闭 root 通道", "su 已退出，但通道未正常结束：" + channel.trim(), process, err, null);
                addFailures(failure, out, err, writeError[0]); throw failure;
            }
            if (out.tooLarge || err.tooLarge) {
                String channel = (out.tooLarge ? "stdout 超过 " + maxOutput + " 字节" : "")
                        + (out.tooLarge && err.tooLarge ? "；" : "") + (err.tooLarge ? "stderr 超过 32768 字节" : "");
                TransportFailure failure = transport("读取 root 输出", "root 输出超过安全限制：" + channel, process, err, null);
                addFailures(failure, out, err, writeError[0]);
                throw failure;
            }
            if (out.failure != null) {
                TransportFailure failure = transport("读取 root stdout", "读取 root 标准输出通道失败", process, err, out.failure);
                addFailures(failure, out, err, writeError[0]); throw failure;
            }
            if (err.failure != null) {
                TransportFailure failure = transport("读取 root stderr", "读取 root 错误输出通道失败", process, err, err.failure);
                addFailures(failure, out, err, writeError[0]); throw failure;
            }
            if (writeError[0] != null) {
                TransportFailure failure = transport("写入 root stdin", "向 root 标准输入通道写入或关闭失败，输入可能未完整传输", process, err, writeError[0]);
                addFailures(failure, out, err, writeError[0]); throw failure;
            }
            return new Result(process.exitValue(), out.bytes.toByteArray(), err.bytes.toByteArray());
        } finally {
            process.destroy();
            try { process.getOutputStream().close(); } catch (IOException ignored) { }
            try { process.getInputStream().close(); } catch (IOException ignored) { }
            try { process.getErrorStream().close(); } catch (IOException ignored) { }
        }
    }

    private static TransportFailure transport(String stage, String reason, Process process, Capture err, Throwable cause) {
        Integer code = null;
        try { code = process.exitValue(); } catch (IllegalThreadStateException ignored) { }
        return new TransportFailure(stage, reason, code,
                new String(err.bytes.toByteArray(), StandardCharsets.UTF_8), cause);
    }

    private static void addFailures(Throwable target, Capture out, Capture err, IOException write) {
        if (out.failure != null) target.addSuppressed(out.failure);
        if (err.failure != null) target.addSuppressed(err.failure);
        if (write != null) target.addSuppressed(write);
    }

    private static Thread daemon(String name, Runnable work) {
        Thread thread = new Thread(work, name); thread.setDaemon(true); thread.start(); return thread;
    }

    private static final class Capture implements Runnable {
        private final InputStream stream;
        private final int limit;
        final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        volatile boolean tooLarge;
        volatile IOException failure;
        Capture(InputStream input, int maximum) { stream = input; limit = maximum; }
        @Override public void run() {
            byte[] buffer = new byte[16384];
            try {
                int length;
                while ((length = stream.read(buffer)) != -1) {
                    int remaining = limit - bytes.size();
                    if (length > remaining) tooLarge = true;
                    if (remaining > 0) bytes.write(buffer, 0, Math.min(length, remaining));
                    // Continue draining so excessive output cannot deadlock the child.
                }
            } catch (IOException e) { failure = e; }
        }
    }
}
