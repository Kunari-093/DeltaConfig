package io.github.deltaconfig.core;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Structured, copyable failure report. Never includes commands or configuration secrets. */
public final class OperationFailure extends IOException {
    public final String operation, stage, path, reason;
    private String writeStatus, rollbackStatus, backupPath, suggestion;
    private Integer processExitCode;
    private final List<String[]> contexts = new ArrayList<String[]>();
    private static final int MAX_REPORT = 12000;
    private static final Pattern ASSIGNMENT = Pattern.compile(
            "(?i)((?:token|hash|aes[_ -]?key|key|fixed[_ -]?mask|mask|device[_ -]?id|android[_ -]?id|serial(?:no|number)?|uin|account|phone|mobile|oaid|imei|imsi|meid|password|passwd|pwd|passphrase|手机号|电话号码|账号|密码|密钥|固定掩码|设备\\s*(?:ID|标识|序列号)|认证摘要)[\"']?\\s*[:=：]\\s*)[^\\r\\n]*");
    private static final Pattern PATH = Pattern.compile("(?<![A-Za-z0-9+])(?:[A-Za-z]:[\\\\/]|/(?:data|storage|sdcard|mnt|system|vendor|apex|proc|dev|cache|product|odm|metadata|tmp|apps)/)[^\\s\\\"'<>|,;]*");
    private static final Pattern COMMAND_TEXT = Pattern.compile("(?im)(?:^[ \\t]*(?:shell[ \\t]+command|command|cmd|完整命令|执行命令)[ \\t]*[:=][^\\r\\n]*|\\b(?:su|sh|bash)[ \\t]+-c[ \\t]+[^\\r\\n]*)");
    private static final Pattern KNOWN_DIAGNOSTIC = Pattern.compile("(?i)Permission denied|No such file or directory|Read-only file system|No space left on device|Operation not permitted|SELinux|avc:[ \\t]*denied|root[ \\t]*授权被拒绝");
    private static final Pattern LONG_VALUE = Pattern.compile("(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])");

    public OperationFailure(String operation, String stage, String path, String reason, Throwable cause) {
        super(sanitize(reason == null || reason.trim().isEmpty() ? "未提供详细原因" : reason), cause);
        this.operation = safe(operation, "未标明操作");
        this.stage = safe(stage, "未标明阶段");
        this.path = safe(path, "未定位到具体文件");
        this.reason = getMessage();
    }

    /** Retain an already precise failure, appending outer context without replacing transaction state. */
    public static OperationFailure wrap(String operation, String stage, String path, Throwable cause) {
        if (cause instanceof OperationFailure) {
            OperationFailure failure = (OperationFailure) cause;
            failure.contexts.add(new String[]{safe(operation, "未标明操作"), safe(stage, "未标明阶段"), safe(path, "未定位到具体文件")});
            return failure;
        }
        return new OperationFailure(operation, stage, path, message(cause), cause);
    }

    public OperationFailure state(String writeStatus, String rollbackStatus, String backupPath) {
        if (writeStatus != null && !writeStatus.trim().isEmpty()) this.writeStatus = sanitize(writeStatus);
        if (rollbackStatus != null && !rollbackStatus.trim().isEmpty()) this.rollbackStatus = sanitize(rollbackStatus);
        if (backupPath != null && !backupPath.trim().isEmpty()) this.backupPath = sanitize(backupPath);
        return this;
    }
    public OperationFailure exitCode(int value) { processExitCode = value; return this; }
    public OperationFailure hint(String value) { suggestion = sanitize(value); return this; }
    public String getOperation() { return operation; }
    public String getStage() { return stage; }
    public String getPath() { return path; }

    /** Redact assignments and bare secrets; preserve diagnostic words and ordinary absolute paths. */
    public static String sanitize(String value) {
        if (value == null) return "";
        String result = value.replace('\u0000', ' ').replaceAll("[\\p{Cntrl}&&[^\\r\\n\\t]]", " ");
        Matcher commands = COMMAND_TEXT.matcher(result);
        StringBuffer withoutCommands = new StringBuffer();
        while (commands.find()) {
            StringBuilder replacement = new StringBuilder("[命令已省略]");
            Matcher diagnostic = KNOWN_DIAGNOSTIC.matcher(commands.group());
            while (diagnostic.find()) replacement.append("；").append(diagnostic.group());
            commands.appendReplacement(withoutCommands, Matcher.quoteReplacement(replacement.toString()));
        }
        commands.appendTail(withoutCommands);
        result = withoutCommands.toString();
        result = ASSIGNMENT.matcher(result).replaceAll("$1[已隐藏]");
        List<String> paths = new ArrayList<String>();
        Matcher matcher = PATH.matcher(result);
        StringBuffer protectedText = new StringBuffer();
        while (matcher.find()) {
            paths.add(matcher.group());
            matcher.appendReplacement(protectedText, Matcher.quoteReplacement("【路径" + (paths.size() - 1) + "】"));
        }
        matcher.appendTail(protectedText);
        result = LONG_VALUE.matcher(protectedText.toString()).replaceAll("[长认证值已隐藏]");
        result = result.replaceAll("(?<![0-9])1[3-9][0-9]{9}(?![0-9])", "[手机号已隐藏]");
        result = result.replaceAll("(?i)\\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\b", "[标识已隐藏]");
        for (int i = 0; i < paths.size(); i++) result = result.replace("【路径" + i + "】", paths.get(i));
        return result;
    }

    private static String safe(String text, String fallback) {
        String result = sanitize(text);
        return result.trim().isEmpty() ? fallback : result;
    }
    private static String message(Throwable error) {
        if (error == null) return "没有异常详情，无法确认失败原因";
        String text = error.getMessage();
        return text == null || text.trim().isEmpty() ? error.getClass().getSimpleName() : text;
    }
    private static final class Entry {
        final Throwable error;
        final String relation;
        Entry(Throwable error, String relation) { this.error = error; this.relation = relation; }
    }
    private static void collect(Throwable error, String relation, List<Entry> result, Set<Throwable> seen) {
        if (error == null || !seen.add(error) || seen.size() > 96) return;
        // Root causes are rendered before their enclosing descriptions so a long wrapper cannot hide them.
        collect(error.getCause(), "原因", result, seen);
        result.add(new Entry(error, relation));
        for (Throwable suppressed : error.getSuppressed()) collect(suppressed, "其他尝试或回滚错误", result, seen);
    }
    private static OperationFailure firstFailure(Throwable error) {
        Set<Throwable> seen = Collections.newSetFromMap(new IdentityHashMap<Throwable, Boolean>());
        while (error != null && seen.add(error)) {
            if (error instanceof OperationFailure) return (OperationFailure) error;
            error = error.getCause();
        }
        return null;
    }
    private static OperationFailure deepestFailure(Throwable error) {
        OperationFailure result = null;
        Set<Throwable> seen = Collections.newSetFromMap(new IdentityHashMap<Throwable, Boolean>());
        while (error != null && seen.add(error)) {
            if (error instanceof OperationFailure) result = (OperationFailure) error;
            error = error.getCause();
        }
        return result;
    }
    private static boolean absolute(String path) { return path.startsWith("/") || path.matches("^[A-Za-z]:[\\\\/].*"); }
    private static String bestPath(OperationFailure primary, List<Entry> entries) {
        if (primary == null) return "未定位到具体文件";
        if (absolute(primary.path)) return primary.path;
        String basename = primary.path;
        for (Entry entry : entries) if (entry.error instanceof OperationFailure) {
            OperationFailure failure = (OperationFailure) entry.error;
            if (absolute(failure.path) && failure.path.replace('\\', '/').endsWith("/" + basename)) return failure.path;
            for (String[] context : failure.contexts)
                if (absolute(context[2]) && context[2].replace('\\', '/').endsWith("/" + basename)) return context[2];
        }
        return primary.path;
    }
    private static String clip(String text, int maximum) {
        if (text.length() <= maximum) return text;
        if (maximum < 60) return text.substring(0, Math.max(0, maximum));
        int head = (maximum - 30) * 2 / 3, tail = maximum - 30 - head;
        return text.substring(0, head) + "\n[较长内容已缩略，保留首尾]\n" + text.substring(text.length() - tail);
    }
    private static String fieldState(Throwable error, int index) {
        Set<Throwable> seen = Collections.newSetFromMap(new IdentityHashMap<Throwable, Boolean>());
        while (error != null && seen.add(error)) {
            if (error instanceof OperationFailure) {
                OperationFailure failure = (OperationFailure) error;
                String value = index == 0 ? failure.writeStatus : index == 1 ? failure.rollbackStatus : failure.backupPath;
                if (value != null && !value.isEmpty()) return value;
            }
            error = error.getCause();
        }
        return index == 0 ? "未知；尚未确认是否写入" : index == 1 ? "未知；尚未确认是否执行或完成回滚" : "未记录";
    }
    private static Integer exitCode(Throwable error) {
        if (error instanceof OperationFailure && ((OperationFailure) error).processExitCode != null)
            return ((OperationFailure) error).processExitCode;
        try {
            Object result = error.getClass().getMethod("getExitCode").invoke(error);
            return result instanceof Number ? ((Number) result).intValue() : null;
        } catch (Exception ignored) { return null; }
    }
    private static String advice(Throwable error, List<Entry> entries) {
        OperationFailure first = firstFailure(error);
        if (first != null && first.suggestion != null && !first.suggestion.isEmpty()) return first.suggestion;
        StringBuilder all = new StringBuilder(), stages = new StringBuilder();
        for (Entry entry : entries) {
            all.append(entry.error.getClass().getSimpleName()).append(' ').append(message(entry.error)).append(' ');
            if (entry.error instanceof OperationFailure) stages.append(((OperationFailure) entry.error).stage).append(' ');
        }
        String lower = all.toString().toLowerCase(Locale.ROOT);
        String rootScope = lower + stages.toString().toLowerCase(Locale.ROOT);
        if (lower.contains("no space left") || lower.contains("enospc") || lower.contains("空间不足"))
            return "释放手机内部存储及备份目录空间后重试；先核对上方写入与回滚状态。";
        if (lower.contains("read-only file system") || lower.contains("erofs") || lower.contains("只读"))
            return "目标文件系统为只读；确认配置位于可写数据目录，不要强行改写系统分区。";
        if (lower.contains("selinux") || lower.contains("avc: denied"))
            return "检查对应文件的 SELinux 拒绝日志、权限和路径；不要通过关闭 SELinux 来掩盖问题。";
        boolean rootRequest = rootScope.contains("root 授权") || rootScope.contains("root permission") || rootScope.contains("superuser")
                || rootScope.contains("超级用户") || rootScope.contains("请求 root") || rootScope.contains("获取 root") || rootScope.contains("su: denied");
        if (rootRequest && (lower.contains("denied") || lower.contains("拒绝") || lower.contains("未授权") || lower.contains("未获得")))
            return "在 root 管理器中允许本应用获得超级用户权限，再重新读取；检查是否误选了拒绝。";
        if (lower.contains("permission denied") || lower.contains("权限"))
            return "检查本应用 root 授权、对应文件权限与访问路径；如有 SELinux 拒绝日志一并核对。";
        if (lower.contains("no such file") || lower.contains("enoent") || lower.contains("不存在") || lower.contains("缺少文件") || lower.contains("找不到文件") || lower.contains("filenotfound"))
            return "确认游戏已安装、至少启动一次并正常退出；核对当前 Android 用户及目标文件完整路径。";
        if (lower.contains("漂移") || lower.contains("发生变化") || lower.contains("已变化") || lower.contains("快照") || lower.contains("changed since"))
            return "游戏或其他程序已改变文件；关闭游戏，重新读取当前配置后再操作，不要覆盖旧快照。";
        if (lower.contains("兼容性") || lower.contains("未识别") || lower.contains("扫描上限") || lower.contains("扫描预算"))
            return "先在游戏中保存画质设置并正常退出，再重新检测；仍失败时，保留游戏版本和本机错误日志以适配当前格式。";
        if (lower.contains("hmac") || lower.contains("认证失败") || lower.contains("认证不匹配"))
            return "确认 Engine.ini、UserGameplay.ini 和游戏库来自本机同一安装版本；重新读取后重试，勿混用其他设备配置。";
        if (lower.contains("libue4") || lower.contains("库不匹配") || lower.contains("认证材料") || lower.contains("elf") || lower.contains("不支持的游戏版本"))
            return "确认安装的是 ARM64 游戏且配置与本机安装配套；库布局或认证规则未识别时，保留游戏版本和错误日志进行适配。";
        if (lower.contains("utf") || lower.contains("malformedinput") || lower.contains("unmappable") || lower.contains("格式") || lower.contains("不受支持") || lower.contains("base64") || lower.contains("密文块") || lower.contains("字段重复"))
            return "配置编码或格式与当前适配不一致；保留原文件及此报告，勿反复强制写入。";
        return "保留此报告；核对目标文件、root 授权及上方写入/回滚状态，再重新读取配置。";
    }

    /** Concise UI report. Full file context belongs only in the explicitly opened local log. */
    public static String userReport(Throwable error) {
        List<Entry> entries = new ArrayList<Entry>();
        collect(error, "失败上下文", entries, Collections.newSetFromMap(new IdentityHashMap<Throwable, Boolean>()));
        OperationFailure primary = deepestFailure(error);
        String rootReason = entries.isEmpty() ? message(error) : message(entries.get(0).error);
        StringBuilder out = new StringBuilder("配置操作失败\n");
        out.append("操作：").append(clip(uiText(primary == null ? "未标明操作" : primary.operation, entries), 180)).append('\n');
        out.append("阶段：").append(clip(uiText(primary == null ? "未标明阶段" : primary.stage, entries), 360)).append('\n');
        out.append("原因：").append(clip(uiText(rootReason, entries), 700)).append('\n');
        for (Entry entry : entries) {
            Integer code = exitCode(entry.error);
            if (code != null) { out.append("退出码：").append(code).append('\n'); break; }
        }
        out.append("写入状态：").append(clip(uiText(fieldState(error, 0), entries), 280)).append('\n');
        out.append("回滚状态：").append(clip(uiText(fieldState(error, 1), entries), 280)).append('\n');
        out.append("建议：").append(clip(uiText(advice(error, entries), entries), 400)).append('\n');
        out.append("详细诊断已保存至本机错误日志。");
        return clip(out.toString(), 2400);
    }

    private static String uiText(String text, List<Entry> entries) {
        String result = sanitize(text);
        for (Entry entry : entries) if (entry.error instanceof OperationFailure) {
            OperationFailure failure = (OperationFailure) entry.error;
            if (!failure.path.isEmpty() && !failure.path.equals("未定位到具体文件"))
                result = result.replace(failure.path, "相关配置");
            if (failure.backupPath != null && !failure.backupPath.isEmpty())
                result = result.replace(failure.backupPath, "本机备份");
            for (String[] context : failure.contexts)
                if (context[2] != null && !context[2].isEmpty() && !context[2].equals("未定位到具体文件"))
                    result = result.replace(context[2], "相关配置");
        }
        result = PATH.matcher(result).replaceAll("相关位置");
        result = result.replaceAll("(?i)(?<![A-Za-z0-9_])(?:[A-Za-z]:[\\\\/]|/)[^\\s\\\"'<>|,;，；]*", "相关位置");
        result = result.replaceAll("(?im)^.*(?:目标文件|备份位置)[：:][^\\r\\n]*(?:\\r?\\n|$)", "");
        result = result.replaceAll("(?i)UserGameplay\\.ini", "认证配置")
                .replaceAll("(?i)Engine\\.ini", "主配置")
                .replaceAll("(?i)Game\\.ini", "渲染配置")
                .replaceAll("(?i)libUE4\\.so", "游戏库");
        result = result.replaceAll("(?i)(?<![A-Za-z0-9_])[A-Za-z0-9_.-]+\\.(?:ini|so|apk|json)(?![A-Za-z0-9_])", "相关配置");
        return result.trim();
    }

    public static String format(Throwable error) {
        List<Entry> entries = new ArrayList<Entry>();
        collect(error, "失败上下文", entries, Collections.newSetFromMap(new IdentityHashMap<Throwable, Boolean>()));
        OperationFailure primary = deepestFailure(error);
        StringBuilder out = new StringBuilder("配置操作失败报告\n");
        out.append("操作：").append(primary == null ? "未标明操作" : primary.operation).append('\n');
        out.append("阶段：").append(primary == null ? "未标明阶段" : primary.stage).append('\n');
        out.append("目标文件：").append(clip(bestPath(primary, entries), 1800)).append('\n');
        String rootReason = entries.isEmpty() ? message(error) : message(entries.get(0).error);
        out.append("原因：").append(clip(sanitize(rootReason), 2500)).append('\n');
        Integer code = null;
        for (Entry entry : entries) { code = exitCode(entry.error); if (code != null) break; }
        if (code != null) out.append("退出码：").append(code).append('\n');
        out.append("写入状态：").append(clip(fieldState(error, 0), 600)).append('\n');
        out.append("回滚状态：").append(clip(fieldState(error, 1), 600)).append('\n');
        out.append("备份位置：").append(clip(fieldState(error, 2), 1000)).append('\n');
        out.append("建议：").append(clip(advice(error, entries), 800)).append('\n');
        out.append("\n详细原因链（含其他尝试或回滚错误）：\n");
        int budget = Math.max(0, MAX_REPORT - out.length() - 100);
        int each = Math.max(120, Math.min(8000, budget / Math.max(1, entries.size())));
        int shown = 0;
        for (Entry entry : entries) {
            StringBuilder detail = new StringBuilder();
            detail.append('[').append(++shown).append("] ").append(entry.relation).append(" · ").append(entry.error.getClass().getSimpleName()).append('\n');
            if (entry.error instanceof OperationFailure) {
                OperationFailure failure = (OperationFailure) entry.error;
                detail.append("操作：").append(failure.operation).append("；阶段：").append(failure.stage).append("\n目标文件：").append(failure.path).append('\n');
                for (String[] context : failure.contexts) detail.append("外层上下文：").append(context[0]).append(" / ").append(context[1]).append("\n目标文件：").append(context[2]).append('\n');
                if (failure.writeStatus != null || failure.rollbackStatus != null)
                    detail.append("该失败状态：写入=").append(failure.writeStatus == null ? "未知" : failure.writeStatus).append("；回滚=").append(failure.rollbackStatus == null ? "未知" : failure.rollbackStatus).append('\n');
            }
            Integer entryCode = exitCode(entry.error);
            if (entryCode != null) detail.append("退出码：").append(entryCode).append('\n');
            detail.append("原因：").append(sanitize(message(entry.error))).append('\n');
            String item = clip(detail.toString(), Math.min(each, Math.max(0, MAX_REPORT - out.length() - 60)));
            out.append(item).append('\n');
            if (MAX_REPORT - out.length() < 120) break;
        }
        if (shown < entries.size()) out.append("[报告过长，其余 ").append(entries.size() - shown).append(" 项已省略]\n");
        else if (entries.size() >= 96) out.append("[异常层级过多，部分深层内容已省略]\n");
        return clip(sanitize(out.toString()), MAX_REPORT);
    }
}
