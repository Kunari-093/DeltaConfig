package io.github.deltaconfig.core;

import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Checks the configuration structures understood by the patcher after cryptographic authentication.
 * A matching structure does not establish the meaning of a future game's internal enum values.
 */
public final class ConfigCompatibility {
    private static final String GEAR = "dfmperfgearconfig";
    private static final String FPS = "qualityfpssetting";
    private static final String SYSTEM = "systemsettings";
    private static final String PAD = "/script/perfgear.perfgearandroidpadsizeconfig";
    private static final String QUALITY = "dfmqualitylevel";
    private static final String FRAME = "dfmfpslevel";
    private static final String[] ENGINE_SECTIONS = {GEAR, FPS, SYSTEM};
    private static final Set<String> GEAR_KEYS = names(QUALITY, FRAME);
    private static final Set<String> SYSTEM_KEYS = names("perfgear.smallpadsize",
            "dfmdeviceframe.white90fps", "dfmdeviceframe.white120fps", "dfmdeviceframe.white144fps",
            "dfmdeviceframe.white165fps", "dfmdeviceframe.white185fps");
    private static final Set<String> PAD_KEYS = names("smallpadconfig", "midpadconfig", "bigpadconfig");
    private static final Set<String> RESOLUTION_KEYS = names("backbuffer", "ultralowresolution",
            "lowresolution", "midresolution", "highresolution", "ultrahighresolution", "superresolution");
    private static final Pattern HEADER = Pattern.compile("^\\[([^\\]\\r\\n]+)\\][ \\t]*(?:[;#].*)?$");
    private static final Pattern INTEGER = Pattern.compile("[+-]?[0-9]{1,10}");
    private static final int MAX_LINES = 100000;
    private static final int MAX_LINE = 65536;

    private ConfigCompatibility() { }

    public static void validate(String enginePlain, byte[] gameIni) throws Exception {
        Ini engine = parse(enginePlain, "主配置", true);
        Map<String, String> gear = engine.values.get(GEAR);
        if (gear == null || (!gear.containsKey(QUALITY) && !gear.containsKey(FRAME)))
            throw incompatible("主配置尚无画质与帧率字段；请先启动游戏保存画质后再读取");
        if (!gear.containsKey(QUALITY) || !gear.containsKey(FRAME))
            throw incompatible("主配置的画质或帧率字段缺失；请先启动游戏保存画质后再读取");
        int quality = integer(gear.get(QUALITY), "画质档位");
        if (quality < 0 || quality > 5) throw incompatible("当前画质枚举超出已识别范围");
        int frame = integer(gear.get(FRAME), "帧率档位");
        if (ConfigPatcher.fpsForInternal(frame) < 0)
            throw incompatible("当前帧率枚举未识别；请先在游戏中保存已支持的帧率档位后再读取");

        Map<String, String> fps = engine.values.get(FPS);
        if (fps != null && fps.containsKey("unlimit")) bool(fps.get("unlimit"), "帧率覆盖开关");
        Map<String, String> system = engine.values.get(SYSTEM);
        if (system != null) for (Map.Entry<String, String> entry : system.entrySet()) {
            if (entry.getKey().equals("perfgear.smallpadsize")) {
                String value = entry.getValue();
                if (!value.matches("[+]?(?:[0-9]{1,3})(?:\\.[0-9]{1,6})?"))
                    throw incompatible("设备尺寸覆盖字段格式已变化");
                double size = Double.parseDouble(value);
                if (size > 100) throw incompatible("设备尺寸覆盖字段超出已识别范围");
            } else bool(entry.getValue(), "设备帧率开关");
        }

        if (gameIni == null || gameIni.length == 0 || gameIni.length > ConfigCrypto.MAX_INI_BYTES)
            throw incompatible("渲染配置为空或超过大小上限");
        String gameText = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(gameIni)).toString();
        Ini game = parse(gameText, "渲染配置", false);
        Map<String, String> pad = game.values.get(PAD);
        if (pad != null) for (String value : pad.values()) new PadReader(value).validate();
    }

    private static Set<String> names(String... values) {
        return new HashSet<String>(Arrays.asList(values));
    }

    private static GeneralSecurityException incompatible(String reason) {
        return new GeneralSecurityException("配置结构兼容性检查未通过：" + reason);
    }

    private static int integer(String value, String label) throws GeneralSecurityException {
        if (!INTEGER.matcher(value).matches()) throw incompatible(label + "不是已识别的整数格式");
        try { return Integer.parseInt(value); }
        catch (NumberFormatException failure) { throw incompatible(label + "超出整数范围"); }
    }

    private static void bool(String value, String label) throws GeneralSecurityException {
        if (!value.equals("0") && !value.equals("1") && !value.equalsIgnoreCase("true")
                && !value.equalsIgnoreCase("false")) throw incompatible(label + "格式已变化");
    }

    private static final class Ini {
        final Map<String, Map<String, String>> values = new HashMap<String, Map<String, String>>();
    }

    private static Ini parse(String text, String label, boolean engine) throws GeneralSecurityException {
        if (text == null || text.length() == 0 || text.length() > ConfigCrypto.MAX_INI_BYTES)
            throw incompatible(label + "为空或超过大小上限");
        if (text.charAt(0) == '\ufeff') text = text.substring(1);
        Ini result = new Ini();
        Set<String> protectedSections = engine ? names(ENGINE_SECTIONS) : names(PAD);
        Set<String> seen = new HashSet<String>();
        boolean headerSeen = false;
        String section = "";
        int lineCount = 0;
        for (int start = 0; start < text.length();) {
            int end = start;
            while (end < text.length() && text.charAt(end) != '\r' && text.charAt(end) != '\n') {
                char c = text.charAt(end);
                if (c == 0 || (c < 32 && c != '\t')) throw incompatible(label + "含控制字符");
                end++;
                if (end - start > MAX_LINE) throw incompatible(label + "单行过长");
            }
            if (++lineCount > MAX_LINES) throw incompatible(label + "行数超过上限");
            String line = text.substring(start, end).trim();
            start = end;
            if (start < text.length() && text.charAt(start) == '\r') start++;
            if (start < text.length() && text.charAt(start) == '\n') start++;
            if (line.isEmpty() || line.startsWith(";") || line.startsWith("#")) continue;
            if (line.startsWith("[")) {
                Matcher header = HEADER.matcher(line);
                if (!header.matches() || header.group(1).trim().isEmpty())
                    throw incompatible(label + "节标题格式已变化");
                section = header.group(1).trim().toLowerCase(Locale.ROOT);
                headerSeen = true;
                if (protectedSections.contains(section)) {
                    if (!header.group(1).equals(header.group(1).trim()))
                        throw incompatible(label + "目标配置节名称含未支持的首尾空白");
                    if (!seen.add(section)) throw incompatible(label + "存在重复的目标配置节");
                    result.values.put(section, new HashMap<String, String>());
                }
                continue;
            }
            int equals = line.indexOf('=');
            if (!headerSeen || equals < 1) throw incompatible(label + "不是已识别的 INI 格式");
            String key = line.substring(0, equals).trim().toLowerCase(Locale.ROOT);
            if (key.isEmpty()) throw incompatible(label + "字段名为空");
            if (!protectedSections.contains(section)) continue;
            Set<String> targetKeys = engine ? (section.equals(GEAR) ? GEAR_KEYS
                    : section.equals(FPS) ? names("unlimit") : SYSTEM_KEYS) : PAD_KEYS;
            if (key.length() > 1 && "+-!.".indexOf(key.charAt(0)) >= 0 && targetKeys.contains(key.substring(1)))
                throw incompatible(label + "目标字段出现未支持的数组操作符");
            if (!targetKeys.contains(key)) continue;
            String value = line.substring(equals + 1).trim();
            int comment = value.length();
            for (int i = 0; i < value.length(); i++) if (value.charAt(i) == ';' || value.charAt(i) == '#') {
                comment = i; break;
            }
            value = value.substring(0, comment).trim();
            Map<String, String> fields = result.values.get(section);
            if (fields.put(key, value) != null) throw incompatible(label + "存在重复的目标字段");
        }
        if (!headerSeen) throw incompatible(label + "缺少 INI 节标题");
        return result;
    }

    /** Known serialized pad tuple; accept order/whitespace changes, reject extra or missing members. */
    private static final class PadReader {
        private final String text;
        private int offset;
        PadReader(String text) throws GeneralSecurityException {
            if (text.length() > 16384) throw incompatible("渲染覆盖组过长");
            this.text = text;
        }
        void validate() throws GeneralSecurityException {
            symbol('(');
            Set<String> levels = new HashSet<String>();
            do {
                String level = name();
                if (!level.matches("level[1-5]config") || !levels.add(level))
                    throw incompatible("渲染覆盖的档位结构已变化或重复");
                symbol('='); symbol('(');
                Set<String> resolutions = new HashSet<String>();
                do {
                    String field = name();
                    if (!RESOLUTION_KEYS.contains(field) || !resolutions.add(field))
                        throw incompatible("渲染覆盖的分辨率字段已变化或重复");
                    symbol('=');
                    int value = number();
                    if (value < 1 || value > 8192) throw incompatible("渲染覆盖尺寸超出已识别范围");
                } while (take(','));
                symbol(')');
                if (resolutions.size() != RESOLUTION_KEYS.size())
                    throw incompatible("渲染覆盖组缺少已知分辨率字段");
            } while (take(','));
            symbol(')');
            space();
            if (levels.size() != 5 || offset != text.length())
                throw incompatible("渲染覆盖组的数量或结尾格式已变化");
        }
        private void space() { while (offset < text.length() && Character.isWhitespace(text.charAt(offset))) offset++; }
        private String name() throws GeneralSecurityException {
            space(); int start = offset;
            while (offset < text.length()) {
                char c = text.charAt(offset);
                if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_') offset++;
                else break;
            }
            if (start == offset || offset - start > 64) throw incompatible("渲染覆盖字段名格式已变化");
            return text.substring(start, offset).toLowerCase(Locale.ROOT);
        }
        private int number() throws GeneralSecurityException {
            space(); int start = offset;
            if (offset < text.length() && text.charAt(offset) == '+') offset++;
            while (offset < text.length() && text.charAt(offset) >= '0' && text.charAt(offset) <= '9') offset++;
            String value = text.substring(start, offset);
            return integer(value, "渲染覆盖尺寸");
        }
        private boolean take(char expected) {
            space();
            if (offset < text.length() && text.charAt(offset) == expected) { offset++; return true; }
            return false;
        }
        private void symbol(char expected) throws GeneralSecurityException {
            if (!take(expected)) throw incompatible("渲染覆盖括号或分隔符结构已变化");
        }
    }
}
