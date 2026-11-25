package io.github.deltaconfig.core;

import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Only changes authenticated, evidenced configuration settings; never changes game code. */
public final class ConfigPatcher {
    public static final String[] QUALITY_LABELS = {"流畅", "标准", "精致", "高清", "极致", "终极"};
    public static final int[] QUALITY_VALUES = {0, 1, 2, 3, 4, 5};
    public static final String[] FPS_LABELS = {"60 帧", "90 帧", "120 帧", "144 帧", "165 帧", "185 帧"};
    public static final int[] FPS_VALUES = {2, 7, 8, 9, 10, 11};
    public static final String PAD_SECTION = "/Script/PerfGear.PerfGearAndroidPadSizeConfig";
    private static final Pattern HEADER = Pattern.compile("^[ \\t]*\\[([^\\]\\r\\n]+)\\][ \\t]*(?:[;#].*)?$");
    private ConfigPatcher() { }

    public static final class Plan {
        public final byte[] engine, game;
        public final String summary;
        /** Requested scene short edge; 8192 is the game's native-surface-clamped sentinel. */
        public final int targetShortEdge;
        private Plan(byte[] engine, byte[] game, String summary, int targetShortEdge) {
            this.engine = engine; this.game = game;
            this.summary = summary; this.targetShortEdge = targetShortEdge;
        }
    }

    public static Plan plan(byte[] engine, byte[] game, byte[] gameplay, byte[] mask,
            int qualityInternal, int fpsInternal, int renderPercent, int baseShortEdge)
            throws Exception {
        try {
            if (qualityInternal < 0 || qualityInternal > 5)
                throw new IllegalArgumentException("画质档位不受支持");
            if (fpsForInternal(fpsInternal) < 0) throw new IllegalArgumentException("帧率档位映射未经验证");
            if (renderPercent < 25 || renderPercent > 100)
                throw new IllegalArgumentException("渲染比例须为 25% 至 100%");
            if (baseShortEdge < 1 || baseShortEdge > 8192)
                throw new IllegalArgumentException("屏幕短边无效");
        } catch (Exception error) {
            throw OperationFailure.wrap("生成修改配置", "检查画质、帧率及渲染比例参数", "Engine.ini / Game.ini", error);
        }
        final int fps = fpsForInternal(fpsInternal);
        if (game == null || game.length == 0 || game.length > ConfigCrypto.MAX_INI_BYTES)
            throw new OperationFailure("生成修改配置", "检查 Game.ini 输入大小", "Game.ini", "Game.ini 为空或超过 2 MiB", null);
        byte[] key;
        try { key = ConfigCrypto.deriveKey(mask, gameplay); }
        catch (Exception error) {
            throw OperationFailure.wrap("生成修改配置", "校验 UserGameplay.ini 并派生本机认证密钥", "UserGameplay.ini", error);
        }
        try {
            String original;
            try { original = ConfigCrypto.decodeIni(engine, key); }
            catch (Exception error) {
                throw OperationFailure.wrap("生成修改配置", "解密并校验 Engine.ini", "Engine.ini", error);
            }
            String changed;
            try {
                changed = setField(original, "DFMPerfGearConfig", "DFMQualityLevel", "" + qualityInternal);
                changed = setField(changed, "DFMPerfGearConfig", "DFMFPSLevel", "" + fpsInternal);
                changed = setField(changed, "QualityFPSSetting", "Unlimit", "1");
                if (fps >= 90)
                    changed = setField(changed, "SystemSettings", "DFMDeviceFrame.White" + fps + "fps", "1");
                changed = setField(changed, "SystemSettings", "PerfGear.SmallPadSize", "0");
            } catch (Exception error) {
                throw OperationFailure.wrap("生成修改配置", "更新 Engine.ini 的画质、帧率及设备字段", "Engine.ini", error);
            }
            byte[] newEngine;
            try { newEngine = ConfigCrypto.replaceIni(engine, changed, key); }
            catch (Exception error) {
                throw OperationFailure.wrap("生成修改配置", "重新加密、认证并回读 Engine.ini", "Engine.ini", error);
            }

            boolean bom = game.length >= 3 && (game[0] & 255) == 0xef
                    && (game[1] & 255) == 0xbb && (game[2] & 255) == 0xbf;
            String gameText;
            try {
                gameText = StandardCharsets.UTF_8.newDecoder()
                        .onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
                        .decode(ByteBuffer.wrap(game, bom ? 3 : 0, game.length - (bom ? 3 : 0))).toString();
            } catch (Exception error) {
                throw OperationFailure.wrap("生成修改配置", "按 UTF-8 解码 Game.ini", "Game.ini", error);
            }
            int target = renderPercent == 100 ? 8192
                    : Math.max(1, (int) Math.round(baseShortEdge * (renderPercent / 100.0)));
            String[] fields = {"UltraLowResolution", "LowResolution", "MidResolution", "HighResolution",
                    "UltraHighResolution", "SuperResolution"};
            StringBuilder inner = new StringBuilder("BackBuffer=8192");
            for (String field : fields) inner.append(',').append(field).append('=').append(target);
            StringBuilder group = new StringBuilder("(");
            for (int level = 1; level <= 5; level++) {
                if (level != 1) group.append(',');
                group.append("Level").append(level).append("Config=(").append(inner).append(')');
            }
            group.append(')');
            try {
                for (String size : new String[]{"Small", "Mid", "Big"})
                    gameText = setField(gameText, PAD_SECTION, size + "PadConfig", group.toString());
            } catch (Exception error) {
                throw OperationFailure.wrap("生成修改配置", "更新 Game.ini 的各档渲染分辨率字段", "Game.ini", error);
            }
            byte[] utf8 = gameText.getBytes(StandardCharsets.UTF_8);
            byte[] newGame = bom ? new byte[utf8.length + 3] : utf8;
            if (bom) {
                System.arraycopy(game, 0, newGame, 0, 3);
                System.arraycopy(utf8, 0, newGame, 3, utf8.length);
            }
            if (newGame.length > ConfigCrypto.MAX_INI_BYTES)
                throw new OperationFailure("生成修改配置", "校验 Game.ini 重新编码大小", "Game.ini", "修改后的 Game.ini 超过 2 MiB", null);
            String summary = qualityLabel(qualityInternal) + " / " + fps + " 帧请求 / 渲染 " + renderPercent
                    + "%\n三组设备配置的全部画质档位使用同一渲染目标；安装包与 UserGameplay.ini 不修改。"
                    + "\n实际帧率与分辨率受游戏运行时、显示模式和设备性能约束。"
                    + (qualityInternal == 5 ? "\n终极画质的资源表独立帧率上限未被本工具覆盖。" : "");
            return new Plan(newEngine, newGame, summary, target);
        } finally { Arrays.fill(key, (byte) 0); }
    }

    /** Clear only the local overrides this tool can set. Defaults are chosen by the game. */
    public static Plan resetDefaults(byte[] engine, byte[] game, byte[] gameplay, byte[] mask)
            throws Exception {
        final String operation = "恢复默认画质设置";
        if (game == null || game.length == 0 || game.length > ConfigCrypto.MAX_INI_BYTES)
            throw new OperationFailure(operation, "检查渲染配置输入大小", "Game.ini", "配置为空或超过安全大小上限", null);
        final byte[] key;
        try { key = ConfigCrypto.deriveKey(mask, gameplay); }
        catch (Exception error) { throw OperationFailure.wrap(operation, "验证本机认证信息", "UserGameplay.ini", error); }
        try {
            String plain;
            try { plain = ConfigCrypto.decodeIni(engine, key); }
            catch (Exception error) { throw OperationFailure.wrap(operation, "解密并认证主配置", "Engine.ini", error); }
            String cleaned = removeFields(plain, "DFMPerfGearConfig", "DFMQualityLevel", "DFMFPSLevel");
            cleaned = removeFields(cleaned, "QualityFPSSetting", "Unlimit");
            cleaned = removeFields(cleaned, "SystemSettings", "PerfGear.SmallPadSize",
                    "DFMDeviceFrame.White90fps", "DFMDeviceFrame.White120fps", "DFMDeviceFrame.White144fps",
                    "DFMDeviceFrame.White165fps", "DFMDeviceFrame.White185fps");
            final byte[] newEngine;
            try { newEngine = ConfigCrypto.replaceIni(engine, cleaned, key); }
            catch (Exception error) { throw OperationFailure.wrap(operation, "重新封装并认证主配置", "Engine.ini", error); }
            boolean bom = game.length >= 3 && (game[0] & 255) == 0xef
                    && (game[1] & 255) == 0xbb && (game[2] & 255) == 0xbf;
            final String gameText;
            try {
                gameText = StandardCharsets.UTF_8.newDecoder()
                        .onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
                        .decode(ByteBuffer.wrap(game, bom ? 3 : 0, game.length - (bom ? 3 : 0))).toString();
                if (gameText.indexOf('\0') >= 0 || !Pattern.compile("(?m)^[ \\t]*\\[[^\\]\\r\\n]+\\]").matcher(gameText).find())
                    throw new IllegalArgumentException("渲染配置不是受支持的 INI 格式");
            } catch (Exception error) { throw OperationFailure.wrap(operation, "解码并验证渲染配置", "Game.ini", error); }
            String resetGame = removeFields(gameText, PAD_SECTION, "SmallPadConfig", "MidPadConfig", "BigPadConfig");
            byte[] utf8 = resetGame.getBytes(StandardCharsets.UTF_8);
            byte[] newGame = bom ? new byte[utf8.length + 3] : utf8;
            if (bom) {
                System.arraycopy(game, 0, newGame, 0, 3);
                System.arraycopy(utf8, 0, newGame, 3, utf8.length);
            }
            return new Plan(newEngine, newGame,
                    "清除本工具涉及的画质、帧率和渲染覆盖项。\n保留其余配置与本机认证信息；默认档位由游戏下次启动时自行生成。", 0);
        } finally { Arrays.fill(key, (byte) 0); }
    }

    private static String removeFields(String text, String section, String... keys) {
        StringBuilder result = new StringBuilder(text.length());
        boolean inside = false;
        for (String line : lines(text)) {
            String body = withoutEnding(line);
            Matcher header = HEADER.matcher(body);
            if (header.matches()) {
                inside = header.group(1).equalsIgnoreCase(section);
                result.append(line);
                continue;
            }
            boolean remove = false;
            if (inside) for (String key : keys) {
                if (Pattern.compile("^[ \\t]*" + Pattern.quote(key) + "[ \\t]*=.*$", Pattern.CASE_INSENSITIVE).matcher(body).matches()) {
                    remove = true; break;
                }
            }
            if (!remove) result.append(line);
        }
        return result.toString();
    }

    public static int fpsForInternal(int value) {
        switch (value) { case 2: return 60; case 7: return 90; case 8: return 120; case 9: return 144;
            case 10: return 165; case 11: return 185; default: return -1; }
    }

    public static String qualityLabel(int value) {
        return value >= 0 && value < QUALITY_LABELS.length ? QUALITY_LABELS[value] : "未知档位";
    }

    public static int getInt(String text, String section, String key, int fallback) {
        try {
            boolean inside = false;
            Pattern field = Pattern.compile("^[ \\t]*" + Pattern.quote(key) + "[ \\t]*=[ \\t]*([+-]?[0-9]+)[ \\t]*(?:[;#].*)?$", Pattern.CASE_INSENSITIVE);
            for (String line : lines(text)) {
                String body = withoutEnding(line);
                Matcher header = HEADER.matcher(body);
                if (header.matches()) { inside = header.group(1).equalsIgnoreCase(section); continue; }
                Matcher value = field.matcher(body);
                if (inside && value.matches()) return Integer.parseInt(value.group(1));
            }
        } catch (RuntimeException ignored) { }
        return fallback;
    }

    private static String setField(String text, String section, String key, String value) {
        String newline = text.contains("\r\n") ? "\r\n" : text.contains("\n") ? "\n" : text.contains("\r") ? "\r" : "\n";
        List<String> lines = lines(text);
        int start = -1, end = lines.size();
        for (int i = 0; i < lines.size(); i++) {
            Matcher header = HEADER.matcher(withoutEnding(lines.get(i)));
            if (!header.matches()) continue;
            if (start >= 0 && end == lines.size()) end = i;
            if (header.group(1).equalsIgnoreCase(section)) {
                if (start >= 0) throw new IllegalArgumentException("目标配置节重复: " + section);
                start = i + 1;
            }
        }
        if (start < 0) {
            String separator = text.isEmpty() || text.endsWith(newline + newline) ? ""
                    : text.endsWith("\n") || text.endsWith("\r") ? newline : newline + newline;
            return text + separator + '[' + section + ']' + newline + key + '=' + value + newline;
        }
        Pattern field = Pattern.compile("^([ \\t]*" + Pattern.quote(key) + "[ \\t]*=[ \\t]*)([^\\r\\n]*)$", Pattern.CASE_INSENSITIVE);
        int found = -1;
        for (int i = start; i < end; i++) {
            Matcher match = field.matcher(withoutEnding(lines.get(i)));
            if (!match.matches()) continue;
            if (found >= 0) throw new IllegalArgumentException("目标字段重复: " + section + '.' + key);
            found = i;
            String old = lines.get(i);
            String ending = old.substring(withoutEnding(old).length());
            lines.set(i, match.group(1) + value + ending);
        }
        if (found < 0) {
            if (end > 0 && !lines.get(end - 1).endsWith("\n") && !lines.get(end - 1).endsWith("\r"))
                lines.set(end - 1, lines.get(end - 1) + newline);
            lines.add(end, key + '=' + value + newline);
        }
        StringBuilder result = new StringBuilder(text.length() + value.length() + 128);
        for (String line : lines) result.append(line);
        return result.toString();
    }

    private static List<String> lines(String text) {
        List<String> lines = new ArrayList<String>();
        int start = 0;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c != '\r' && c != '\n') continue;
            if (c == '\r' && i + 1 < text.length() && text.charAt(i + 1) == '\n') i++;
            lines.add(text.substring(start, i + 1)); start = i + 1;
        }
        if (start < text.length()) lines.add(text.substring(start));
        return lines;
    }

    private static String withoutEnding(String line) {
        int end = line.length();
        while (end > 0 && (line.charAt(end - 1) == '\r' || line.charAt(end - 1) == '\n')) end--;
        return line.substring(0, end);
    }
}
