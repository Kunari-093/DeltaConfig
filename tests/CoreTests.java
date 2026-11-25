import io.github.deltaconfig.core.ConfigCrypto;
import io.github.deltaconfig.core.ConfigCompatibility;
import io.github.deltaconfig.core.ConfigPatcher;
import io.github.deltaconfig.core.OperationFailure;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipFile;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Host-only tests. Real configuration inputs are supplied at runtime and never bundled. */
public final class CoreTests {
    private static int assertions;
    private interface Action { void run() throws Exception; }
    private static void check(boolean value, String message) {
        assertions++;
        if (!value) throw new AssertionError(message);
    }
    private static void rejects(Action action, String message) throws Exception {
        boolean failed = false;
        try { action.run(); } catch (GeneralSecurityException | IllegalArgumentException | OperationFailure ex) { failed = true; }
        check(failed, message);
    }
    private static byte[] envelope(String text, byte[] key, int magic, boolean padding,
            boolean quoted, String newline, int lengthOverride, boolean nonzeroPadding) throws Exception {
        int length = text.length();
        byte[] raw = new byte[(length + 6 + 15) & ~15];
        raw[0] = (byte) magic; raw[1] = (byte) (magic >>> 8);
        int declared = lengthOverride < 0 ? length : lengthOverride;
        for (int i = 0; i < 4; i++) raw[i + 2] = (byte) (declared >>> (i * 8));
        for (int i = 0; i < length; i++) raw[6 + i] = (byte) (text.charAt(i) - 1);
        if (nonzeroPadding) Arrays.fill(raw, length + 6, raw.length, (byte) 19);
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(new SecretKeySpec(key, "HmacSHA1"));
        byte[] tag = mac.doFinal(raw), aes = key.clone();
        for (int i = 0; i < 32; i++) aes[i] ^= tag[i % 20];
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aes, "AES"));
        byte[] ciphertext = cipher.doFinal(raw), combined = new byte[20 + ciphertext.length];
        System.arraycopy(tag, 0, combined, 0, 20);
        System.arraycopy(ciphertext, 0, combined, 20, ciphertext.length);
        String base64 = Base64.getEncoder().encodeToString(combined);
        if (!padding) base64 = base64.replaceAll("=+$", "");
        return ("; synthetic\u00e9" + newline + "[Envelope]" + newline + "tOkEn \t= \t"
                + (quoted ? "\"" : "") + base64 + (quoted ? "\"" : "") + " \t" + newline
                + "Other=preserved" + newline).getBytes(StandardCharsets.ISO_8859_1);
    }
    private static int occurrences(String text, String literal) {
        int result = 0, index = 0;
        while ((index = text.indexOf(literal, index)) >= 0) { result++; index += literal.length(); }
        return result;
    }
    private static Map<String, String> fields(String text) {
        Map<String, String> result = new HashMap<String, String>();
        String section = "";
        for (String line : text.split("\\r?\\n")) {
            if (line.startsWith("[") && line.endsWith("]")) section = line;
            else if (line.contains("=")) result.put(section + line.substring(0, line.indexOf('=')), line.substring(line.indexOf('=') + 1));
        }
        return result;
    }
    private static void syntheticTests() throws Exception {
        Random random = new Random(0x5a263e4);
        final byte[] key = new byte[32]; random.nextBytes(key);
        for (int magic : new int[]{0x4501, 0x4502}) {
            for (int length : new int[]{0, 1, 9, 10, 15, 16, 17, 255, 256, 4097}) {
                char[] chars = new char[length];
                for (int i = 0; i < length; i++) chars[i] = (char) (random.nextInt(256) + 1);
                String text = new String(chars);
                for (boolean quoted : new boolean[]{false, true}) {
                    for (boolean padding : new boolean[]{false, true}) {
                        byte[] ini = envelope(text, key, magic, padding, quoted, "\r\n", -1, false);
                        check(ConfigCrypto.decodeIni(ini, key).equals(text), "random payload decodes");
                        check(Arrays.equals(ConfigCrypto.replaceIni(ini, text, key), ini), "exact unchanged roundtrip");
                        String changed = text + "\u0001\u0100";
                        byte[] patched = ConfigCrypto.replaceIni(ini, changed, key);
                        check(ConfigCrypto.decodeIni(patched, key).equals(changed), "random payload modified roundtrip");
                        String oldRaw = new String(ini, StandardCharsets.ISO_8859_1);
                        String newRaw = new String(patched, StandardCharsets.ISO_8859_1);
                        String oldValue = new String(ConfigCrypto.getField(ini, "Token"), StandardCharsets.US_ASCII);
                        String newValue = new String(ConfigCrypto.getField(patched, "Token"), StandardCharsets.US_ASCII);
                        check(oldRaw.replace(oldValue, "REPLACED").equals(newRaw.replace(newValue, "REPLACED")), "wrapper bytes preserved");
                        check(padding || !newValue.endsWith("="), "padding convention retained");
                    }
                }
            }
        }
        final byte[] valid = envelope("[Test]\nx=1\n", key, 0x4502, true, false, "\n", -1, false);
        byte[] wrongKey = key.clone(); wrongKey[0] ^= 1;
        rejects(() -> ConfigCrypto.decodeIni(valid, wrongKey), "wrong key refused");
        byte[] oldToken = ConfigCrypto.getField(valid, "Token");
        byte[] combined = Base64.getDecoder().decode(oldToken);
        for (int offset : new int[]{0, 10, 19, 20, combined.length - 1}) {
            byte[] bad = combined.clone(); bad[offset] ^= 1;
            final byte[] ini = ("Token=" + Base64.getEncoder().encodeToString(bad) + "\n").getBytes(StandardCharsets.US_ASCII);
            rejects(() -> ConfigCrypto.decodeIni(ini, key), "tampering refused");
        }
        rejects(() -> ConfigCrypto.decodeIni("Token=not!base64\n".getBytes(StandardCharsets.US_ASCII), key), "invalid base64 refused");
        rejects(() -> ConfigCrypto.decodeIni("Token=AAAA\n".getBytes(StandardCharsets.US_ASCII), key), "invalid block length refused");
        rejects(() -> ConfigCrypto.decodeIni(envelope("abc", key, 0x9999, true, false, "\n", -1, false), key), "authenticated unsupported magic refused");
        rejects(() -> ConfigCrypto.decodeIni(envelope("abc", key, 0x4502, true, false, "\n", 9999, false), key), "authenticated invalid length refused");
        rejects(() -> ConfigCrypto.replaceIni(valid, "\u0000", key), "zero code point refused");
        rejects(() -> ConfigCrypto.replaceIni(valid, "\u0101", key), "unrepresentable code point refused");
        rejects(() -> ConfigCrypto.getField(new byte[ConfigCrypto.MAX_INI_BYTES + 1], "Token"), "oversized input refused");
        rejects(() -> ConfigCrypto.getField("Token=AA\nToken=BB\n".getBytes(StandardCharsets.US_ASCII), "Token"), "duplicate envelopes refused");
        byte[] nonzero = envelope("abc", key, 0x4501, false, true, "\r\n", -1, true);
        check(Arrays.equals(nonzero, ConfigCrypto.replaceIni(nonzero, "abc", key)), "authenticated original padding preserved on no-op");
        byte[] mask = new byte[32]; random.nextBytes(mask);
        byte[] obfuscated = mask.clone(); for (int i = 0; i < 32; i++) obfuscated[i] ^= (byte) 0xe2;
        check(Arrays.equals(mask, ConfigCrypto.decodeFixedMask(obfuscated)), "mask decoding");
        String hash = "00112233445566778899aabbccddeeff00112233";
        byte[] manifest = new String(envelope(hash, mask, 0x4502, true, false, "\n", -1, false), StandardCharsets.ISO_8859_1)
                .replace("tOkEn", "Hash").getBytes(StandardCharsets.ISO_8859_1);
        byte[] expected = mask.clone();
        for (int i = 0; i < 32; i++) expected[i] ^= (byte) Integer.parseInt(hash.substring((i % 20) * 2, (i % 20) * 2 + 2), 16);
        check(Arrays.equals(expected, ConfigCrypto.deriveKey(mask, manifest)), "authenticated manifest key derivation");
        rejects(() -> ConfigCrypto.deriveKey(key, manifest), "manifest wrong mask refused");
        check(ConfigPatcher.getInt("[A]\r\nx=7\r\n[B]\r\nx=9\r\n", "A", "x", -1) == 7, "integer getter scoped to section");
        check(ConfigPatcher.getInt("[A]\nx=invalid\n", "A", "x", 3) == 3, "integer getter uses fallback");
        byte[] syntheticEngine = envelope("[DFMPerfGearConfig]\nDFMQualityLevel=1\nDFMFPSLevel=8\n",
                expected, 0x4502, true, false, "\n", -1, false);
        byte[] syntheticGame = "[LuaFrontEnd]\nLastHotUpdateVersion=synthetic\n".getBytes(StandardCharsets.UTF_8);
        for (int quality = 0; quality <= 5; quality++) for (int fps : ConfigPatcher.FPS_VALUES)
            for (int percent : new int[]{25, 75, 100}) {
                ConfigPatcher.Plan plan = ConfigPatcher.plan(syntheticEngine, syntheticGame, manifest, mask, quality, fps, percent, 1440);
                ConfigCompatibility.validate(ConfigCrypto.decodeIni(plan.engine, expected), plan.game);
                check(true, "generated synthetic plan passes structural compatibility for every supported combination");
            }
        Arrays.fill(expected, (byte) 0); Arrays.fill(mask, (byte) 0);
    }


    public static final class SampleTransportFailure extends java.io.IOException {
        public SampleTransportFailure(String detail) { super(detail); }
        public Integer getExitCode() { return 13; }
    }
    private static OperationFailure failure(Action action) throws Exception {
        try { action.run(); }
        catch (OperationFailure error) { return error; }
        throw new AssertionError("expected precise OperationFailure");
    }
    private static void resetTests() throws Exception {
        Random random = new Random(0x5e7defa);
        final byte[] mask = new byte[32]; random.nextBytes(mask);
        String digest = "00112233445566778899aabbccddeeff00112233";
        final byte[] gameplay = new String(envelope(digest, mask, 0x4502, false, true, "\r\n", -1, false), StandardCharsets.ISO_8859_1)
                .replace("tOkEn", "Hash").getBytes(StandardCharsets.ISO_8859_1);
        final byte[] key = ConfigCrypto.deriveKey(mask, gameplay);
        for (String newline : new String[]{"\r\n", "\n", "\r"}) {
            String original = "; Engine comment - DFMFPSLevel=KEEP" + newline
                    + "[DFMPerfGearConfig] ; quality section" + newline
                    + "DFMQualityLevel=5" + newline + " dFmFpSlEvEl \t=11 ; duplicate below" + newline
                    + "DFMFPSLevel=9" + newline + "DFMFPSLevelSuffix=preserve" + newline
                    + "OtherSetting=42" + newline + "[DFMPerfGearConfig]" + newline + "DFMQualityLevel=3" + newline
                    + "[QualityFPSSetting]" + newline + ";Unlimit=comment" + newline + "Unlimit=1" + newline
                    + "Unknown=retain" + newline + "[SystemSettings]" + newline
                    + "PerfGear.SmallPadSize=0" + newline + "DFMDeviceFrame.White90fps=1" + newline
                    + "DFMDeviceFrame.White120fps=1" + newline + "DFMDeviceFrame.White144fps=1" + newline
                    + "DFMDeviceFrame.White165fps=1" + newline + "DFMDeviceFrame.White185fps=1" + newline
                    + "DFMDeviceFrame.White60fps=1" + newline + "DFMDeviceFrame.White240fps=1" + newline
                    + "[SYSTEMSETTINGS]" + newline + "dfmdeviceframe.white185FPS=1" + newline
                    + "[Other]" + newline + "DFMQualityLevel=unrelated" + newline + "Unlimit=unrelated" + newline
                    + "PerfGear.SmallPadSize=unrelated" + newline + "Trailing=untouched";
            String expected = "; Engine comment - DFMFPSLevel=KEEP" + newline
                    + "[DFMPerfGearConfig] ; quality section" + newline
                    + "DFMFPSLevelSuffix=preserve" + newline + "OtherSetting=42" + newline
                    + "[DFMPerfGearConfig]" + newline + "[QualityFPSSetting]" + newline
                    + ";Unlimit=comment" + newline + "Unknown=retain" + newline + "[SystemSettings]" + newline
                    + "DFMDeviceFrame.White60fps=1" + newline + "DFMDeviceFrame.White240fps=1" + newline
                    + "[SYSTEMSETTINGS]" + newline + "[Other]" + newline + "DFMQualityLevel=unrelated" + newline
                    + "Unlimit=unrelated" + newline + "PerfGear.SmallPadSize=unrelated" + newline + "Trailing=untouched";
            String gameOriginal = "\ufeff; Game comment preserved\r\n[LuaFrontEnd]\nLastHotUpdateVersion=39\r"
                    + "[" + ConfigPatcher.PAD_SECTION + "] ; reset exact three keys\r\n"
                    + "SmallPadConfig=(Level1=example)\r\nMidPadConfig=abc\nBigPadConfig=xyz\r"
                    + "SmallPadConfig=duplicate\n;SmallPadConfig=comment\nUnknownPadConfig=retained\r\n"
                    + "[" + ConfigPatcher.PAD_SECTION.toUpperCase(java.util.Locale.ROOT) + "]\r\n"
                    + " smallpadconfig \t=other-duplicate\n[Other]\rSmallPadConfig=unrelated\r\nTail=\u4e2d\u6587";
            String gameExpected = "\ufeff; Game comment preserved\r\n[LuaFrontEnd]\nLastHotUpdateVersion=39\r"
                    + "[" + ConfigPatcher.PAD_SECTION + "] ; reset exact three keys\r\n"
                    + ";SmallPadConfig=comment\nUnknownPadConfig=retained\r\n"
                    + "[" + ConfigPatcher.PAD_SECTION.toUpperCase(java.util.Locale.ROOT) + "]\r\n"
                    + "[Other]\rSmallPadConfig=unrelated\r\nTail=\u4e2d\u6587";
            byte[] engine = envelope(original, key, 0x4501, false, true, newline, -1, false);
            byte[] game = gameOriginal.getBytes(StandardCharsets.UTF_8);
            byte[] engineCopy = engine.clone(), gameCopy = game.clone(), gameplayCopy = gameplay.clone(), maskCopy = mask.clone();
            ConfigPatcher.Plan reset = ConfigPatcher.resetDefaults(engine, game, gameplay, mask);
            check(ConfigCrypto.decodeIni(reset.engine, key).equals(expected), "reset deletes every scoped Engine override and preserves every other byte");
            check(Arrays.equals(gameExpected.getBytes(StandardCharsets.UTF_8), reset.game), "reset preserves Game BOM, mixed newlines, comments and unrelated values");
            String oldToken = new String(ConfigCrypto.getField(engine, "Token"), StandardCharsets.US_ASCII);
            String newToken = new String(ConfigCrypto.getField(reset.engine, "Token"), StandardCharsets.US_ASCII);
            check(new String(engine, StandardCharsets.ISO_8859_1).replace(oldToken, "VALUE")
                    .equals(new String(reset.engine, StandardCharsets.ISO_8859_1).replace(newToken, "VALUE")), "reset preserves envelope wrapper byte-for-byte");
            check(!newToken.endsWith("="), "reset preserves no-padding envelope convention");
            ConfigPatcher.Plan again = ConfigPatcher.resetDefaults(reset.engine, reset.game, gameplay, mask);
            check(Arrays.equals(reset.engine, again.engine) && Arrays.equals(reset.game, again.game), "reset is byte-idempotent");
            check(Arrays.equals(engine, engineCopy) && Arrays.equals(game, gameCopy)
                    && Arrays.equals(gameplay, gameplayCopy) && Arrays.equals(mask, maskCopy), "reset never mutates supplied arrays");
        }
        final byte[] cleanEngine = envelope("[Untouched]\nx=1\n", key, 0x4502, true, false, "\n", -1, false);
        final byte[] cleanGame = "[Untouched]\nSmallPadConfig=other-section\n".getBytes(StandardCharsets.UTF_8);
        ConfigPatcher.Plan clean = ConfigPatcher.resetDefaults(cleanEngine, cleanGame, gameplay, mask);
        check(Arrays.equals(cleanEngine, clean.engine) && Arrays.equals(cleanGame, clean.game), "reset without scoped keys is an exact no-op");
        rejects(() -> ConfigPatcher.resetDefaults(cleanEngine, new byte[0], gameplay, mask), "reset refuses empty Game");
        rejects(() -> ConfigPatcher.resetDefaults(cleanEngine, new byte[]{(byte) 0xc3, 0x28}, gameplay, mask), "reset refuses malformed UTF8 Game");
        rejects(() -> ConfigPatcher.resetDefaults(cleanEngine, "[X]\nx=\0".getBytes(StandardCharsets.UTF_8), gameplay, mask), "reset refuses NUL Game");
        rejects(() -> ConfigPatcher.resetDefaults(cleanEngine, "not-an-ini".getBytes(StandardCharsets.UTF_8), gameplay, mask), "reset refuses non-INI Game");
        rejects(() -> ConfigPatcher.resetDefaults("Token=broken".getBytes(StandardCharsets.US_ASCII), cleanGame, gameplay, mask), "reset refuses unauthenticated Engine");
        rejects(() -> ConfigPatcher.resetDefaults(cleanEngine, cleanGame, "Hash=broken".getBytes(StandardCharsets.US_ASCII), mask), "reset refuses unauthenticated gameplay context");
        Arrays.fill(key, (byte) 0); Arrays.fill(mask, (byte) 0);
    }

    private static void userReportTests() throws Exception {
        String enginePath = "/data/user/0/com.tencent.tmgp.dfm/files/UE4Game/DeltaForce/DeltaForce/Saved/Config/Android/Engine.ini";
        String gamePath = enginePath.replace("Engine.ini", "Game.ini");
        OperationFailure primary = new OperationFailure("读取 Engine.ini 配置", "定位 " + enginePath,
                enginePath, "Engine.ini 文件不可见，请检查 /data/user/0/com.tencent.tmgp.dfm/files",
                new SampleTransportFailure("Permission denied at " + gamePath + "; UserGameplay.ini libUE4.so\nE:\\apk\\change\\1.zip"))
                .state("未写入 " + enginePath, "无需回滚 Game.ini", "/data/adb/deltaconfig/backups/test").exitCode(44);
        primary.addSuppressed(new OperationFailure("回退读取", "打开 UserGameplay.ini", "/data/media/0/Android/data/game/UserGameplay.ini",
                "libUE4.so read failed /data/app/random/base.apk", null));
        OperationFailure outer = OperationFailure.wrap("读取配置", "执行操作", gamePath, primary);
        String detailed = OperationFailure.format(outer), brief = OperationFailure.userReport(outer);
        for (String banned : new String[]{"目标文件：", "备份位置：", "详细原因链", "其他尝试", "外层上下文", "Engine.ini", "Game.ini",
                "UserGameplay.ini", "libUE4.so", "base.apk", "/data/", "E:\\apk", "1.zip"})
            check(!brief.contains(banned), "short report omits path, basename or expanded trace: " + banned);
        for (String required : new String[]{"操作：", "阶段：", "原因：", "退出码：", "写入状态：", "回滚状态："})
            check(brief.contains(required), "short report retains actionable field: " + required);
        check(brief.contains("44") || brief.contains("13"), "short report retains actual process exit code");
        check(brief.contains("Permission denied") || brief.contains("不可见"), "short report retains failure classification");
        check(brief.contains("未写入") && brief.contains("无需回滚"), "short report retains transaction knowledge");
        check(brief.length() <= 2400, "short report is bounded for a dialog");
        check(detailed.contains(enginePath) && detailed.contains(gamePath) && detailed.contains("详细原因链"), "detailed report keeps diagnostic file and cause evidence");
        check(detailed.contains("UserGameplay.ini") && detailed.contains("libUE4.so"), "full log retains fallback file evidence");

        java.io.IOException raw = new java.io.IOException("cat /storage/emulated/0/Android/data/game/UserGameplay.ini: No such file or directory");
        raw.addSuppressed(new java.io.IOException("Engine.ini fallback C:\\Users\\owner\\Desktop\\Game.ini failed"));
        brief = OperationFailure.userReport(raw);
        check(!brief.contains("/storage/") && !brief.contains("UserGameplay.ini") && !brief.contains("Engine.ini")
                && !brief.contains("Game.ini") && !brief.contains("C:\\Users"), "short unexpected error cannot expose raw path or filenames");
        check(brief.contains("No such file") || brief.contains("不存在") || brief.contains("找不到"), "short unexpected error retains useful missing-file reason");
        check(!OperationFailure.userReport(new RuntimeException()).contains("目标文件："), "short unexpected blank failure has no target field");
        check(OperationFailure.userReport(null).contains("原因："), "short missing exception reports uncertainty without throwing");
    }
    private static void diagnosticTests() throws Exception {
        String enginePath = "/data/user/0/com.tencent.tmgp.dfm/files/UE4Game/DeltaForce/DeltaForce/Saved/Config/Android/Engine.ini";
        OperationFailure inner = new OperationFailure("配置解码", "认证 Engine", "Engine.ini", "HMAC 认证失败", new GeneralSecurityException("HMAC mismatch"));
        OperationFailure wrapped = OperationFailure.wrap("读取配置", "解析 Engine.ini", enginePath, inner);
        check(wrapped == inner, "precise failure object and state retained by wrap");
        String detailed = OperationFailure.format(wrapped);
        check(detailed.contains("目标文件：" + enginePath), "full absolute file path promoted from outer context");
        check(detailed.contains("阶段：认证 Engine") && detailed.contains("解析 Engine.ini"), "inner stage and outer stage both survive");
        check(detailed.contains("HMAC mismatch") && detailed.contains("HMAC 认证失败"), "root cause and contextual reason both survive");
        check(detailed.contains("同一安装版本"), "authentication advice remains actionable");
        check(detailed.contains("写入状态：未知") && detailed.contains("回滚状态：未知"), "missing transaction knowledge never claims rollback");

        OperationFailure transaction = new OperationFailure("写入配置", "提交第二个文件", enginePath, "Game.ini 写入后回读不一致", new SampleTransportFailure("Permission denied; SELinux avc: denied"))
                .state("Engine 已写入；Game 状态未知", "Engine 已回滚；Game 回滚失败", "/data/user/0/io.github.deltaconfig/files/backups/20261025");
        transaction.addSuppressed(new OperationFailure("回滚", "恢复 Game.ini", enginePath.replace("Engine.ini", "Game.ini"), "Read-only file system", null).exitCode(30));
        detailed = OperationFailure.format(OperationFailure.wrap("修改配置", "完成事务", enginePath, transaction));
        check(detailed.contains("Engine 已回滚；Game 回滚失败"), "partial rollback status retained exactly");
        check(detailed.contains("退出码：13") && detailed.contains("退出码：30"), "primary and secondary process exit codes shown");
        check(detailed.contains("Permission denied") && detailed.contains("SELinux avc: denied"), "permission diagnostics stay visible");
        check(detailed.contains("恢复 Game.ini") && detailed.contains("Read-only file system"), "rollback secondary failure details retained");
        check(detailed.contains("备份位置：/data/user/0/io.github.deltaconfig/files/backups/20261025"), "backup location remains exact");
        OperationFailure afterCommit = new OperationFailure("刷新界面", "提交后重读", enginePath, "刷新失败", transaction)
                .state("两份文件已提交并通过校验", "未执行；配置已提交", null);
        detailed = OperationFailure.format(afterCommit);
        check(detailed.contains("写入状态：两份文件已提交并通过校验"), "outer committed state overrides earlier state");
        check(detailed.contains("Engine 已写入；Game 状态未知"), "inner transaction state is still included for diagnosis");

        OperationFailure libraries = new OperationFailure("读取游戏库", "尝试所有库位置", "libUE4.so", "没有可读取的库", null);
        libraries.addSuppressed(new OperationFailure("读取库", "读取安装目录", "/data/app/random/com.tencent.tmgp.dfm/lib/arm64/libUE4.so", "No such file or directory", null));
        libraries.addSuppressed(new OperationFailure("读取库", "读取 APK 成员", "/data/app/random/com.tencent.tmgp.dfm/base.apk!/lib/arm64-v8a/libUE4.so", "Permission denied", null));
        detailed = OperationFailure.format(libraries);
        check(detailed.contains("/lib/arm64/libUE4.so") && detailed.contains("base.apk!/lib/arm64-v8a/libUE4.so"), "every library candidate path shown");
        check(detailed.contains("No such file or directory") && detailed.contains("Permission denied"), "every library fallback reason shown");

        String token = "aBcD0123456789+/aBcD0123456789+/aBcD0123456789+/aBcD0123456789+/=";
        String hash = "abcdef0123456789abcdef0123456789abcdef01";
        String secrets = "Token=" + token + "\nHash=" + hash + "\nkey='secret value'\nAndroidID=abcd76543210\ndeviceId: 357990045612345\n"
                + "uin=123456789 account='user-name' phone=13812345678\n手机号：13812345678\n"
                + "command: su -c cat /private/file\nRaw=" + token + "\n"
                + "Permission denied SELinux No such file version=2207 uid=10471\n" + enginePath;
        String redacted = OperationFailure.sanitize(secrets);
        for (String secret : new String[]{token, hash, "secret value", "abcd76543210", "357990045612345", "123456789", "user-name", "13812345678", "su -c cat"})
            check(!redacted.contains(secret), "sensitive value redacted at case " + java.util.Arrays.asList(token, hash, "secret value", "abcd76543210", "357990045612345", "123456789", "user-name", "13812345678", "su -c cat").indexOf(secret));
        check(redacted.contains(enginePath), "ordinary Android file path preserved after redaction");
        check(redacted.contains("version=2207 uid=10471") && redacted.contains("Permission denied SELinux No such file"), "version UID and diagnostic text not mistaken for secrets");
        String installPath = "/data/app/~~aBcD0123456789abcdefghijklmno==/com.tencent.tmgp.dfm-random/lib/arm64/libUE4.so";
        check(OperationFailure.sanitize(installPath).equals(installPath), "dynamic install path preserved for locating actual file");
        OperationFailure secretError = new OperationFailure("读取", "认证", enginePath, secrets, new java.io.IOException(secrets));
        secretError.addSuppressed(new java.io.IOException("Hash=" + hash));
        detailed = OperationFailure.format(secretError);
        check(!detailed.contains(token) && !detailed.contains(hash) && !detailed.contains("13812345678"), "full cause/suppressed report cannot reintroduce secrets");
        check(OperationFailure.sanitize(redacted).equals(redacted), "redaction idempotent");
        String unquotedSecrets = "Token=first second third\naccount=ordinary name with spaces\npassword=unguoted password with spaces\n\"deviceId\":\"short-id\"\nHash=has spaces after hash\n目标文件：" + enginePath;
        OperationFailure unquotedFailure = new OperationFailure("读取", "认证", enginePath, unquotedSecrets, new java.io.IOException(unquotedSecrets));
        unquotedFailure.addSuppressed(new java.io.IOException(unquotedSecrets));
        String unquotedReport = OperationFailure.format(unquotedFailure);
        for (String secret : new String[]{"first", "second", "third", "ordinary name", "unguoted password", "short-id", "has spaces after hash"})
            check(!unquotedReport.contains(secret), "unquoted or JSON secret cannot leak through any cause branch");
        check(unquotedReport.contains(enginePath), "redacting whole secret line preserves next line file context");
        check(OperationFailure.format(new java.io.IOException("root command failed: SELinux avc: denied")).contains("对应文件的 SELinux"), "file SELinux denial is not misreported as rejected root authorization");
        check(OperationFailure.format(new OperationFailure("读取权限", "读取 SELinux 标签", enginePath, "No such file or directory", null)).contains("至少启动一次"), "a metadata stage mentioning SELinux cannot hide the real missing-file cause");
        String commandFailure = OperationFailure.sanitize("su -c cat /data/private/file: Permission denied; echo private-command");
        check(commandFailure.contains("Permission denied") && !commandFailure.contains("private-command") && !commandFailure.contains("cat /data"), "shell command redacted while known failure reason retained");
        for (String reason : new String[]{"No space left on device", "Read-only file system", "root 授权被拒绝", "SELinux avc: denied", "No such file or directory", "文件发生变化", "库不匹配 ELF", "格式不受支持"})
            check(!OperationFailure.format(new java.io.IOException(reason)).contains("建议：保留此报告；"), "known failure class gets specific advice");

        StringBuilder longMessage = new StringBuilder("START-marker ");
        for (int i = 0; i < 2500; i++) longMessage.append("详细错误 ");
        longMessage.append(" END-marker Permission denied");
        detailed = OperationFailure.format(new OperationFailure("读取", "长错误", enginePath, "外层原因", new java.io.IOException(longMessage.toString())));
        check(detailed.length() <= 12000 && detailed.contains("START-marker") && detailed.contains("END-marker"), "long single cause bounded and keeps both useful ends");
        check(detailed.length() > 900, "single cause is not discarded at an unhelpful 900 character cap");
        java.io.IOException cyclicA = new java.io.IOException("cycle A"), cyclicB = new java.io.IOException("cycle B");
        cyclicA.initCause(cyclicB); cyclicB.initCause(cyclicA); cyclicA.addSuppressed(cyclicB); cyclicB.addSuppressed(cyclicA);
        detailed = OperationFailure.format(cyclicA);
        check(detailed.contains("cycle A") && detailed.contains("cycle B") && detailed.length() <= 12000, "cyclic cause and suppressed graph terminates");
        Throwable many = new java.io.IOException("deep root");
        for (int i = 0; i < 600; i++) many = new java.io.IOException("context " + i, many);
        check(OperationFailure.format(many).length() <= 12000, "very deep exception graph bounded");
        check(OperationFailure.format(new RuntimeException()).contains("回滚状态：未知"), "plain unexpected exception cannot falsely claim rollback");
        check(OperationFailure.format(null).contains("无法确认失败原因"), "missing exception reports uncertainty");

        Random random = new Random(9517);
        final byte[] mask = new byte[32]; random.nextBytes(mask);
        String digest = "00112233445566778899aabbccddeeff00112233";
        final byte[] manifest = new String(envelope(digest, mask, 0x4502, true, false, "\n", -1, false), StandardCharsets.ISO_8859_1)
                .replace("tOkEn", "Hash").getBytes(StandardCharsets.ISO_8859_1);
        final byte[] key = ConfigCrypto.deriveKey(mask, manifest);
        final byte[] engine = envelope("[DFMPerfGearConfig]\nDFMQualityLevel=1\nDFMFPSLevel=2\n", key, 0x4502, true, false, "\n", -1, false);
        final byte[] game = "[Any]\nx=1\n".getBytes(StandardCharsets.UTF_8);
        OperationFailure error = failure(() -> ConfigPatcher.plan(engine, game, "Hash=broken".getBytes(StandardCharsets.US_ASCII), mask, 1, 2, 100, 1440));
        check(error.path.equals("UserGameplay.ini") && error.stage.contains("派生"), "manifest failure identified at key derivation stage");
        final byte[] badEngine = "Token=broken".getBytes(StandardCharsets.US_ASCII);
        error = failure(() -> ConfigPatcher.plan(badEngine, game, manifest, mask, 1, 2, 100, 1440));
        check(error.path.equals("Engine.ini") && error.stage.contains("解密"), "Engine decode failure located precisely");
        final byte[] duplicateEngine = envelope("[DFMPerfGearConfig]\nDFMFPSLevel=2\nDFMFPSLevel=3\n", key, 0x4502, true, false, "\n", -1, false);
        error = failure(() -> ConfigPatcher.plan(duplicateEngine, game, manifest, mask, 1, 2, 100, 1440));
        check(error.path.equals("Engine.ini") && error.stage.contains("更新") && error.getCause().getMessage().contains("字段重复"), "Engine update failure preserves field name");
        final byte[] invalidUtf8 = {(byte) 0xc3, (byte) 0x28};
        error = failure(() -> ConfigPatcher.plan(engine, invalidUtf8, manifest, mask, 1, 2, 100, 1440));
        check(error.path.equals("Game.ini") && error.stage.contains("UTF-8"), "invalid Game encoding located precisely");
        check(OperationFailure.format(error).contains("配置编码或格式"), "invalid UTF8 produces relevant advice");
        final byte[] duplicateGame = ("[" + ConfigPatcher.PAD_SECTION + "]\n[" + ConfigPatcher.PAD_SECTION + "]\n").getBytes(StandardCharsets.UTF_8);
        error = failure(() -> ConfigPatcher.plan(engine, duplicateGame, manifest, mask, 1, 2, 100, 1440));
        check(error.path.equals("Game.ini") && error.stage.contains("更新"), "Game field update failure located precisely");
        error = failure(() -> ConfigPatcher.plan(engine, new byte[0], manifest, mask, 1, 2, 100, 1440));
        check(error.path.equals("Game.ini") && error.stage.contains("大小"), "empty Game file identified before decrypting unrelated files");
        Arrays.fill(key, (byte) 0); Arrays.fill(mask, (byte) 0);
    }

    private static void realFixtureTests(Path zipPath, Path libPath, Path output) throws Exception {
        byte[] engine, game, gameplay;
        try (ZipFile zip = new ZipFile(zipPath.toFile())) {
            engine = read(zip, "1/Engine.ini"); game = read(zip, "1/Game.ini"); gameplay = read(zip, "1/UserGameplay.ini");
        }
        byte[] encrypted32 = new byte[32];
        try (RandomAccessFile library = new RandomAccessFile(libPath.toFile(), "r")) {
            library.seek(0x171e1b0); library.readFully(encrypted32, 0, 16);
            library.seek(0x17416f0); library.readFully(encrypted32, 16, 16);
        }
        byte[] mask = ConfigCrypto.decodeFixedMask(encrypted32);
        byte[] key = ConfigCrypto.deriveKey(mask, gameplay);
        String text = ConfigCrypto.decodeIni(engine, key);
        check(Arrays.equals(engine, ConfigCrypto.replaceIni(engine, text, key)), "real fixture exact authenticated roundtrip");
        byte[] gameplayCopy = gameplay.clone();
        for (int quality = 0; quality <= 5; quality++) {
            for (int fps : ConfigPatcher.FPS_VALUES) {
                for (int percent : new int[]{25, 75, 100}) {
                    ConfigPatcher.Plan plan = ConfigPatcher.plan(engine, game, gameplay, mask, quality, fps, percent, 1440);
                    String result = ConfigCrypto.decodeIni(plan.engine, key);
                    ConfigCompatibility.validate(result, plan.game);
                    check(true, "real fixture generated plan passes structure gate");
                    check(ConfigPatcher.getInt(result, "DFMPerfGearConfig", "DFMQualityLevel", -1) == quality, "requested quality retained");
                    check(ConfigPatcher.getInt(result, "DFMPerfGearConfig", "DFMFPSLevel", -1) == fps, "requested FPS retained");
                    check(ConfigPatcher.getInt(result, "QualityFPSSetting", "Unlimit", -1) == 1, "regular quality matrix override set");
                    check(ConfigPatcher.getInt(result, "SystemSettings", "PerfGear.SmallPadSize", -1) == 0, "small pad branch enabled");
                    if (fps >= 7) check(ConfigPatcher.getInt(result, "SystemSettings", "DFMDeviceFrame.White" + ConfigPatcher.fpsForInternal(fps) + "fps", -1) == 1, "selected FPS whitelist setting");
                    Map<String, String> before = fields(text), after = fields(result);
                    for (String field : new String[]{"[DFMPerfGearConfig]DFMQualityLevel", "[DFMPerfGearConfig]DFMFPSLevel", "[QualityFPSSetting]Unlimit", "[SystemSettings]PerfGear.SmallPadSize"}) { before.remove(field); after.remove(field); }
                    if (fps >= 7) { before.remove("[SystemSettings]DFMDeviceFrame.White" + ConfigPatcher.fpsForInternal(fps) + "fps"); after.remove("[SystemSettings]DFMDeviceFrame.White" + ConfigPatcher.fpsForInternal(fps) + "fps"); }
                    check(before.equals(after), "unrelated Engine values retained");
                    String gameText = new String(plan.game, StandardCharsets.UTF_8);
                    int target = percent == 100 ? 8192 : (int) Math.round(1440 * percent / 100.0);
                    check(plan.targetShortEdge == target, "short edge calculation");
                    check(occurrences(gameText, "[" + ConfigPatcher.PAD_SECTION + "]") == 1, "single target Game section");
                    check(occurrences(gameText, "BackBuffer=8192") == 15, "15 backbuffers retained native");
                    if (percent == 100) check(occurrences(gameText, "=8192") == 105, "105 native-resolution fields");
                    else check(occurrences(gameText, "=" + target) == 90, "90 scene fields use ratio");
                    check(gameText.contains("LastHotUpdateVersion=39"), "HotUpdateVersion untouched");
                    check(Arrays.equals(gameplay, gameplayCopy), "UserGameplay unmodified");
                    ConfigPatcher.Plan again = ConfigPatcher.plan(plan.engine, plan.game, gameplay, mask, quality, fps, percent, 1440);
                    check(Arrays.equals(plan.engine, again.engine) && Arrays.equals(plan.game, again.game), "patch idempotent");
                }
            }
        }
        ConfigPatcher.Plan nativePlan = ConfigPatcher.plan(engine, game, gameplay, mask, 5, 9, 100, 1440);
        ConfigPatcher.Plan reducedPlan = ConfigPatcher.plan(engine, game, gameplay, mask, 2, 8, 75, 1440);
        ConfigPatcher.Plan plan165 = ConfigPatcher.plan(engine, game, gameplay, mask, 4, 10, 100, 1440);
        ConfigPatcher.Plan plan185 = ConfigPatcher.plan(engine, game, gameplay, mask, 4, 11, 100, 1440);
        ConfigPatcher.Plan sequential165 = ConfigPatcher.plan(nativePlan.engine, nativePlan.game, gameplay, mask, 5, 10, 100, 1440);
        ConfigPatcher.Plan sequential185 = ConfigPatcher.plan(sequential165.engine, sequential165.game, gameplay, mask, 5, 11, 100, 1440);
        ConfigPatcher.Plan reset = ConfigPatcher.resetDefaults(sequential185.engine, sequential185.game, gameplay, mask);
        ConfigPatcher.Plan resetAgain = ConfigPatcher.resetDefaults(reset.engine, reset.game, gameplay, mask);
        check(Arrays.equals(reset.engine, resetAgain.engine) && Arrays.equals(reset.game, resetAgain.game), "real fixture reset is idempotent after sequential FPS changes");
        check(Arrays.equals(gameplay, gameplayCopy), "real reset leaves current-device UserGameplay unchanged");
        Files.createDirectories(output);
        Files.write(output.resolve("native-Engine.ini"), nativePlan.engine);
        Files.write(output.resolve("native-Game.ini"), nativePlan.game);
        Files.write(output.resolve("reduced-Engine.ini"), reducedPlan.engine);
        Files.write(output.resolve("reduced-Game.ini"), reducedPlan.game);
        Files.write(output.resolve("fps165-Engine.ini"), plan165.engine);
        Files.write(output.resolve("fps165-Game.ini"), plan165.game);
        Files.write(output.resolve("fps185-Engine.ini"), plan185.engine);
        Files.write(output.resolve("fps185-Game.ini"), plan185.game);
        Files.write(output.resolve("reset-Engine.ini"), reset.engine);
        Files.write(output.resolve("reset-Game.ini"), reset.game);
        Files.write(output.resolve("reset-source-Engine.ini"), sequential185.engine);
        Files.write(output.resolve("reset-source-Game.ini"), sequential185.game);
        byte[] prefixedGame = new byte[game.length + 3];
        prefixedGame[0] = (byte) 0xef; prefixedGame[1] = (byte) 0xbb; prefixedGame[2] = (byte) 0xbf;
        System.arraycopy(game, 0, prefixedGame, 3, game.length);
        ConfigPatcher.Plan bomPlan = ConfigPatcher.plan(engine, prefixedGame, gameplay, mask, 1, 2, 50, 1440);
        check((bomPlan.game[0] & 255) == 0xef && (bomPlan.game[1] & 255) == 0xbb && (bomPlan.game[2] & 255) == 0xbf, "Game BOM retained");
        byte[] duplicate = (new String(game, StandardCharsets.UTF_8) + "\n[" + ConfigPatcher.PAD_SECTION + "]\n[" + ConfigPatcher.PAD_SECTION + "]\n").getBytes(StandardCharsets.UTF_8);
        rejects(() -> ConfigPatcher.plan(engine, duplicate, gameplay, mask, 0, 2, 100, 1440), "duplicate target sections fail closed");
        rejects(() -> ConfigPatcher.plan(engine, game, gameplay, mask, 6, 2, 100, 1440), "unsupported quality refused");
        rejects(() -> ConfigPatcher.plan(engine, game, gameplay, mask, 0, 6, 100, 1440), "unverified FPS refused");
        rejects(() -> ConfigPatcher.plan(engine, game, gameplay, mask, 0, 2, 101, 1440), "oversized render percent refused");
        rejects(() -> ConfigPatcher.plan(engine, game, gameplay, mask, 0, 2, 24, 1440), "undersized render percent refused");
        rejects(() -> ConfigPatcher.plan(engine, game, gameplay, mask, 0, 2, 50, 0), "invalid screen size refused");
        check(ConfigPatcher.fpsForInternal(2) == 60 && ConfigPatcher.fpsForInternal(7) == 90 && ConfigPatcher.fpsForInternal(8) == 120 && ConfigPatcher.fpsForInternal(9) == 144 && ConfigPatcher.fpsForInternal(10) == 165 && ConfigPatcher.fpsForInternal(11) == 185, "verified FPS map");
        Arrays.fill(key, (byte) 0); Arrays.fill(mask, (byte) 0);
    }
    private static byte[] read(ZipFile zip, String name) throws Exception {
        java.io.InputStream input = zip.getInputStream(zip.getEntry(name));
        try {
            java.io.ByteArrayOutputStream output = new java.io.ByteArrayOutputStream();
            byte[] buffer = new byte[8192]; int read;
            while ((read = input.read(buffer)) >= 0) output.write(buffer, 0, read);
            return output.toByteArray();
        } finally { input.close(); }
    }
    public static void main(String[] args) throws Exception {
        syntheticTests();
        resetTests();
        diagnosticTests();
        userReportTests();
        if (args.length == 3) realFixtureTests(Paths.get(args[0]), Paths.get(args[1]), Paths.get(args[2]));
        else if (args.length != 0) throw new IllegalArgumentException("Supply no arguments, or fixture zip, library, temporary output directory");
        System.out.println("Core Java tests passed: " + assertions + " assertions; no keys or plaintext emitted.");
    }
}
