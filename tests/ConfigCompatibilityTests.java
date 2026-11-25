import io.github.deltaconfig.core.ConfigCompatibility;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;

/** Host-only compatibility checks. Default fixtures are synthetic and contain no game secrets. */
public final class ConfigCompatibilityTests {
    private static int assertions;
    private static final String ENGINE = "[Core.System]\n+Paths=first\n+Paths=second\n"
            + "[DFMPerfGearConfig]\nDFMQualityLevel=1\nDFMFPSLevel=8\n";
    private static final byte[] GAME = "[LuaFrontEnd]\nLastHotUpdateVersion=synthetic\n".getBytes(StandardCharsets.UTF_8);
    private interface Action { void run() throws Exception; }
    private static void check(boolean result, String message) {
        assertions++;
        if (!result) throw new AssertionError(message);
    }
    private static void pass(String engine, byte[] game, String message) throws Exception {
        ConfigCompatibility.validate(engine, game);
        check(true, message);
    }
    private static void reject(Action action, String message) throws Exception {
        boolean failed = false;
        try { action.run(); } catch (GeneralSecurityException | IllegalArgumentException ex) { failed = true; }
        catch (java.nio.charset.CharacterCodingException ex) { failed = true; }
        check(failed, message);
    }
    private static byte[] bytes(String text) { return text.getBytes(StandardCharsets.UTF_8); }
    private static String tuple() {
        StringBuilder text = new StringBuilder("(");
        for (int i = 1; i <= 5; i++) {
            if (i > 1) text.append(',');
            text.append("Level").append(i).append("Config=(BackBuffer=8192,UltraLowResolution=720,LowResolution=720,MidResolution=1080,HighResolution=1440,UltraHighResolution=2160,SuperResolution=2160)");
        }
        return text.append(')').toString();
    }
    public static void main(String[] args) throws Exception {
        pass(ENGINE, GAME, "minimal known structure and unrelated repeated arrays");
        for (int quality = 0; quality <= 5; quality++) for (int fps : new int[]{2, 7, 8, 9, 10, 11})
            pass(ENGINE.replace("DFMQualityLevel=1", "DFMQualityLevel=" + quality)
                    .replace("DFMFPSLevel=8", "DFMFPSLevel=" + fps), GAME, "known values accepted");
        pass(ENGINE.toLowerCase().replace("\n", "\r\n"), bytes("\ufeff[Other]\nName=中文\n"), "case, CRLF and UTF8 BOM supported");
        pass(ENGINE + "[QualityFPSSetting]\nUnlimit=true ; comment\n[SystemSettings]\nPerfGear.SmallPadSize=7.1\nDFMDeviceFrame.White144fps=1\n", GAME, "optional existing override fields");
        pass(ENGINE + "[Unrelated]\nSame=1\nSame=2\n[Unrelated]\nSame=3\n", GAME, "unrelated duplicates retained");
        final String group = tuple();
        final String section = "[/Script/PerfGear.PerfGearAndroidPadSizeConfig]\n";
        pass(ENGINE, bytes(section), "empty pad section allowed before overrides");
        pass(ENGINE, bytes(section + "SmallPadConfig=" + group + "\nMidPadConfig=" + group + "\nBigPadConfig=" + group + "\n"), "all three known serialized groups accepted");
        pass(ENGINE, bytes(section + "SmallPadConfig = " + group.replace(",", ", ").replace("=", " = ") + " ; comment\n"), "tuple whitespace and inline comment");
        reject(() -> ConfigCompatibility.validate(null, GAME), "null main refused");
        reject(() -> ConfigCompatibility.validate("not an ini", GAME), "non INI refused");
        reject(() -> ConfigCompatibility.validate(ENGINE + "\0", GAME), "control character refused");
        reject(() -> ConfigCompatibility.validate(ENGINE.replace("DFMQualityLevel=1\n", ""), GAME), "missing quality refused");
        reject(() -> ConfigCompatibility.validate(ENGINE.replace("DFMFPSLevel=8\n", ""), GAME), "missing frame refused");
        try { ConfigCompatibility.validate("[Other]\nValue=1\n", GAME); throw new AssertionError("missing defaults accepted"); }
        catch (GeneralSecurityException failure) { check(failure.getMessage().contains("启动游戏"), "regenerated defaults guidance"); }
        reject(() -> ConfigCompatibility.validate(ENGINE.replace("DFMQualityLevel=1", "DFMQualityLevel=6"), GAME), "unknown quality refused");
        reject(() -> ConfigCompatibility.validate(ENGINE.replace("DFMFPSLevel=8", "DFMFPSLevel=12"), GAME), "unknown FPS enum refused");
        reject(() -> ConfigCompatibility.validate(ENGINE.replace("DFMFPSLevel=8", "DFMFPSLevel=120"), GAME), "FPS text is not mistaken for enum");
        reject(() -> ConfigCompatibility.validate(ENGINE.replace("[DFMPerfGearConfig]", "[ DFMPerfGearConfig ]"), GAME), "padded target header cannot mismatch patcher");
        reject(() -> ConfigCompatibility.validate(ENGINE.replace("DFMFPSLevel=8", "DFMFPSLevel=8.0"), GAME), "changed numeric format refused");
        reject(() -> ConfigCompatibility.validate(ENGINE + "DFMFPSLevel=8\n", GAME), "duplicate FPS refused");
        reject(() -> ConfigCompatibility.validate(ENGINE + "dfmqualitylevel=1\n", GAME), "case duplicate quality refused");
        reject(() -> ConfigCompatibility.validate(ENGINE.replace("DFMFPSLevel", "+DFMFPSLevel"), GAME), "array operator target refused");
        reject(() -> ConfigCompatibility.validate(ENGINE + "[DFMPerfGearConfig]\n", GAME), "duplicate target section refused");
        reject(() -> ConfigCompatibility.validate(ENGINE + "[SystemSettings]\n[systemsettings]\n", GAME), "duplicate optional target section refused");
        reject(() -> ConfigCompatibility.validate(ENGINE + "[QualityFPSSetting]\nUnlimit=maybe\n", GAME), "changed optional boolean refused");
        reject(() -> ConfigCompatibility.validate(ENGINE + "[SystemSettings]\nPerfGear.SmallPadSize=-1\n", GAME), "invalid device size refused");
        reject(() -> ConfigCompatibility.validate(ENGINE, null), "null render INI refused");
        reject(() -> ConfigCompatibility.validate(ENGINE, new byte[0]), "empty render INI refused");
        reject(() -> ConfigCompatibility.validate(ENGINE, new byte[]{(byte)0xc3, 0x28}), "malformed UTF8 refused");
        reject(() -> ConfigCompatibility.validate(ENGINE, bytes("[Other]\nValue=ok\0\n")), "render NUL refused");
        reject(() -> ConfigCompatibility.validate(ENGINE, bytes("Token=encrypted\n")), "render requires INI section");
        reject(() -> ConfigCompatibility.validate(ENGINE, bytes(section + "SmallPadConfig=" + group + "\nsmallpadconfig=" + group)), "duplicate pad group refused");
        reject(() -> ConfigCompatibility.validate(ENGINE, bytes(section + "SmallPadConfig=" + group + "\n" + section)), "duplicate pad section refused");
        reject(() -> ConfigCompatibility.validate(ENGINE, bytes(section + "SmallPadConfig=" + group.replace("Level5Config", "Level6Config"))), "new level layout refused");
        reject(() -> ConfigCompatibility.validate(ENGINE, bytes(section + "SmallPadConfig=" + group.replace("Level5Config", "Level4Config"))), "duplicate level refused");
        reject(() -> ConfigCompatibility.validate(ENGINE, bytes(section + "SmallPadConfig=" + group.replace(",SuperResolution=2160", ""))), "missing resolution field refused");
        reject(() -> ConfigCompatibility.validate(ENGINE, bytes(section + "SmallPadConfig=" + group.replace("SuperResolution", "FutureResolution"))), "new resolution field refused");
        reject(() -> ConfigCompatibility.validate(ENGINE, bytes(section + "SmallPadConfig=" + group.replace("BackBuffer=8192", "BackBuffer=0"))), "zero render size refused");
        reject(() -> ConfigCompatibility.validate(ENGINE, bytes(section + "SmallPadConfig=" + group.replace("BackBuffer=8192", "BackBuffer=65536"))), "oversize render refused");
        reject(() -> ConfigCompatibility.validate(ENGINE, bytes(section + "SmallPadConfig=" + group + ",")), "trailing structure junk refused");
        reject(() -> ConfigCompatibility.validate(ENGINE, bytes(section + "SmallPadConfig=(Level1=example)\n")), "unrecognized tuple syntax refused");
        if (args.length == 2) {
            pass(new String(Files.readAllBytes(Paths.get(args[0])), StandardCharsets.UTF_8), Files.readAllBytes(Paths.get(args[1])), "explicit private plaintext compatibility fixture");
        } else if (args.length != 0) throw new IllegalArgumentException("Supply both explicit engine-plaintext and game INI paths, or no arguments.");
        System.out.println("Config compatibility checks passed: " + assertions);
    }
}
