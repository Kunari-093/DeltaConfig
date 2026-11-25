import io.github.deltaconfig.GameTarget;
import java.util.HashSet;
import java.util.Set;

/** Distribution allowlist and deterministic first-launch/saved-choice selection. */
public final class GameTargetTests {
    private static int assertions;
    private interface Action { void run(); }
    private static void check(boolean value, String message) {
        assertions++; if (!value) throw new AssertionError(message);
    }
    private static void rejects(Action action, String message) {
        boolean rejected = false;
        try { action.run(); } catch (IllegalArgumentException expected) { rejected = true; }
        check(rejected, message);
    }
    public static void main(String[] args) {
        GameTarget[] targets = GameTarget.values();
        check(targets.length == 3, "exactly three distributions are supported");
        check(targets[0] == GameTarget.CN && targets[1] == GameTarget.GLOBAL && targets[2] == GameTarget.GARENA,
            "stable selection ordering");
        check("com.tencent.tmgp.dfm".equals(GameTarget.CN.packageName), "CN identity");
        check("com.proxima.dfm".equals(GameTarget.GLOBAL.packageName), "Level Infinite identity");
        check("com.garena.game.df".equals(GameTarget.GARENA.packageName), "Garena identity");
        check(!GameTarget.CN.international && GameTarget.GLOBAL.international && GameTarget.GARENA.international,
            "international validation status is explicit");
        Set<String> packages = new HashSet<String>();
        for (GameTarget target : targets) {
            check(packages.add(target.packageName), "unique package identity");
            check(target.label != null && !target.label.isEmpty(), "visible distribution label");
            check(GameTarget.lookup(target.packageName) == target, "exact allowlisted lookup");
        }
        for (String invalid : new String[]{null, "", "COM.PROXIMA.DFM", "com.proxima.dfm ",
                "com.proxima.dfm/../other", "com.other.game", "com.tencent.tmgp.dfm;id"})
            rejects(() -> GameTarget.lookup(invalid), "unknown or manipulated package cannot be selected");
        targets[0] = null;
        check(GameTarget.values()[0] == GameTarget.CN, "caller cannot mutate catalog ordering");
        targets = GameTarget.values();
        for (int state = 0; state < 8; state++) {
            boolean[] installed = new boolean[3];
            int count = 0, only = -1;
            for (int i = 0; i < installed.length; i++) if (installed[i] = (state & (1 << i)) != 0) {
                count++; only = i;
            }
            GameTarget expected = count == 1 ? targets[only] : GameTarget.CN;
            check(GameTarget.initialSelection(null, installed) == expected, "only one installed distribution is auto-selected");
            check(GameTarget.initialSelection("unknown.saved.package", installed) == expected,
                "obsolete preference cannot escape allowlist");
            for (GameTarget target : targets)
                check(GameTarget.initialSelection(target.packageName, installed) == target,
                    "saved choice remains selected even if not installed");
        }
        rejects(() -> GameTarget.initialSelection(null, null), "missing install state is rejected");
        rejects(() -> GameTarget.initialSelection(null, new boolean[2]), "truncated install state is rejected");
        System.out.println("Game target checks passed: " + assertions);
    }
}
