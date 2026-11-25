package io.github.deltaconfig;

/** Explicitly supported distribution identities; selection never accepts arbitrary packages. */
public final class GameTarget {
    public static final GameTarget CN = new GameTarget("com.tencent.tmgp.dfm", "国服（腾讯）", false);
    public static final GameTarget GLOBAL = new GameTarget("com.proxima.dfm", "国际服（Level Infinite）", true);
    public static final GameTarget GARENA = new GameTarget("com.garena.game.df", "国际服（Garena）", true);
    private static final GameTarget[] TARGETS = {CN, GLOBAL, GARENA};

    public final String packageName, label;
    public final boolean international;

    private GameTarget(String packageName, String label, boolean international) {
        this.packageName = packageName; this.label = label; this.international = international;
    }

    public static GameTarget[] values() { return TARGETS.clone(); }

    public static GameTarget lookup(String packageName) {
        for (GameTarget target : TARGETS) if (target.packageName.equals(packageName)) return target;
        throw new IllegalArgumentException("未识别的游戏发行版；仅支持列表中的国服、Level Infinite 与 Garena 版本");
    }

    /** An explicit saved choice wins; first launch auto-selects only one installed distribution. */
    public static GameTarget initialSelection(String savedPackage, boolean[] installed) {
        if (installed == null || installed.length != TARGETS.length)
            throw new IllegalArgumentException("已安装发行版状态与支持列表不一致");
        if (savedPackage != null) {
            try { return lookup(savedPackage); }
            catch (IllegalArgumentException invalidPreference) { /* Ignore obsolete or corrupt local preferences. */ }
        }
        GameTarget only = null;
        for (int i = 0; i < TARGETS.length; i++) if (installed[i]) {
            if (only != null) return CN;
            only = TARGETS[i];
        }
        return only == null ? CN : only;
    }
}
