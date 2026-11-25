package io.github.deltaconfig;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.provider.Settings;
import io.github.deltaconfig.core.ConfigCrypto;
import io.github.deltaconfig.core.ConfigPatcher;
import io.github.deltaconfig.core.ConfigCompatibility;
import io.github.deltaconfig.core.LibraryMaskResolver;
import io.github.deltaconfig.core.OperationFailure;
import org.json.JSONObject;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Arrays;
import java.util.Locale;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/** Device-local configuration access. No configuration is sent elsewhere. */
public final class GameRepository {
    public static final String PACKAGE = "com.tencent.tmgp.dfm";
    public static final String BASELINE_VERSION = "1.201.37117.67";
    public static final int BASELINE_CODE = 2207;
    private static final String RELATIVE = "/UE4Game/DeltaForce/DeltaForce/Saved/Config/Android/";
    private static final String ROOT = "/data/adb/deltaconfig";
    private static final int LIMIT = 4 * 1024 * 1024;
    private static final long TIMEOUT = 120000;
    private static final int LIBRARY_READ_LIMIT = 1024 * 1024;
    private static final long LIBRARY_SIZE_LIMIT = 8L * 1024 * 1024 * 1024;
    private static final long APK_INFLATE_LIMIT = 1024L * 1024 * 1024;
    private final Context context;
    private final GameTarget target;
    private final String packageName;
    private final int userId;
    private final String base;
    // Public entry points are synchronized; these fields describe exactly one operation.
    private String operation = "读取配置", writeStatus = "未写入游戏配置", rollbackStatus = "无需回滚";
    private String backupPath;
    private boolean originalRestored;
    private RootShell.Access rootAccess;
    private volatile boolean rootAuthorized;

    public GameRepository(Context context) {
        this(context, PACKAGE);
    }

    public GameRepository(Context context, String packageName) {
        target = GameTarget.lookup(packageName);
        this.packageName = target.packageName;
        Context application = context.getApplicationContext();
        this.context = application == null ? context : application;
        userId = android.os.Process.myUid() / 100000;
        base = backupBase(packageName, userId);
    }

    public String getPackageName() { return packageName; }

    public static final class Snapshot {
        public final byte[] engine, game, gameplay, fixedMask;
        public final String packageName, versionName, enginePath, gamePath, gameplayPath, librarySource, rootAccessDescription, compatibilityDescription;
        public final long versionCode;
        private final String engineHash, gameHash, gameplayHash;
        private final int uid;
        private final Installation installation;
        private Snapshot(Paths paths, byte[] engine, byte[] game, byte[] gameplay,
                         byte[] mask, String library, String rootAccessDescription, String compatibilityDescription) throws Exception {
            this.engine = engine.clone(); this.game = game.clone(); this.gameplay = gameplay.clone();
            installation = paths.installation;
            packageName = installation.packageName;
            fixedMask = mask.clone(); versionName = installation.versionName; versionCode = installation.versionCode;
            enginePath = paths.engine; gamePath = paths.game; gameplayPath = paths.gameplay;
            librarySource = library; uid = paths.info.uid;
            this.rootAccessDescription = rootAccessDescription;
            this.compatibilityDescription = compatibilityDescription;
            engineHash = hash(engine); gameHash = hash(game); gameplayHash = hash(gameplay);
        }
    }

    public synchronized Snapshot load() throws Exception {
        begin("读取配置");
        try { requireRoot(); Paths paths = paths(); recover(paths); return capture(paths, true); }
        catch (Exception failure) { throw diagnosed(failure); }
    }

    /** Reports the last actual UID check; game-path visibility is a separate condition. */
    public boolean hasRootAuthorization() { return rootAuthorized; }

    /** Authorization-only action: no game paths, transaction recovery or filesystem writes. */
    public synchronized String checkRootAuthorization() throws Exception {
        begin("检查 root 授权");
        try {
            requireRoot();
            return "root 授权已确认（UID 0）；配置可读性将在读取时另行检查。";
        } catch (Exception failure) { throw diagnosed(failure); }
    }

    private Snapshot capture(Paths paths, boolean authenticateCurrentEngine) throws Exception {
        checkInstallation(paths, "读取配置前核对游戏安装身份");
        byte[] engine = read(paths.engine, LIMIT, "读取 Engine.ini 字节");
        byte[] game = read(paths.game, LIMIT, "读取 Game.ini 字节");
        byte[] gameplay = read(paths.gameplay, LIMIT, "读取 UserGameplay.ini 字节");
        Exception nativeFailure;
        String nativePath = paths.info.nativeLibraryDir + "/libUE4.so";
        try {
            ResolvedMask resolved = resolveNativeMask(paths, nativePath, gameplay, authenticateCurrentEngine ? engine : null);
            byte[] mask = resolved.mask;
            if (authenticateCurrentEngine) authenticate(mask, gameplay, engine, game, paths, "本机库认证");
            else verifyGameplay(mask, gameplay, paths.gameplay, "还原前验证当前设备 Hash 派生");
            if (authenticateCurrentEngine) validateCompatibility(mask, gameplay, engine, game, paths, "本机库配置结构兼容检查");
            checkInstallation(paths, "读取配置后核对游戏安装身份");
            return new Snapshot(paths, engine, game, gameplay, mask, nativePath, rootAccess.description(), resolved.description);
        } catch (Exception e) {
            if (stopLibraryFallback(e)) throw e;
            nativeFailure = e;
        }
        String apkLibrary = paths.info.sourceDir + "!lib/arm64-v8a/libUE4.so";
        try {
            ResolvedMask resolved = resolveApkMask(paths, gameplay, authenticateCurrentEngine ? engine : null);
            byte[] mask = resolved.mask;
            if (authenticateCurrentEngine) authenticate(mask, gameplay, engine, game, paths, "APK 库回退认证");
            else verifyGameplay(mask, gameplay, paths.gameplay, "APK 库回退验证当前设备 Hash 派生");
            if (authenticateCurrentEngine) validateCompatibility(mask, gameplay, engine, game, paths, "APK 库配置结构兼容检查");
            checkInstallation(paths, "APK 库读取后核对游戏安装身份");
            return new Snapshot(paths, engine, game, gameplay, mask, apkLibrary, rootAccess.description(), resolved.description);
        } catch (Exception e) {
            OperationFailure failure = problem("本机库与 APK 库两路读取/认证均失败", nativePath + "\n" + apkLibrary,
                    "两个库来源都未能完成配置认证；下方分别列出失败的文件与步骤", e);
            failure.addSuppressed(nativeFailure); throw failure;
        }
    }

    public synchronized String apply(Snapshot snapshot, byte[] newEngine, byte[] newGame) throws Exception {
        begin("修改配置");
        try {
            if (snapshot == null) throw problem("检查配置快照", null, "尚无配置快照，请先读取配置", null);
            if (newEngine == null || newGame == null || newEngine.length == 0 || newGame.length == 0
                    || newEngine.length > LIMIT || newGame.length > LIMIT)
                throw problem("检查待写入配置大小", snapshot.enginePath + "\n" + snapshot.gamePath,
                        "Engine.ini 或 Game.ini 为空，或超过 " + LIMIT + " 字节安全上限", null);
            requireRoot(); Paths paths = paths(); recover(paths); checkSnapshot(paths, snapshot);
            authenticate(snapshot.fixedMask, snapshot.gameplay, snapshot.engine, snapshot.game, paths, "验证原配置");
            authenticate(snapshot.fixedMask, snapshot.gameplay, newEngine, newGame, paths, "验证待写入配置");
            validateCompatibility(snapshot.fixedMask, snapshot.gameplay, snapshot.engine, snapshot.game, paths, "修改前核对原配置结构");
            validateCompatibility(snapshot.fixedMask, snapshot.gameplay, newEngine, newGame, paths, "修改前核对目标配置结构");
            return transact(paths, snapshot, newEngine.clone(), newGame.clone(), true);
        } catch (Exception failure) { throw diagnosed(failure); }
    }

    /** Remove this tool's override fields; the game determines its defaults on its next launch. */
    public synchronized String resetDefaults(Snapshot before) throws Exception {
        begin("重置为游戏默认配置");
        try {
            if (before == null) throw problem("检查重置前配置快照", null, "尚无配置快照，请先读取配置", null);
            requireRoot(); Paths paths = paths(); recover(paths); checkSnapshot(paths, before);
            authenticate(before.fixedMask, before.gameplay, before.engine, before.game, paths, "重置前验证当前配置");
            final ConfigPatcher.Plan plan;
            try { plan = ConfigPatcher.resetDefaults(before.engine, before.game, before.gameplay, before.fixedMask); }
            catch (Exception failure) { throw wrap("生成删除本工具覆盖项的配置", paths.engine + "\n" + paths.game, failure); }
            if (plan == null || plan.engine == null || plan.game == null || plan.engine.length == 0 || plan.game.length == 0
                    || plan.engine.length > LIMIT || plan.game.length > LIMIT)
                throw problem("检查默认配置重建方案大小", paths.engine + "\n" + paths.game,
                        "重置方案的 Engine.ini 或 Game.ini 为空，或超过 " + LIMIT + " 字节安全上限", null);
            authenticate(before.fixedMask, before.gameplay, plan.engine, plan.game, paths, "验证删除覆盖项后的待写入配置");
            if (Arrays.equals(before.engine, plan.engine) && Arrays.equals(before.game, plan.game)) {
                checkSnapshot(paths, before);
                return "当前配置无需删除本工具覆盖项，未写入游戏文件；默认档位仍由游戏自行决定。";
            }
            transact(paths, before, plan.engine.clone(), plan.game.clone(), true);
            return "已删除本工具的画质、帧率及渲染覆盖项，并通过回读认证；默认值由游戏下次启动时重建。"
                    + "\n本次重置前配置备份：" + backupPath;
        } catch (Exception failure) { throw diagnosed(failure); }
    }

    /** UserGameplay is never overwritten, including during restore. */
    public synchronized String restoreLatest() throws Exception {
        begin("还原配置");
        try {
            requireRoot(); Paths paths = paths(); recover(paths);
            // An invalid current Engine must not prevent restoring an authenticated original.
            Snapshot current = capture(paths, false);
            String id = pointer("latest");
            if (id == null) throw problem("查找最近成功备份", base + "/latest", "当前 Android 用户没有可恢复的备份索引", null);
            String directory = base + "/" + id;
            JSONObject manifest = manifest(id, paths);
            byte[] engine = read(directory + "/Engine.ini", LIMIT, "读取待恢复的 Engine.ini 备份");
            byte[] game = read(directory + "/Game.ini", LIMIT, "读取待恢复的 Game.ini 备份");
            byte[] gameplay = read(directory + "/UserGameplay.ini", LIMIT, "读取设备认证上下文备份");
            verifyBackup(manifest, engine, game, gameplay, directory);
            verifyContext(current.gameplay, manifest.getString("gameplayHash"), paths.gameplay, "核对备份设备认证上下文");
            authenticate(current.fixedMask, current.gameplay, engine, game, paths, "验证待恢复配置");
            transact(paths, current, engine, game, false);
            return "已恢复原配置；备份仍保留在 " + directory;
        } catch (Exception failure) { throw diagnosed(failure); }
    }

    public synchronized String latestBackupInfo() throws Exception {
        begin("查询备份位置");
        try { requireRoot(); paths(); String id = pointer("latest"); return id == null ? "尚无备份" : base + "/" + id; }
        catch (Exception failure) { throw diagnosed(failure); }
    }

    private String transact(Paths paths, Snapshot snapshot, byte[] engine, byte[] game,
                            boolean updateLatest) throws Exception {
        // The user controls the game lifecycle. Detect observable concurrent changes instead of stopping it.
        checkSnapshot(paths, snapshot);
        String id = new SimpleDateFormat("yyyyMMdd_HHmmss_SSS", Locale.US).format(new Date())
                + "-" + UUID.randomUUID().toString();
        String directory = base + "/" + id;
        ensureStorage();
        checked("创建原配置备份目录", directory, "umask 077; mkdir " + q(directory), null, 8192);
        backupPath = directory;
        Metadata engineMetadata = metadata(paths.engine, "备份前读取 Engine.ini 权限");
        Metadata gameMetadata = metadata(paths.game, "备份前读取 Game.ini 权限");
        JSONObject manifest = new JSONObject();
        manifest.put("format", 2).put("package", packageName).put("versionName", paths.installation.versionName)
                .put("versionCode", paths.installation.versionCode).put("lastUpdateTime", paths.installation.lastUpdateTime)
                .put("sourceDir", paths.installation.sourceDir).put("nativeLibraryDir", paths.installation.nativeLibraryDir)
                .put("userId", userId).put("uid", paths.info.uid)
                .put("device", deviceIdentity()).put("enginePath", paths.engine)
                .put("gamePath", paths.game).put("gameplayPath", paths.gameplay)
                .put("engineHash", snapshot.engineHash).put("gameHash", snapshot.gameHash)
                .put("gameplayHash", snapshot.gameplayHash).put("updateLatest", updateLatest)
                .put("engineMetadata", engineMetadata.json()).put("gameMetadata", gameMetadata.json());
        backupOne(paths.engine, directory + "/Engine.ini");
        backupOne(paths.game, directory + "/Game.ini");
        backupOne(paths.gameplay, directory + "/UserGameplay.ini");
        writeRoot(directory + "/manifest.json", manifest.toString().getBytes(StandardCharsets.UTF_8), "保存备份清单");
        verifyBackup(manifest, read(directory + "/Engine.ini", LIMIT, "回读 Engine.ini 原件备份"),
                read(directory + "/Game.ini", LIMIT, "回读 Game.ini 原件备份"),
                read(directory + "/UserGameplay.ini", LIMIT, "回读 UserGameplay.ini 原件备份"), directory);
        prepare(paths.engine, engine, engineMetadata, id);
        prepare(paths.game, game, gameMetadata, id);
        checkSnapshot(paths, snapshot);
        writeRoot(directory + "/state", "PREPARED\n".getBytes(StandardCharsets.US_ASCII), "保存准备完成事务状态");
        writePointer("pending", id);
        CommitBoundary commit = new CommitBoundary();
        // Once a rename is attempted, a channel failure cannot prove no write occurred.
        writeStatus = "已开始替换游戏配置，可能已部分写入";
        rollbackStatus = "失败时将尝试回滚";
        try {
            checkInstallation(paths, "提交前再次核对游戏安装身份");
            checked("替换 Engine.ini（重命名暂存文件）", paths.engine,
                    "mv -f " + q(temporary(paths.engine, id, ".new")) + " " + q(paths.engine), null, 8192);
            checkInstallation(paths, "替换 Game.ini 前核对游戏安装身份");
            checked("替换 Game.ini（重命名暂存文件）", paths.game,
                    "mv -f " + q(temporary(paths.game, id, ".new")) + " " + q(paths.game), null, 8192);
            checked("同步已写入配置到存储", paths.engine + "\n" + paths.game, "sync", null, 8192);
            byte[] writtenEngine = read(paths.engine, LIMIT, "写入后回读 Engine.ini");
            byte[] writtenGame = read(paths.game, LIMIT, "写入后回读 Game.ini");
            byte[] writtenGameplay = read(paths.gameplay, LIMIT, "写入后回读 UserGameplay.ini（确认未被改动）");
            checkInstallation(paths, "写入后核对游戏安装身份");
            verifyBytes(writtenEngine, hash(engine), paths.engine, "写入后校验 Engine.ini 字节");
            verifyBytes(writtenGame, hash(game), paths.game, "写入后校验 Game.ini 字节");
            verifyBytes(writtenGameplay, snapshot.gameplayHash, paths.gameplay, "写入后校验 UserGameplay.ini 未变化");
            authenticate(snapshot.fixedMask, writtenGameplay, writtenEngine, writtenGame, paths, "写入后认证回读配置");
            verifyMetadata(paths.engine, engineMetadata, "写入后验证 Engine.ini 权限");
            verifyMetadata(paths.game, gameMetadata, "写入后验证 Game.ini 权限");
            // Prepare and sync a separate marker while the journal still says PREPARED.
            // Never start rollback after attempting to publish COMMITTED: a transport
            // failure cannot prove whether mv already replaced the journal state.
            String statePath = directory + "/state";
            String committedMarker = statePath + ".commit-" + UUID.randomUUID().toString();
            writeRoot(committedMarker, "COMMITTED\n".getBytes(StandardCharsets.US_ASCII), "准备并同步已提交事务标记");
            commit.markerAttempted();
            checked("提交 COMMITTED 事务标记：重命名", statePath,
                    "mv -f " + q(committedMarker) + " " + q(statePath), null, 8192);
            commit.markerConfirmed();
            writeStatus = "配置已写入并校验通过；COMMITTED 标记已替换，等待存储同步";
            rollbackStatus = "未回滚：已发布提交标记";
            checked("提交 COMMITTED 事务标记：同步到存储", statePath, "sync", null, 8192);
            commit.markerSynced();
            writeStatus = "配置已写入并通过回读、认证及权限校验";
            rollbackStatus = "未回滚：配置提交已成功";
            if (updateLatest) writePointer("latest", id);
            checked("删除已完成事务的 pending 索引", base + "/pending", "rm -f " + q(base + "/pending"), null, 8192);
            cleanup(paths, id);
        } catch (Exception failure) {
            if (commit.canRollback()) {
                try { rollback(paths, id, manifest); }
                catch (Exception rollbackFailure) {
                    if (originalRestored) {
                        writeStatus = "原配置已恢复并校验通过；回滚记录或临时文件清理未完成";
                        rollbackStatus = "已还原游戏配置，但同步或收尾失败；请保留备份并查看具体失败步骤";
                    } else {
                        writeStatus = "配置可能部分写入；未能完成回滚";
                        rollbackStatus = "需要人工恢复；请勿启动游戏，请保留下面的原配置备份目录";
                    }
                    OperationFailure combined = problem("写入失败后的自动回滚", directory,
                            originalRestored ? "原配置已还原，但回滚收尾失败；原始失败与回滚失败均保留在下方"
                                    : "原始写入失败，自动回滚也失败；两个错误均保留在下方", failure);
                    combined.addSuppressed(rollbackFailure); throw combined;
                }
                writeStatus = "写入失败，原配置已恢复并校验通过";
                rollbackStatus = "自动回滚成功";
            } else if (!commit.isMarkerConfirmed()) {
                writeStatus = "配置已写入并校验通过；COMMITTED 标记重命名的结果尚未确认";
                rollbackStatus = "未自动回滚：提交标记可能已生效；pending 索引已保留，下次读取将按实际事务状态恢复或完成提交";
            } else if (!commit.isMarkerSynced()) {
                writeStatus = "配置已写入并校验通过；COMMITTED 标记已替换，但持久化同步未确认";
                rollbackStatus = "未回滚已发布的提交；pending 索引已保留，下次读取将按实际事务状态检查";
            } else {
                writeStatus = "配置已写入并校验通过；备份索引或临时文件清理失败";
                rollbackStatus = "未回滚：配置提交已成功；请按具体失败步骤检查备份索引或临时文件";
            }
            throw failure;
        }
        return "配置已写入并回读验证；原配置备份：" + directory;
    }

    private void backupOne(String source, String target) throws Exception {
        checked("复制原配置到备份（来源 → 目标）", source + "\n→ " + target,
                "umask 077; cp -p " + q(source) + " " + q(target), null, 8192);
        checked("设置备份文件所有者", target, "chown 0:0 " + q(target), null, 8192);
        checked("设置备份文件权限", target, "chmod 600 " + q(target), null, 8192);
    }

    private void prepare(String target, byte[] data, Metadata metadata, String id) throws Exception {
        regular(target, "准备替换文件：检查原配置");
        String old = temporary(target, id, ".old"), fresh = temporary(target, id, ".new");
        absent(old, "检查原件旁路副本路径"); absent(fresh, "检查新配置暂存路径");
        checked("创建原件旁路副本（来源 → 目标）", target + "\n→ " + old,
                "cp -p " + q(target) + " " + q(old), null, 8192);
        checked("创建新配置暂存文件（来源 → 目标）", target + "\n→ " + fresh,
                "cp -p " + q(target) + " " + q(fresh), null, 8192);
        setMetadata(old, metadata, "设置原件旁路副本权限");
        checked("写入新配置暂存字节", fresh, "cat > " + q(fresh), data, 8192);
        setMetadata(fresh, metadata, "设置新配置暂存文件权限");
        verifyBytes(read(fresh, LIMIT, "回读新配置暂存字节"), hash(data), fresh, "校验新配置暂存文件字节");
    }

    private void recover(Paths paths) throws Exception {
        String id = pointer("pending"); if (id == null) return;
        String directory = base + "/" + id;
        backupPath = directory;
        writeStatus = "发现未完成事务，游戏配置可能已部分写入";
        rollbackStatus = "正在检查上一次事务状态";
        JSONObject manifest = manifest(id, paths);
        String statePath = directory + "/state";
        String state = new String(read(statePath, 128, "读取未完成事务状态"), StandardCharsets.US_ASCII).trim();
        if ("COMMITTED".equals(state)) {
            writeStatus = "上次配置已提交；备份索引和临时文件清理尚未全部完成";
            rollbackStatus = "无需回滚已提交配置";
            if (restoreLatestFlag(manifest, directory)) writePointer("latest", id);
            checked("恢复事务：删除已提交 pending 索引", base + "/pending", "rm -f " + q(base + "/pending"), null, 8192);
            cleanup(paths, id);
            writeStatus = "已完成上次已提交配置的索引和清理；本次尚未写入新配置";
        } else if ("PREPARED".equals(state) || "ROLLED_BACK".equals(state)) {
            rollbackStatus = "尚未开始回滚，正在核对原件备份与当前认证上下文";
            try { rollback(paths, id, manifest); }
            catch (Exception failure) {
                if (originalRestored) {
                    writeStatus = "原配置已恢复并校验通过；事务恢复收尾未完成";
                    rollbackStatus = "游戏配置已还原，回滚记录或临时文件清理失败";
                } else {
                    writeStatus = "上次配置可能部分写入，自动恢复失败";
                    rollbackStatus = "回滚未完成，需要人工恢复；请保留原配置备份，不要启动游戏";
                }
                throw failure;
            }
            writeStatus = "本次读取前已自动恢复原配置，并通过回读校验";
            rollbackStatus = "未完成事务已成功回滚";
        } else throw problem("识别未完成事务状态", statePath,
                "事务状态不是 PREPARED、COMMITTED 或 ROLLED_BACK，为保护原件已停止操作", null);
    }

    private void rollback(Paths paths, String id, JSONObject manifest) throws Exception {
        String directory = base + "/" + id;
        originalRestored = false; rollbackStatus = "正在从原件备份回滚";
        byte[] engine = read(directory + "/Engine.ini", LIMIT, "回滚：读取 Engine.ini 原件备份");
        byte[] game = read(directory + "/Game.ini", LIMIT, "回滚：读取 Game.ini 原件备份");
        byte[] gameplay = read(directory + "/UserGameplay.ini", LIMIT, "回滚：读取认证上下文备份");
        verifyBackup(manifest, engine, game, gameplay, directory);
        // Never restore an Engine encrypted for a previous device context.
        verifyContext(read(paths.gameplay, LIMIT, "回滚：读取当前 UserGameplay.ini"),
                manifest.getString("gameplayHash"), paths.gameplay, "回滚：核对设备认证上下文");
        checkInstallation(paths, "回滚前核对游戏安装身份");
        restoreOne(paths, paths.engine, engine, backupMetadata(manifest, "engineMetadata", directory), id);
        restoreOne(paths, paths.game, game, backupMetadata(manifest, "gameMetadata", directory), id);
        checkInstallation(paths, "回滚后核对游戏安装身份");
        verifyBytes(read(paths.engine, LIMIT, "回滚后回读 Engine.ini"), manifest.getString("engineHash"), paths.engine, "回滚后校验 Engine.ini 字节");
        verifyBytes(read(paths.game, LIMIT, "回滚后回读 Game.ini"), manifest.getString("gameHash"), paths.game, "回滚后校验 Game.ini 字节");
        originalRestored = true;
        writeStatus = "原配置已恢复并校验通过";
        rollbackStatus = "游戏配置已还原，正在保存回滚状态并清理临时文件";
        writeRoot(directory + "/state", "ROLLED_BACK\n".getBytes(StandardCharsets.US_ASCII), "保存已回滚事务状态");
        checked("回滚：同步还原配置到存储", paths.engine + "\n" + paths.game, "sync", null, 8192);
        checked("回滚：删除 pending 索引", base + "/pending", "rm -f " + q(base + "/pending"), null, 8192);
        cleanup(paths, id); rollbackStatus = "原配置回滚及收尾均已完成";
    }

    private Metadata backupMetadata(JSONObject manifest, String field, String directory) throws Exception {
        try { return Metadata.from(manifest.getJSONObject(field)); }
        catch (Exception failure) { throw problem("解析备份清单中的 " + field + " 权限记录", directory + "/manifest.json",
                "备份权限记录缺失或 UID/GID/权限/SELinux 标签格式无效", failure); }
    }

    private boolean restoreLatestFlag(JSONObject manifest, String directory) throws Exception {
        try { return manifest.getBoolean("updateLatest"); }
        catch (Exception failure) { throw wrap("读取备份清单的 updateLatest 恢复标记", directory + "/manifest.json", failure); }
    }

    private void restoreOne(Paths paths, String target, byte[] data, Metadata metadata, String id) throws Exception {
        regular(target, "回滚：检查目标原配置");
        String temp = temporary(target, id, ".rollback");
        noLink(temp, "回滚：检查暂存文件路径");
        checked("回滚：创建暂存副本（来源 → 目标）", target + "\n→ " + temp,
                "cp -p " + q(target) + " " + q(temp), null, 8192);
        checked("回滚：写入原配置暂存字节", temp, "cat > " + q(temp), data, 8192);
        setMetadata(temp, metadata, "回滚：设置暂存文件权限");
        verifyBytes(read(temp, LIMIT, "回滚：回读暂存字节"), hash(data), temp, "回滚：校验暂存文件字节");
        checkInstallation(paths, "回滚：替换原配置前再次核对游戏安装身份");
        checked("回滚：替换目标文件", target, "mv -f " + q(temp) + " " + q(target), null, 8192);
        verifyMetadata(target, metadata, "回滚：验证还原文件权限");
    }

    private void cleanup(Paths paths, String id) throws Exception {
        for (String target : new String[]{paths.engine, paths.game}) {
            for (String suffix : new String[]{".new", ".old", ".rollback"}) {
                String path = temporary(target, id, suffix);
                checked("清理事务临时文件", path, "rm -f " + q(path), null, 8192);
            }
        }
    }

    private JSONObject manifest(String id, Paths paths) throws Exception {
        String path = base + "/" + id + "/manifest.json";
        try {
            JSONObject json = new JSONObject(new String(read(path, 32768, "读取备份清单"), StandardCharsets.UTF_8));
            int format = json.getInt("format");
            if ((format != 1 && format != 2) || !packageName.equals(json.getString("package"))
                    || !sameGameVersion(paths.installation.versionName, paths.installation.versionCode,
                            json.getString("versionName"), json.getLong("versionCode"))
                    || (format == 2 && (json.getLong("lastUpdateTime") != paths.installation.lastUpdateTime
                            || !paths.installation.sourceDir.equals(json.getString("sourceDir"))
                            || !paths.installation.nativeLibraryDir.equals(json.getString("nativeLibraryDir"))))
                    || json.getInt("userId") != userId
                    || json.getInt("uid") != paths.info.uid || !deviceIdentity().equals(json.getString("device"))
                    || !paths.engine.equals(json.getString("enginePath"))
                    || !paths.game.equals(json.getString("gamePath"))
                    || !paths.gameplay.equals(json.getString("gameplayPath")))
                throw problem("核对备份清单与当前环境", path, "备份的设备标识、Android 用户、游戏版本、UID 或文件路径与当前环境不匹配", null);
            return json;
        } catch (Exception failure) { throw wrap("读取并核对备份清单", path, failure); }
    }

    private void verifyBackup(JSONObject manifest, byte[] engine, byte[] game, byte[] gameplay, String directory) throws Exception {
        try {
            verifyBytes(engine, manifest.getString("engineHash"), directory + "/Engine.ini", "校验 Engine.ini 原件备份");
            verifyBytes(game, manifest.getString("gameHash"), directory + "/Game.ini", "校验 Game.ini 原件备份");
            verifyBytes(gameplay, manifest.getString("gameplayHash"), directory + "/UserGameplay.ini", "校验 UserGameplay.ini 原件备份");
        } catch (Exception failure) { throw wrap("校验备份清单记录的文件摘要", directory + "/manifest.json", failure); }
    }

    private void verifyBytes(byte[] data, String expectedHash, String path, String stage) throws Exception {
        if (!hash(data).equals(expectedHash)) throw problem(stage, path,
                "文件内容与预期的 SHA-256 摘要不一致；文件可能被改动、写入不完整或备份损坏", null);
    }

    private static void verifyGameplayContext(byte[] currentGameplay, String expectedHash) throws Exception {
        if (!hash(currentGameplay).equals(expectedHash))
            throw new IOException("UserGameplay 已变化，旧备份的认证上下文不再匹配；已停止恢复并保留事务记录及原件");
    }

    private void verifyContext(byte[] currentGameplay, String expectedHash, String path, String stage) throws Exception {
        try { verifyGameplayContext(currentGameplay, expectedHash); }
        catch (Exception failure) { throw wrap(stage, path, failure); }
    }

    private void checkSnapshot(Paths paths, Snapshot snapshot) throws Exception {
        try { verifySnapshotTarget(packageName, snapshot.packageName); }
        catch (Exception failure) { throw wrap("核对读取快照的游戏目标", "package:" + packageName, failure); }
        if (!snapshot.installation.equals(paths.installation))
            throw problem("核对读取快照的游戏版本与安装身份", "package:" + packageName,
                    "游戏版本或安装来源自读取后发生变化；请重新读取，新版本不会复用旧配置快照", null);
        checkInstallation(paths, "提交配置前核对游戏未升级或重新安装");
        if (rootAccess == null || !rootAccess.description().equals(snapshot.rootAccessDescription))
            throw problem("核对读取快照的 root 访问上下文", paths.engine,
                    "读取快照与当前操作的 root 路径或挂载命名空间不一致；为避免在不同上下文写入，请重新读取配置", null);
        if (snapshot.uid != paths.info.uid || !snapshot.enginePath.equals(paths.engine)
                || !snapshot.gamePath.equals(paths.game) || !snapshot.gameplayPath.equals(paths.gameplay))
            throw problem("核对读取快照的用户与路径", paths.engine + "\n" + paths.game + "\n" + paths.gameplay,
                    "当前应用 UID 或配置路径与读取快照不一致，请重新读取", null);
        verifyBytes(snapshot.engine, snapshot.engineHash, snapshot.enginePath, "核对内存 Engine.ini 快照未变化");
        verifyBytes(snapshot.game, snapshot.gameHash, snapshot.gamePath, "核对内存 Game.ini 快照未变化");
        verifyBytes(snapshot.gameplay, snapshot.gameplayHash, snapshot.gameplayPath, "核对内存 UserGameplay.ini 快照未变化");
        verifyBytes(read(paths.engine, LIMIT, "重新读取 Engine.ini 检查并发变化"), snapshot.engineHash, paths.engine, "核对 Engine.ini 自读取后未变化");
        verifyBytes(read(paths.game, LIMIT, "重新读取 Game.ini 检查并发变化"), snapshot.gameHash, paths.game, "核对 Game.ini 自读取后未变化");
        verifyBytes(read(paths.gameplay, LIMIT, "重新读取 UserGameplay.ini 检查并发变化"), snapshot.gameplayHash, paths.gameplay, "核对 UserGameplay.ini 自读取后未变化");
    }

    private static void verifySnapshotTarget(String expectedPackage, String snapshotPackage) throws IOException {
        GameTarget.lookup(expectedPackage);
        if (!expectedPackage.equals(snapshotPackage))
            throw new IOException("读取快照属于其他游戏目标；国服与国际服配置不能交叉写入，请重新读取当前目标配置");
    }

    private static void verifyInstalledTarget(String expectedPackage, String installedPackage, String applicationPackage)
            throws IOException {
        GameTarget.lookup(expectedPackage);
        if (!expectedPackage.equals(installedPackage) || !expectedPackage.equals(applicationPackage))
            throw new IOException("查询到的游戏包名与当前所选目标不匹配，已停止读取");
    }

    private static String backupBase(String selectedPackage, int user) {
        GameTarget.lookup(selectedPackage);
        if (user < 0) throw new IllegalArgumentException("Android 用户编号无效");
        return ROOT + "/backups/" + (PACKAGE.equals(selectedPackage) ? "" : selectedPackage + "/") + user;
    }

    private static String[] backupDirectories(String selectedPackage, int user) {
        String backup = backupBase(selectedPackage, user);
        return PACKAGE.equals(selectedPackage)
                ? new String[]{ROOT, ROOT + "/backups", backup}
                : new String[]{ROOT, ROOT + "/backups", ROOT + "/backups/" + selectedPackage, backup};
    }

    private static String privateConfigDirectory(String selectedPackage, String dataDir) throws IOException {
        GameTarget.lookup(selectedPackage);
        if (dataDir == null || !dataDir.startsWith("/") || dataDir.indexOf('\0') >= 0)
            throw new IOException("所选游戏的应用私有目录无效");
        return dataDir + "/files" + RELATIVE;
    }

    private static String gameplayPath(String selectedPackage, int user, boolean rawMedia) {
        GameTarget.lookup(selectedPackage);
        if (user < 0) throw new IllegalArgumentException("Android 用户编号无效");
        return (rawMedia ? "/data/media/" : "/storage/emulated/") + user + "/Android/data/"
                + selectedPackage + "/files" + RELATIVE + "UserGameplay.ini";
    }

    private Paths paths() throws Exception {
        final PackageInfo pkg;
        try { pkg = context.getPackageManager().getPackageInfo(packageName, 0); }
        catch (PackageManager.NameNotFoundException failure) {
            throw problem("查询已安装游戏", "package:" + packageName,
                    "当前 Android 用户未安装所选的" + target.label + "（" + packageName
                            + "），或系统未向本应用提供该包信息；请安装并启动所选游戏生成配置", failure);
        } catch (Exception failure) { throw wrap("查询已安装游戏信息", "package:" + packageName, failure); }
        ApplicationInfo info = pkg.applicationInfo;
        if (info == null || info.uid / 100000 != userId)
            throw problem("核对游戏所属 Android 用户", "package:" + packageName,
                    "当前工具用户：" + userId + "；游戏用户：" + (info == null ? "未知（缺少 ApplicationInfo）" : info.uid / 100000)
                            + "；拒绝跨用户读取", null);
        final Installation installation;
        try { installation = Installation.from(pkg, packageName); }
        catch (Exception failure) { throw wrap("读取实际游戏版本与安装身份", "package:" + packageName, failure); }
        String directory = privateConfigDirectory(packageName, info.dataDir);
        try { rootAccess = RootShell.selectForFile(directory + "Engine.ini", TIMEOUT); }
        catch (RootShell.SelectionFailure failure) {
            OperationFailure wrapped = problem("选择 root 访问上下文：逐路验证 Engine.ini 可见性", directory + "Engine.ini",
                    failure.getMessage(), failure);
            if (failure.exitCode != null) wrapped.exitCode(failure.exitCode);
            throw wrapped;
        } catch (InterruptedException failure) {
            Thread.currentThread().interrupt(); throw problem("选择 root 访问上下文：等待探测", directory + "Engine.ini",
                    "root 上下文探测被中断，尚未写入游戏配置", failure);
        } catch (Exception failure) { throw wrap("选择 root 访问上下文", directory + "Engine.ini", failure); }
        ensureStorage();
        String engine = canonical(directory + "Engine.ini"), game = canonical(directory + "Game.ini");
        String external = gameplayPath(packageName, userId, false);
        String media = gameplayPath(packageName, userId, true);
        String gameplay;
        try { gameplay = canonical(external); }
        catch (Exception first) {
            try { gameplay = canonical(media); }
            catch (Exception second) {
                OperationFailure failure = problem("定位 UserGameplay.ini 的两条外部存储路径", external + "\n" + media,
                        "外部存储路径与底层 media 路径均不可用；请先启动游戏生成配置，并检查存储挂载与 root 访问权限", second);
                failure.addSuppressed(first); throw failure;
            }
        }
        return new Paths(info, installation, engine, game, gameplay);
    }

    private String canonical(String path) throws Exception {
        regular(path, "定位配置：检查原始路径");
        String resolved = checked("解析配置真实路径", path, "readlink -f " + q(path), null, 8192).text().trim();
        if (!resolved.startsWith("/") || resolved.indexOf('\n') >= 0 || resolved.indexOf('\r') >= 0)
            throw problem("检查规范化后的配置路径", path, "readlink 未返回一个完整且唯一的绝对路径", null);
        regular(resolved, "定位配置：检查解析后路径"); return resolved;
    }

    private void regular(String path, String stage) throws Exception {
        checked(stage, path,
                "if [ -L " + q(path) + " ]; then echo '拒绝符号链接' >&2; exit 47; fi; "
                + "if [ ! -e " + q(path) + " ]; then echo '文件不存在或在当前 root 命名空间不可见' >&2; exit 44; fi; "
                + "if [ ! -f " + q(path) + " ]; then echo '路径不是普通文件' >&2; exit 45; fi; "
                + "if [ ! -r " + q(path) + " ]; then echo '文件不可读' >&2; exit 46; fi", null, 8192);
    }

    private void noLink(String path, String stage) throws Exception {
        checked(stage, path, "if [ -L " + q(path) + " ]; then echo '拒绝符号链接' >&2; exit 47; fi", null, 8192);
    }

    private void absent(String path, String stage) throws Exception {
        noLink(path, stage);
        checked(stage, path, "if [ -e " + q(path) + " ]; then echo '临时目标已存在，拒绝覆盖' >&2; exit 48; fi", null, 8192);
    }

    private byte[] read(String path, int maximum, String stage) throws Exception {
        regular(path, stage + "：检查文件");
        return checked(stage + "：读取字节", path, "cat " + q(path), null, maximum).stdout;
    }

    private ResolvedMask resolveNativeMask(Paths paths, final String path, byte[] gameplay, byte[] engine) throws Exception {
        regular(path, "本机库：检查 libUE4.so");
        final long length;
        try {
            length = Long.parseLong(checked("本机库：读取 ELF 文件长度", path,
                    "stat -c %s " + q(path), null, 8192).text().trim());
            validateLibraryLength(length);
        } catch (Exception failure) { throw wrap("本机库：验证库长度", path, failure); }
        LibraryMaskResolver.Source source = new LibraryMaskResolver.Source() {
            @Override public long length() { return length; }
            @Override public boolean efficientRandomAccess() { return true; }
            @Override public byte[] read(long offset, int count) throws Exception {
                validateLibraryRange(length, offset, count);
                if (count == 0) return new byte[0];
                final int block = 65536;
                long start = offset / block, inside = offset % block;
                long blocks = (inside + count + block - 1) / block;
                int capacity = (int) (blocks * block);
                byte[] data = checked("本机库：按范围读取 ELF 兼容性材料", path,
                        "dd if=" + q(path) + " bs=" + block + " skip=" + start + " count=" + blocks,
                        null, capacity).stdout;
                if (inside + count > data.length) throw new IOException("游戏库范围读取被截断");
                return Arrays.copyOfRange(data, (int) inside, (int) inside + count);
            }
        };
        try { return resolveMask(paths, source, path, gameplay, engine); }
        catch (Exception failure) { throw wrap("本机库：ELF ARM64 兼容识别与配置认证", path, failure); }
    }

    private ResolvedMask resolveApkMask(Paths paths, byte[] gameplay, byte[] engine) throws Exception {
        final String apkPath = paths.info.sourceDir;
        final ZipFile zip;
        try { zip = new ZipFile(apkPath); }
        catch (Exception failure) { throw wrap("APK 库回退：打开游戏 APK", apkPath, failure); }
        String entryPath = apkPath + "!lib/arm64-v8a/libUE4.so";
        try (ZipFile closeZip = zip) {
            ZipEntry entry = zip.getEntry("lib/arm64-v8a/libUE4.so");
            if (entry == null) throw problem("APK 库回退：定位 ARM64 库条目", entryPath,
                    "APK 内没有 lib/arm64-v8a/libUE4.so；需要 ARM64 ELF 库才能检查当前配置兼容性", null);
            try (ZipLibrarySource source = new ZipLibrarySource(zip, entry)) {
                return resolveMask(paths, source, entryPath + ":" + entry.getCrc(), gameplay, engine);
            }
        } catch (Exception failure) { throw wrap("APK 库回退：ELF ARM64 兼容识别与配置认证", entryPath, failure); }
    }

    private ResolvedMask resolveMask(Paths paths, LibraryMaskResolver.Source source, String sourceIdentity,
                                     byte[] gameplay, byte[] engine) throws Exception {
        validateArm64Header(source.read(0, 64), source.length());
        String prefix = hash((paths.installation.cacheIdentity() + "|" + sourceIdentity + "|" + source.length())
                .getBytes(StandardCharsets.UTF_8));
        android.content.SharedPreferences cache = null;
        try { cache = context.getSharedPreferences("verified-library-offsets", Context.MODE_PRIVATE); }
        catch (Exception ignored) { /* A cache is optional; authentication is not. */ }
        if (cache != null) {
            try {
                long first = cache.getLong(prefix + ".a", -1), second = cache.getLong(prefix + ".b", -1);
                if (first >= 0 && second >= 0) {
                    byte[] candidate = new byte[32];
                    System.arraycopy(source.read(first, 16), 0, candidate, 0, 16);
                    System.arraycopy(source.read(second, 16), 0, candidate, 16, 16);
                    CachedMaterial found = null;
                    int preferred = cache.getInt(prefix + ".e", -1);
                    try {
                        found = authenticateCachedMask(candidate, gameplay, engine, preferred);
                        if (found != null) {
                            if (engine != null && found.encoding != preferred) {
                                try { cache.edit().putInt(prefix + ".e", found.encoding).apply(); }
                                catch (Exception ignored) { /* An encoding hint never replaces authentication. */ }
                            }
                            return new ResolvedMask(found.mask,
                                    engine == null ? "已验证偏移缓存；当前 Hash 认证通过" : "已验证偏移缓存；Hash 与 Engine HMAC 均通过");
                        }
                    } finally {
                        Arrays.fill(candidate, (byte) 0);
                        if (found != null) Arrays.fill(found.mask, (byte) 0);
                    }
                }
            } catch (ConfigCrypto.MaterialAuthenticationBudgetException limit) { throw limit; }
            catch (ConfigCrypto.AuthenticatedFormatException unsupported) { throw unsupported; }
            catch (Exception ignored) { /* A stale offset must fall back to bounded discovery. */ }
        }
        LibraryMaskResolver.Result result = LibraryMaskResolver.resolve(source, gameplay, engine);
        if (cache != null && engine != null) {
            try { cache.edit().putLong(prefix + ".a", result.firstOffset).putLong(prefix + ".b", result.secondOffset)
                    .putInt(prefix + ".e", result.materialEncoding).apply(); }
            catch (Exception ignored) { /* Keep the authenticated read usable if a cache cannot be saved. */ }
        }
        try { return new ResolvedMask(result.mask, result.description); }
        finally { Arrays.fill(result.mask, (byte) 0); }
    }

    private static final class CachedMaterial {
        final byte[] mask;
        final int encoding;
        CachedMaterial(byte[] mask, int encoding) { this.mask = mask.clone(); this.encoding = encoding; }
    }

    private static boolean stopLibraryFallback(Throwable failure) {
        for (int depth = 0; failure != null && depth < 96; depth++, failure = failure.getCause())
            if (failure instanceof ConfigCrypto.AuthenticatedFormatException
                    || failure instanceof ConfigCrypto.MaterialAuthenticationBudgetException) return true;
        return false;
    }

    private static CachedMaterial authenticateCachedMask(byte[] stored, byte[] gameplay, byte[] engine, int preferred)
            throws ConfigCrypto.MaterialAuthenticationBudgetException, ConfigCrypto.AuthenticatedFormatException {
        if (stored == null || stored.length != 32) return null;
        byte[] hashToken = ConfigCrypto.getField(gameplay, "Hash");
        long candidateCost = hashToken.length;
        long remaining = ConfigCrypto.MAX_MATERIAL_AUTH_BYTES;
        int[] encodings = ConfigCrypto.materialEncodingCandidates();
        try {
            for (int at = -1; at < encodings.length; at++) {
                int transform = at < 0 ? preferred : encodings[at];
                if (transform < 0 || transform > 255 || (at >= 0 && transform == preferred)) continue;
                if (candidateCost > remaining) throw new ConfigCrypto.MaterialAuthenticationBudgetException(
                        "认证材料编码探测超过 64 MiB 校验预算；已停止读取并保留原配置");
                remaining -= candidateCost;
                byte[] decoded = stored.clone();
                for (int i = 0; i < decoded.length; i++) decoded[i] ^= (byte) transform;
                try {
                    if (candidateMatches(decoded, hashToken, engine)) return new CachedMaterial(decoded, transform);
                } finally { Arrays.fill(decoded, (byte) 0); }
            }
            return null;
        } finally { Arrays.fill(hashToken, (byte) 0); }
    }

    private static boolean candidateMatches(byte[] material, byte[] hashToken, byte[] engine)
            throws ConfigCrypto.AuthenticatedFormatException {
        byte[] key = null;
        try {
            key = ConfigCrypto.deriveKeyFromHash(material, hashToken);
            if (engine != null) ConfigCrypto.decodeIni(engine, key);
            return true;
        } catch (ConfigCrypto.AuthenticatedFormatException unsupported) { throw unsupported; }
        catch (Exception mismatch) { return false; }
        finally { if (key != null) Arrays.fill(key, (byte) 0); }
    }

    private static void validateLibraryLength(long length) throws IOException {
        if (length < 64 || length > LIBRARY_SIZE_LIMIT)
            throw new IOException("游戏库长度不在 ELF 兼容检测范围内");
    }

    private static void validateArm64Header(byte[] header, long length) throws IOException {
        validateLibraryLength(length);
        if (header == null || header.length != 64 || header[0] != 0x7f || header[1] != 'E'
                || header[2] != 'L' || header[3] != 'F' || header[4] != 2 || header[5] != 1 || header[6] != 1
                || (header[16] & 255) != 3 || header[17] != 0 || (header[18] & 255) != 183 || header[19] != 0
                || (header[52] & 255) != 64 || header[53] != 0)
            throw new IOException("游戏库不是支持的 ELF64 小端 ARM64 共享库；已停止配置操作");
    }

    private static void validateLibraryRange(long size, long offset, int count) throws IOException {
        validateLibraryLength(size);
        if (offset < 0 || count < 0 || count > LIBRARY_READ_LIMIT || offset > size || count > size - offset)
            throw new IOException("ELF 读取范围越界或单次读取超过 1 MiB");
    }

    private static final class ResolvedMask {
        final byte[] mask;
        final String description;
        ResolvedMask(byte[] mask, String description) { this.mask = mask.clone(); this.description = description; }
    }

    /** A single monotonic stream for scans, reopening only when seeking backwards. No full-library copy. */
    private static final class ZipLibrarySource implements LibraryMaskResolver.Source, AutoCloseable {
        private final ZipFile zip;
        private final ZipEntry entry;
        private InputStream stream;
        private long position, inflated;
        ZipLibrarySource(ZipFile zip, ZipEntry entry) throws Exception {
            this.zip = zip; this.entry = entry;
            validateLibraryLength(entry.getSize());
            if (entry.getMethod() != ZipEntry.STORED && entry.getMethod() != ZipEntry.DEFLATED)
                throw new IOException("APK 游戏库压缩方法不受支持");
        }
        @Override public long length() { return entry.getSize(); }
        @Override public byte[] read(long offset, int count) throws Exception {
            validateLibraryRange(length(), offset, count);
            if (stream == null || offset < position) {
                if (stream != null) stream.close();
                stream = zip.getInputStream(entry); position = 0;
            }
            long distance = offset - position;
            if (entry.getMethod() == ZipEntry.DEFLATED) consumeBudget(distance);
            while (position < offset) {
                long skipped = stream.skip(offset - position);
                if (skipped > 0) position += skipped;
                else if (stream.read() >= 0) position++;
                else throw new IOException("APK 游戏库在跳转期间被截断");
            }
            consumeBudget(count);
            byte[] bytes = exact(stream, count); position += bytes.length;
            return bytes;
        }
        private void consumeBudget(long amount) throws IOException {
            if (amount < 0 || amount > APK_INFLATE_LIMIT - inflated)
                throw new IOException("APK 游戏库兼容识别读取量超过 1 GiB；已停止探测并保留原配置");
            inflated += amount;
        }
        @Override public void close() throws IOException { if (stream != null) stream.close(); }
    }

    private static void skip(InputStream stream, long count) throws IOException {
        while (count > 0) {
            long skipped = stream.skip(count);
            if (skipped > 0) count -= skipped;
            else if (stream.read() != -1) count--;
            else throw new IOException("游戏库被截断，尚需跳过 " + count + " 字节");
        }
    }

    private static byte[] exact(InputStream stream, int count) throws IOException {
        byte[] result = new byte[count]; int offset = 0;
        while (offset < count) {
            int n = stream.read(result, offset, count - offset);
            if (n < 0) throw new IOException("游戏库被截断：需要 " + count + " 字节，仅读到 " + offset + " 字节");
            offset += n;
        }
        return result;
    }

    private static byte[] mask(byte[] first, byte[] second) throws IOException {
        if (first.length != 16 || second.length != 16)
            throw new IOException("游戏库适配区段长度不正确：第一段 " + first.length + " 字节，第二段 " + second.length + " 字节；应各为 16 字节");
        byte[] result = new byte[32];
        for (int i = 0; i < 16; i++) { result[i] = (byte) (first[i] ^ 0xe2); result[i + 16] = (byte) (second[i] ^ 0xe2); }
        return result;
    }

    private void authenticate(byte[] mask, byte[] gameplay, byte[] engine, byte[] game, Paths paths, String stage) throws Exception {
        final byte[] key;
        try { key = ConfigCrypto.deriveKey(mask, gameplay); }
        catch (Exception failure) { throw wrap(stage + "：解析 UserGameplay Hash 并派生本机配置密钥", paths.gameplay, failure); }
        try {
            try { ConfigCrypto.decodeIni(engine, key); }
            catch (Exception failure) { throw wrap(stage + "：解析 Engine Token、解密并验证 HMAC", paths.engine, failure); }
            try { validateGame(game); }
            catch (Exception failure) { throw wrap(stage + "：验证 Game.ini 明文格式", paths.game, failure); }
        } finally { Arrays.fill(key, (byte) 0); }
    }

    private void validateCompatibility(byte[] mask, byte[] gameplay, byte[] engine, byte[] game, Paths paths, String stage) throws Exception {
        byte[] key = null;
        try {
            key = ConfigCrypto.deriveKey(mask, gameplay);
            ConfigCompatibility.validate(ConfigCrypto.decodeIni(engine, key), game);
        } catch (Exception failure) { throw wrap(stage, paths.engine + "\n" + paths.game, failure); }
        finally { if (key != null) Arrays.fill(key, (byte) 0); }
    }

    private void checkInstallation(Paths paths, String stage) throws Exception {
        try {
            PackageInfo current = context.getPackageManager().getPackageInfo(packageName, 0);
            if (!paths.installation.equals(Installation.from(current, packageName)))
                throw new IOException("游戏版本或安装身份在操作期间发生变化；已停止使用旧配置快照，请重新读取");
        } catch (Exception failure) { throw wrap(stage, "package:" + packageName, failure); }
    }

    private static boolean sameGameVersion(String expectedName, long expectedCode, String actualName, long actualCode) {
        return expectedName != null && expectedName.equals(actualName) && expectedCode == actualCode;
    }

    private void verifyGameplay(byte[] mask, byte[] gameplay, String path, String stage) throws Exception {
        try { byte[] key = ConfigCrypto.deriveKey(mask, gameplay); Arrays.fill(key, (byte) 0); }
        catch (Exception failure) { throw wrap(stage, path, failure); }
    }

    private static void validateGame(byte[] game) throws Exception {
        if (game.length == 0 || game.length > ConfigCrypto.MAX_INI_BYTES) throw new IOException("Game.ini 大小无效");
        String text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(game)).toString();
        if (text.startsWith("\ufeff")) text = text.substring(1);
        if (text.indexOf('\0') >= 0 || !java.util.regex.Pattern.compile("(?m)^\\s*\\[[^\\]\\r\\n]+\\]\\s*$").matcher(text).find())
            throw new IOException("Game.ini 不是支持的明文 INI 格式");
    }

    private void requireRoot() throws Exception {
        rootAuthorized = false;
        String uid = checked("获取 root 权限并检查 UID", "su / 当前 Android 用户 " + userId, "id -u", null, 128).text().trim();
        if (!"0".equals(uid)) throw problem("验证 root UID", "su", "su 返回的 UID 为 " + uid + "，需要 UID 0；请在 root 管理器中授权本应用", null);
        rootAuthorized = true;
    }

    private void ensureStorage() throws Exception {
        String[] directories = backupDirectories(packageName, userId);
        for (String path : directories) noLink(path, "检查备份目录不是符号链接");
        checked("创建本机备份目录", base, "umask 077; mkdir -p " + q(base), null, 8192);
        for (String path : directories) {
            checked("设置备份目录所有者", path, "chown 0:0 " + q(path), null, 8192);
            checked("设置备份目录访问权限", path, "chmod 700 " + q(path), null, 8192);
        }
    }

    private String pointer(String name) throws Exception {
        String path = base + "/" + name;
        noLink(path, "检查 " + name + " 备份索引路径");
        RootShell.Result result = checked("读取 " + name + " 备份索引", path,
                "if [ -e " + q(path) + " ]; then if [ ! -f " + q(path) + " ]; then echo '索引不是普通文件' >&2; exit 45; fi; cat " + q(path) + "; fi", null, 256);
        String value = result.text().trim(); if (value.isEmpty()) return null;
        if (!value.matches("[0-9]{8}_[0-9]{6}_[0-9]{3}-[a-f0-9-]{36}"))
            throw problem("解析 " + name + " 备份索引", path, "索引内容不是受支持的事务 ID 格式", null);
        return value;
    }

    private void writePointer(String name, String id) throws Exception {
        String path = base + "/" + name, temp = path + ".tmp";
        writeRoot(temp, (id + "\n").getBytes(StandardCharsets.US_ASCII), "保存 " + name + " 备份索引暂存内容");
        checked("提交 " + name + " 备份索引", path, "mv -f " + q(temp) + " " + q(path), null, 8192);
        checked("同步 " + name + " 备份索引", path, "sync", null, 8192);
    }

    private void writeRoot(String path, byte[] bytes, String stage) throws Exception {
        String temporary = path + ".write-" + UUID.randomUUID().toString();
        noLink(path, stage + "：检查目标路径"); absent(temporary, stage + "：检查临时文件路径");
        checked(stage + "：创建临时文件并写入字节", temporary, "umask 077; cat > " + q(temporary), bytes, 8192);
        checked(stage + "：设置临时文件所有者", temporary, "chown 0:0 " + q(temporary), null, 8192);
        checked(stage + "：设置临时文件权限", temporary, "chmod 600 " + q(temporary), null, 8192);
        verifyBytes(read(temporary, Math.max(bytes.length, 128), stage + "：回读临时文件"), hash(bytes), temporary, stage + "：校验临时文件字节");
        checked(stage + "：重命名提交", path, "mv -f " + q(temporary) + " " + q(path), null, 8192);
        checked(stage + "：同步到存储", path, "sync", null, 8192);
    }

    private Metadata metadata(String path, String stage) throws Exception {
        regular(path, stage + "：检查文件");
        String[] values = checked(stage + "：读取 UID/GID/权限位", path, "stat -c '%u %g %a' " + q(path), null, 1024).text().trim().split("\\s+");
        if (values.length != 3) throw problem(stage + "：解析 UID/GID/权限位", path, "stat 未返回恰好三项 UID、GID 和八进制权限位", null);
        String[] label = checked(stage + "：读取 SELinux 标签", path, "ls -Zd " + q(path), null, 8192).text().trim().split("\\s+");
        if (label.length == 0 || label[0].isEmpty()) throw problem(stage + "：解析 SELinux 标签", path, "ls -Z 没有返回 SELinux 标签", null);
        try { return new Metadata(values[0], values[1], values[2], label[0]); }
        catch (Exception failure) { throw wrap(stage + "：验证 UID/GID/权限/SELinux 标签格式", path, failure); }
    }

    private void setMetadata(String path, Metadata metadata, String stage) throws Exception {
        checked(stage + "：chown 设置 UID/GID", path, "chown " + q(metadata.uid + ":" + metadata.gid) + " " + q(path), null, 8192);
        checked(stage + "：chmod 设置权限位", path, "chmod " + q(metadata.mode) + " " + q(path), null, 8192);
        Exception chconFailure = null;
        try { checked(stage + "：chcon 设置 SELinux 标签", path, "chcon " + q(metadata.label) + " " + q(path), null, 8192); }
        catch (Exception first) {
            chconFailure = first;
            try { checked(stage + "：chcon 失败后尝试 restorecon", path, "restorecon " + q(path), null, 8192); }
            catch (Exception second) { second.addSuppressed(first); throw second; }
        }
        try { verifyMetadata(path, metadata, stage + "：回读验证权限和 SELinux 标签"); }
        catch (Exception failure) { if (chconFailure != null) failure.addSuppressed(chconFailure); throw failure; }
    }

    private void verifyMetadata(String path, Metadata expected, String stage) throws Exception {
        Metadata actual = metadata(path, stage);
        if (!actual.equals(expected)) throw problem(stage, path,
                "权限或 SELinux 标签与原件不一致；预期 UID:GID=" + expected.uid + ":" + expected.gid
                        + "，权限=" + expected.mode + "，标签=" + expected.label + "；实际 UID:GID=" + actual.uid + ":"
                        + actual.gid + "，权限=" + actual.mode + "，标签=" + actual.label, null);
    }

    private String deviceIdentity() throws Exception {
        final String id;
        try { id = Settings.Secure.getString(context.getContentResolver(), Settings.Secure.ANDROID_ID); }
        catch (Exception failure) { throw wrap("读取用于本机备份匹配的 Android ID", "Settings.Secure.ANDROID_ID", failure); }
        if (id == null || id.isEmpty()) throw problem("检查本机备份标识", "Settings.Secure.ANDROID_ID", "系统未返回 Android ID，无法保证备份属于本设备", null);
        return hash((id + "|" + userId).getBytes(StandardCharsets.UTF_8));
    }

    private RootShell.Result checked(String stage, String path, String command, byte[] input, int maximum) throws Exception {
        final RootShell.Result result;
        try { result = rootAccess == null ? RootShell.run(command, input, maximum, TIMEOUT)
                : rootAccess.run(command, input, maximum, TIMEOUT); }
        catch (RootShell.TransportFailure failure) {
            String detail = OperationFailure.sanitize(failure.stderr);
            OperationFailure wrapped = problem(stage + " / " + failure.stage, path,
                    failure.getMessage() + (detail.isEmpty() ? "" : "；root stderr：" + detail), failure);
            if (failure.exitCode != null) wrapped.exitCode(failure.exitCode);
            throw wrapped;
        } catch (InterruptedException failure) {
            Thread.currentThread().interrupt(); throw problem(stage + " / 等待 root 通道", path, "当前操作线程被中断，需根据事务状态判断是否已写入", failure);
        } catch (Exception failure) { throw wrap(stage + " / 执行 root 命令", path, failure); }
        if (result.exitCode != 0) {
            String detail = OperationFailure.sanitize(result.stderr), reason;
            switch (result.exitCode) {
                case 44: reason = "文件不存在或在当前 root 命名空间不可见"; break;
                case 45: reason = "目标不是普通文件"; break;
                case 46: reason = "文件不可读"; break;
                case 47: reason = "目标是符号链接，为避免误改已拒绝操作"; break;
                case 48: reason = "临时目标已存在，拒绝覆盖"; break;
                case 49: reason = "当前 root 进程不再具有 UID 0，已停止操作"; break;
                case 50: reason = "root 挂载命名空间与已验证上下文不一致，已停止操作；请重新读取配置"; break;
                default: reason = "root 命令返回失败";
            }
            reason += detail.isEmpty() ? "；root 未返回错误文本" : "；root stderr：" + detail;
            throw problem(stage, path, reason, null).exitCode(result.exitCode);
        }
        return result;
    }

    private void begin(String name) {
        operation = name; writeStatus = "未写入游戏配置"; rollbackStatus = "无需回滚"; backupPath = null; originalRestored = false;
        rootAccess = null;
    }

    private OperationFailure problem(String stage, String path, String reason, Throwable cause) {
        return new OperationFailure(operation, stage, path, reason, cause);
    }

    private OperationFailure wrap(String stage, String path, Throwable cause) {
        return OperationFailure.wrap(operation, stage, path, cause);
    }

    private OperationFailure diagnosed(Throwable cause) {
        return wrap("执行操作", null, cause).state(writeStatus, rollbackStatus, backupPath);
    }

    /** Fault boundaries used by the real transaction and host regression checks. */
    private static final class CommitBoundary {
        private int phase;
        void markerAttempted() {
            if (phase != 0) throw new IllegalStateException("提交标记重命名只能尝试一次");
            phase = 1;
        }
        void markerConfirmed() {
            if (phase != 1) throw new IllegalStateException("尚未尝试提交标记重命名");
            phase = 2;
        }
        void markerSynced() {
            if (phase != 2) throw new IllegalStateException("提交标记尚未确认替换，不能确认同步");
            phase = 3;
        }
        boolean canRollback() { return phase == 0; }
        boolean isMarkerConfirmed() { return phase >= 2; }
        boolean isMarkerSynced() { return phase == 3; }
    }

    /** Compatibility helper retained for host boundary tests. Values and multiline payloads are omitted. */
    private static String safeDiagnostic(String stderr) {
        if (stderr == null || stderr.isEmpty()) return "";
        String first = stderr.split("[\\r\\n]", 2)[0].replaceAll("[\\p{Cntrl}]", " ").trim();
        first = first.replaceAll("(?i)\\b(token|hash|password|passwd|secret|key)\\b(?:\\s*[:=]|\\s+).*", "$1=[REDACTED]");
        first = first.replaceAll("[A-Za-z0-9+/=_-]{64,}", "[REDACTED]");
        return first.length() > 300 ? first.substring(0, 300) : first;
    }

    private static String q(String value) { return RootShell.quote(value); }
    private static String temporary(String target, String id, String suffix) { return target + ".deltaconfig-" + id + suffix; }
    private static String hash(byte[] data) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(data);
        StringBuilder text = new StringBuilder(64);
        for (byte value : digest) text.append(String.format(Locale.US, "%02x", value & 255));
        return text.toString();
    }

    private static final class Paths {
        final ApplicationInfo info;
        final Installation installation;
        final String engine, game, gameplay;
        Paths(ApplicationInfo info, Installation installation, String engine, String game, String gameplay) {
            this.info = info; this.installation = installation; this.engine = engine; this.game = game; this.gameplay = gameplay;
        }
    }

    /** Immutable package identity, independent of the configuration format's compatibility result. */
    private static final class Installation {
        final String packageName, versionName, sourceDir, nativeLibraryDir;
        final long versionCode, lastUpdateTime;
        final int uid;
        Installation(String packageName, String versionName, long versionCode, long lastUpdateTime, String sourceDir, String nativeLibraryDir, int uid) throws IOException {
            GameTarget.lookup(packageName);
            if (versionName == null || versionName.trim().isEmpty() || versionCode < 0 || lastUpdateTime < 0
                    || sourceDir == null || !sourceDir.startsWith("/") || nativeLibraryDir == null || !nativeLibraryDir.startsWith("/"))
                throw new IOException("游戏的实际版本号或安装路径无效，无法绑定配置与备份");
            this.packageName = packageName; this.versionName = versionName; this.versionCode = versionCode; this.lastUpdateTime = lastUpdateTime;
            this.sourceDir = sourceDir; this.nativeLibraryDir = nativeLibraryDir; this.uid = uid;
        }
        static Installation from(PackageInfo info, String expectedPackage) throws IOException {
            if (info == null || info.applicationInfo == null) throw new IOException("缺少游戏安装信息");
            verifyInstalledTarget(expectedPackage, info.packageName, info.applicationInfo.packageName);
            long code = Build.VERSION.SDK_INT >= 28 ? info.getLongVersionCode() : info.versionCode;
            return new Installation(expectedPackage, info.versionName, code, info.lastUpdateTime, info.applicationInfo.sourceDir,
                    info.applicationInfo.nativeLibraryDir, info.applicationInfo.uid);
        }
        String cacheIdentity() {
            return packageName + "|" + versionName + "|" + versionCode + "|" + lastUpdateTime + "|" + uid + "|" + sourceDir + "|" + nativeLibraryDir;
        }
        @Override public boolean equals(Object other) {
            if (!(other instanceof Installation)) return false;
            Installation actual = (Installation) other;
            return packageName.equals(actual.packageName) && sameGameVersion(versionName, versionCode, actual.versionName, actual.versionCode)
                    && lastUpdateTime == actual.lastUpdateTime && uid == actual.uid
                    && sourceDir.equals(actual.sourceDir) && nativeLibraryDir.equals(actual.nativeLibraryDir);
        }
        @Override public int hashCode() { return cacheIdentity().hashCode(); }
    }

    private static final class Metadata {
        final String uid, gid, mode, label;
        Metadata(String uid, String gid, String mode, String label) throws IOException {
            if (!uid.matches("[0-9]{1,10}") || !gid.matches("[0-9]{1,10}") || !mode.matches("[0-7]{3,4}")
                    || !label.matches("[a-zA-Z0-9_]+:[a-zA-Z0-9_]+:[a-zA-Z0-9_]+:[a-zA-Z0-9_:,.-]+"))
                throw new IOException("文件权限或 SELinux 标签格式不受支持");
            this.uid = uid; this.gid = gid; this.mode = mode; this.label = label;
        }
        JSONObject json() throws Exception { return new JSONObject().put("uid", uid).put("gid", gid).put("mode", mode).put("label", label); }
        static Metadata from(JSONObject json) throws Exception { return new Metadata(json.getString("uid"), json.getString("gid"), json.getString("mode"), json.getString("label")); }
        @Override public boolean equals(Object other) {
            if (!(other instanceof Metadata)) return false;
            Metadata metadata = (Metadata) other;
            return uid.equals(metadata.uid) && gid.equals(metadata.gid) && mode.equals(metadata.mode) && label.equals(metadata.label);
        }
        @Override public int hashCode() { return (uid + gid + mode + label).hashCode(); }
    }
}
