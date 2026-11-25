import io.github.deltaconfig.RootShell;
import io.github.deltaconfig.GameRepository;
import io.github.deltaconfig.GameTarget;
import io.github.deltaconfig.core.ConfigCrypto;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

/** Host-only transport, library-reader, and input-validation boundary tests. No su is executed. */
public final class RepositoryTests {
    private static int checks;
    public static void main(String[] args) throws Exception {
        equal("''", RootShell.quote(""));
        equal("'abc'", RootShell.quote("abc"));
        equal("'a'\\''b'", RootShell.quote("a'b"));
        equal("'$(id); `x`\n space'", RootShell.quote("$(id); `x`\n space"));
        try { RootShell.quote("a\0b"); throw new AssertionError("NUL accepted"); }
        catch (IllegalArgumentException expected) { checks++; }

        Class<?> captureClass = Class.forName("io.github.deltaconfig.RootShell$Capture");
        Constructor<?> constructor = captureClass.getDeclaredConstructor(InputStream.class, int.class);
        constructor.setAccessible(true);
        byte[] binary = new byte[65536];
        for (int i = 0; i < binary.length; i++) binary[i] = (byte) i;
        Object capture = constructor.newInstance(new ByteArrayInputStream(binary), binary.length);
        ((Runnable) capture).run();
        Field bytesField = captureClass.getDeclaredField("bytes"); bytesField.setAccessible(true);
        Field largeField = captureClass.getDeclaredField("tooLarge"); largeField.setAccessible(true);
        check(Arrays.equals(binary, ((ByteArrayOutputStream) bytesField.get(capture)).toByteArray()));
        check(!largeField.getBoolean(capture));
        ByteArrayInputStream source = new ByteArrayInputStream(binary);
        Object capped = constructor.newInstance(source, 31);
        ((Runnable) capped).run();
        check(largeField.getBoolean(capped));
        check(((ByteArrayOutputStream) bytesField.get(capped)).size() == 31);
        check(source.available() == 0);
        Object zero = constructor.newInstance(new ByteArrayInputStream(binary), 0);
        ((Runnable) zero).run();
        check(largeField.getBoolean(zero));
        check(((ByteArrayOutputStream) bytesField.get(zero)).size() == 0);

        Method mask = accessible("mask", byte[].class, byte[].class);
        byte[] first = new byte[16], second = new byte[16];
        Arrays.fill(first, (byte) 0xe2); Arrays.fill(second, (byte) 0x11);
        byte[] result = (byte[]) mask.invoke(null, first, second);
        check(result.length == 32);
        for (int i = 0; i < 16; i++) { check(result[i] == 0); check(result[i + 16] == (byte) 0xf3); }
        reject(mask, new byte[15], second);

        Method skip = accessible("skip", InputStream.class, long.class);
        Method exact = accessible("exact", InputStream.class, int.class);
        InputStream fragmented = new InputStream() {
            private final ByteArrayInputStream in = new ByteArrayInputStream(new byte[]{1, 2, 3, 4, 5});
            @Override public int read() { return in.read(); }
            @Override public long skip(long count) { return 0; }
        };
        skip.invoke(null, fragmented, 3L);
        check(Arrays.equals((byte[]) exact.invoke(null, fragmented, 2), new byte[]{4, 5}));
        reject(skip, new ByteArrayInputStream(new byte[0]), 1L);
        reject(exact, new ByteArrayInputStream(new byte[]{1}), 2);

        Method game = accessible("validateGame", byte[].class);
        game.invoke(null, (Object) "[LuaFrontEnd]\nLastHotUpdateVersion=1\n".getBytes(StandardCharsets.UTF_8)); checks++;
        game.invoke(null, (Object) "\ufeff[LuaFrontEnd]\nX=1\n".getBytes(StandardCharsets.UTF_8)); checks++;
        game.invoke(null, (Object) "\ufeff[LuaFrontEnd]\nX=1\n\n[Other]\nY=2\n".getBytes(StandardCharsets.UTF_8)); checks++;
        reject(game, (Object) new byte[0]);
        reject(game, (Object) new byte[]{(byte) 0xc0, (byte) 0x80});
        reject(game, (Object) "[x]\nA=\0".getBytes(StandardCharsets.UTF_8));
        reject(game, (Object) "Token=not-an-ini".getBytes(StandardCharsets.UTF_8));

        Method hash = accessible("hash", byte[].class);
        equal("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hash.invoke(null, (Object) new byte[0]));
        equal("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", hash.invoke(null, (Object) "abc".getBytes(StandardCharsets.US_ASCII)));
        Method context = accessible("verifyGameplayContext", byte[].class, String.class);
        byte[] originalGameplay = "[UserGameplay]\nHash=original-context\n".getBytes(StandardCharsets.UTF_8);
        String originalHash = (String) hash.invoke(null, (Object) originalGameplay);
        context.invoke(null, originalGameplay, originalHash); checks++;
        reject(context, "[UserGameplay]\nHash=rebuilt-context\n".getBytes(StandardCharsets.UTF_8), originalHash);
        reject(context, originalGameplay, null);

        Method diagnostic = accessible("safeDiagnostic", String.class);
        equal("", diagnostic.invoke(null, (Object) null));
        equal("", diagnostic.invoke(null, ""));
        equal("cat: /data/user/0/x: Permission denied", diagnostic.invoke(null, "cat: /data/user/0/x: Permission denied\nsecond line hidden"));
        equal("Token=[REDACTED]", diagnostic.invoke(null, "Token=abc def ghi\nconfiguration tail"));
        equal("Hash=[REDACTED]", diagnostic.invoke(null, "Hash: abc def"));
        equal("Password=[REDACTED]", diagnostic.invoke(null, "Password 'a spaced password'"));
        equal("secret=[REDACTED]", diagnostic.invoke(null, "secret = \"value with spaces\""));
        equal("library: [REDACTED]", diagnostic.invoke(null, "library: " + new String(new char[70]).replace('\0', 'A')));
        equal("cat: Permission denied", diagnostic.invoke(null, "cat:\tPermission denied"));
        equal(300, ((String) diagnostic.invoke(null, new String(new char[340]).replace('\0', '.'))).length());
        commitBoundaryRegression();
        installationIdentityRegression();
        targetIsolationRegression();
        librarySourceRegression();
        cachedEncodingRegression();
        terminalLibraryFailureRegression();
        System.out.println("Repository host checks: " + checks + " passed (no device/root transaction test)");
    }

    private static byte[] envelope(String field, String text, byte[] key) throws Exception {
        return envelope(field, text, key, 0x4502);
    }

    private static void terminalLibraryFailureRegression() throws Exception {
        Method terminal = accessible("stopLibraryFallback", Throwable.class);
        check(!(Boolean) terminal.invoke(null, (Object) null));
        check(!(Boolean) terminal.invoke(null, new IOException("ordinary source missing")));
        check(!(Boolean) terminal.invoke(null, new java.security.GeneralSecurityException("ordinary HMAC mismatch")));
        Throwable format = new ConfigCrypto.AuthenticatedFormatException("authenticated unsupported format");
        Throwable budget = new ConfigCrypto.MaterialAuthenticationBudgetException("budget exhausted");
        for (Throwable cause : new Throwable[]{format, budget}) {
            check((Boolean) terminal.invoke(null, cause));
            check((Boolean) terminal.invoke(null, new IOException("source context", cause)));
            check((Boolean) terminal.invoke(null, new Exception("wrapper", new IOException("source context", cause))));
        }
    }

    private static byte[] envelope(String field, String text, byte[] key, int magic) throws Exception {
        Method encrypt = ConfigCrypto.class.getDeclaredMethod("encrypt", String.class, byte[].class, int.class);
        encrypt.setAccessible(true);
        byte[] token = (byte[]) encrypt.invoke(null, text, key, magic);
        return ("[Envelope]\n" + field + "=" + new String(token, StandardCharsets.US_ASCII) + "\n")
                .getBytes(StandardCharsets.US_ASCII);
    }

    private static void cachedEncodingRegression() throws Exception {
        Method authenticate = accessible("authenticateCachedMask", byte[].class, byte[].class, byte[].class, int.class);
        Class<?> cached = Class.forName("io.github.deltaconfig.GameRepository$CachedMaterial");
        Field maskField = cached.getDeclaredField("mask"); maskField.setAccessible(true);
        Field encodingField = cached.getDeclaredField("encoding"); encodingField.setAccessible(true);
        byte[] mask = new byte[32];
        for (int i = 0; i < mask.length; i++) mask[i] = (byte) (i * 19 + 3);
        byte[] gameplay = envelope("Hash", "0123456789abcdef0123456789abcdef01234567", mask);
        byte[] key = ConfigCrypto.deriveKey(mask, gameplay);
        byte[] engine = envelope("Token", "[DFMPerfGearConfig]\nDFMFPSLevel=8\n", key);
        byte[] corrupt = engine.clone(); corrupt[corrupt.length - 4] ^= 1;
        byte[] wrongHash = gameplay.clone(); wrongHash[wrongHash.length - 4] ^= 1;
        for (int encoding : new int[]{0, 0xe2, 0x10, 0x33, 0xff}) {
            byte[] stored = mask.clone();
            for (int i = 0; i < stored.length; i++) stored[i] ^= (byte) encoding;
            byte[] before = stored.clone();
            for (int preference : new int[]{-1, encoding, encoding ^ 255, -9, 300}) {
                Object result = authenticate.invoke(null, stored, gameplay, engine, preference);
                byte[] resolved = (byte[]) maskField.get(result);
                check(Arrays.equals(mask, resolved));
                check(resolved != stored);
                check(encodingField.getInt(result) == encoding);
                Arrays.fill(resolved, (byte) 0);
            }
            check(Arrays.equals(before, stored));
            check(authenticate.invoke(null, stored, gameplay, corrupt, encoding) == null);
            check(authenticate.invoke(null, stored, wrongHash, engine, encoding) == null);
            Object restoreResult = authenticate.invoke(null, stored, gameplay, null, encoding);
            byte[] restore = (byte[]) maskField.get(restoreResult);
            check(Arrays.equals(mask, restore));
            Arrays.fill(restore, (byte) 0);
        }
        check(authenticate.invoke(null, new byte[31], gameplay, engine, -1) == null);
        check(authenticate.invoke(null, null, gameplay, engine, -1) == null);
        byte[] excessiveHash = ("[Envelope]\nHash=" + new String(new char[300000]).replace('\0', 'A') + "\n")
                .getBytes(StandardCharsets.US_ASCII);
        try {
            authenticate.invoke(null, mask, excessiveHash, engine, -1);
            throw new AssertionError("Cached material authentication budget ignored");
        } catch (InvocationTargetException expected) {
            check(expected.getCause() instanceof IOException);
            check(expected.getCause().getMessage().contains("64 MiB"));
        }
        byte[] unsupportedHash = envelope("Hash", "authenticated-digest-format-changed", mask);
        byte[] unsupportedHeader = envelope("Hash", "0123456789abcdef0123456789abcdef01234567", mask, 0x4503);
        byte[] unsupportedEngine = envelope("Token", "[Future]\nNew=1\n", key, 0x4503);
        for (byte[][] pair : new byte[][][]{
                {unsupportedHash, engine}, {unsupportedHeader, engine}, {gameplay, unsupportedEngine}}) {
            try {
                authenticate.invoke(null, mask, pair[0], pair[1], 0);
                throw new AssertionError("Authenticated unsupported format treated as another encoding candidate");
            } catch (InvocationTargetException expected) {
                check(expected.getCause() instanceof ConfigCrypto.AuthenticatedFormatException);
            }
        }
        Arrays.fill(mask, (byte) 0); Arrays.fill(key, (byte) 0);
    }

    private static void installationIdentityRegression() throws Exception {
        Method sameVersion = accessible("sameGameVersion", String.class, long.class, String.class, long.class);
        check((Boolean) sameVersion.invoke(null, "future-build", 5000000000L, "future-build", 5000000000L));
        check(!(Boolean) sameVersion.invoke(null, "future-build", 5000000000L, "future-build", 705032704L));
        check(!(Boolean) sameVersion.invoke(null, "future-build", 10L, "next-build", 10L));
        check(!(Boolean) sameVersion.invoke(null, null, 10L, null, 10L));
        Class<?> identity = Class.forName("io.github.deltaconfig.GameRepository$Installation");
        Constructor<?> create = identity.getDeclaredConstructor(String.class, String.class, long.class, long.class, String.class, String.class, int.class);
        create.setAccessible(true);
        Object original = create.newInstance(GameRepository.PACKAGE, "future-build", 5000000000L, 100L, "/data/app/base.apk", "/data/app/lib/arm64", 10234);
        check(original.equals(create.newInstance(GameRepository.PACKAGE, "future-build", 5000000000L, 100L, "/data/app/base.apk", "/data/app/lib/arm64", 10234)));
        check(!original.equals(create.newInstance(GameRepository.PACKAGE, "future-build", 5000000000L, 101L, "/data/app/base.apk", "/data/app/lib/arm64", 10234)));
        check(!original.equals(create.newInstance(GameRepository.PACKAGE, "future-build", 5000000000L, 100L, "/data/app/new.apk", "/data/app/lib/arm64", 10234)));
        check(!original.equals(create.newInstance(GameRepository.PACKAGE, "future-build", 5000000000L, 100L, "/data/app/base.apk", "/data/app/other/arm64", 10234)));
        check(!original.equals(create.newInstance(GameRepository.PACKAGE, "future-build", 5000000000L, 100L, "/data/app/base.apk", "/data/app/lib/arm64", 10235)));
        try { create.newInstance(GameRepository.PACKAGE, "", 1L, 1L, "/x", "/lib", 1); throw new AssertionError("Empty package version accepted"); }
        catch (InvocationTargetException expected) { checks++; }
        try { create.newInstance(GameRepository.PACKAGE, "future", -1L, 1L, "/x", "/lib", 1); throw new AssertionError("Negative package version accepted"); }
        catch (InvocationTargetException expected) { checks++; }
    }

    private static void targetIsolationRegression() throws Exception {
        GameTarget[] targets = GameTarget.values();
        check(targets.length == 3);
        check(targets[0] == GameTarget.CN && targets[1] == GameTarget.GLOBAL && targets[2] == GameTarget.GARENA);
        targets[0] = null;
        check(GameTarget.values()[0] == GameTarget.CN);
        try { GameTarget.lookup("../../other"); throw new AssertionError("Arbitrary package accepted"); }
        catch (IllegalArgumentException expected) { checks++; }
        Method base = accessible("backupBase", String.class, int.class);
        Method directories = accessible("backupDirectories", String.class, int.class);
        Method privateDir = accessible("privateConfigDirectory", String.class, String.class);
        Method gameplay = accessible("gameplayPath", String.class, int.class, boolean.class);
        Method snapshot = accessible("verifySnapshotTarget", String.class, String.class);
        Method installed = accessible("verifyInstalledTarget", String.class, String.class, String.class);
        Class<?> identity = Class.forName("io.github.deltaconfig.GameRepository$Installation");
        Constructor<?> create = identity.getDeclaredConstructor(String.class, String.class, long.class, long.class,
                String.class, String.class, int.class);
        create.setAccessible(true);
        Method cacheIdentity = identity.getDeclaredMethod("cacheIdentity"); cacheIdentity.setAccessible(true);
        String relative = "/UE4Game/DeltaForce/DeltaForce/Saved/Config/Android/";
        Object[] installations = new Object[3];
        int index = 0;
        for (GameTarget target : GameTarget.values()) {
            String pkg = target.packageName;
            check(GameTarget.lookup(pkg) == target);
            equal("/data/user/0/" + pkg + "/files" + relative,
                    privateDir.invoke(null, pkg, "/data/user/0/" + pkg));
            for (int user : new int[]{0, 10}) {
                String expected = "/data/adb/deltaconfig/backups/" + (target == GameTarget.CN ? "" : pkg + "/") + user;
                equal(expected, base.invoke(null, pkg, user));
                String[] guards = (String[]) directories.invoke(null, pkg, user);
                check(guards.length == (target == GameTarget.CN ? 3 : 4));
                equal(expected, guards[guards.length - 1]);
                if (target != GameTarget.CN) equal("/data/adb/deltaconfig/backups/" + pkg, guards[2]);
                equal("/storage/emulated/" + user + "/Android/data/" + pkg + "/files" + relative + "UserGameplay.ini",
                        gameplay.invoke(null, pkg, user, false));
                equal("/data/media/" + user + "/Android/data/" + pkg + "/files" + relative + "UserGameplay.ini",
                        gameplay.invoke(null, pkg, user, true));
            }
            snapshot.invoke(null, pkg, pkg); checks++;
            installed.invoke(null, pkg, pkg, pkg); checks++;
            reject(snapshot, pkg, null);
            reject(installed, pkg, pkg, null);
            installations[index++] = create.newInstance(pkg, "same-build", 100L, 1L, "/same/base.apk", "/same/lib", 10234);
            check(((String) cacheIdentity.invoke(installations[index - 1])).startsWith(pkg + "|"));
            for (GameTarget other : GameTarget.values()) if (target != other) {
                reject(snapshot, pkg, other.packageName);
                reject(installed, pkg, other.packageName, pkg);
                reject(installed, pkg, pkg, other.packageName);
            }
        }
        for (int i = 0; i < installations.length; i++) for (int j = i + 1; j < installations.length; j++) {
            check(!installations[i].equals(installations[j]));
            check(!cacheIdentity.invoke(installations[i]).equals(cacheIdentity.invoke(installations[j])));
        }
        equal("/data/adb/deltaconfig/backups/0", base.invoke(null, GameRepository.PACKAGE, 0));
        reject(base, "unrecognized.package", 0);
        reject(base, GameRepository.PACKAGE, -1);
        reject(gameplay, "unrecognized.package", 0, false);
        reject(gameplay, GameRepository.PACKAGE, -1, false);
        reject(privateDir, GameRepository.PACKAGE, "relative/path");
        reject(privateDir, "unrecognized.package", "/data/user/0/unrecognized.package");
    }

    private static void librarySourceRegression() throws Exception {
        Method range = accessible("validateLibraryRange", long.class, long.class, int.class);
        range.invoke(null, 128L, 64L, 64); checks++;
        range.invoke(null, 128L, 128L, 0); checks++;
        reject(range, 128L, -1L, 1); reject(range, 128L, 64L, 65);
        reject(range, Long.MAX_VALUE, 1L, 1); reject(range, 128L, Long.MAX_VALUE, 2);
        reject(range, 2L * 1024 * 1024, 0L, 1024 * 1024 + 1);
        Method headerCheck = accessible("validateArm64Header", byte[].class, long.class);
        byte[] header = new byte[64]; header[0] = 0x7f; header[1] = 'E'; header[2] = 'L'; header[3] = 'F';
        header[4] = 2; header[5] = 1; header[6] = 1; header[16] = 3; header[18] = (byte) 183; header[52] = 64;
        headerCheck.invoke(null, header, 64L); checks++;
        byte[] wrong = header.clone(); wrong[18] = 62; reject(headerCheck, wrong, 64L);
        wrong = header.clone(); wrong[4] = 1; reject(headerCheck, wrong, 64L);
        wrong = header.clone(); wrong[5] = 2; reject(headerCheck, wrong, 64L);
        reject(headerCheck, new byte[63], 64L);
        Class<?> sourceClass = Class.forName("io.github.deltaconfig.GameRepository$ZipLibrarySource");
        Constructor<?> constructor = sourceClass.getDeclaredConstructor(ZipFile.class, ZipEntry.class); constructor.setAccessible(true);
        Method read = sourceClass.getDeclaredMethod("read", long.class, int.class); read.setAccessible(true);
        Method close = sourceClass.getDeclaredMethod("close"); close.setAccessible(true);
        Field inflated = sourceClass.getDeclaredField("inflated"); inflated.setAccessible(true);
        byte[] bytes = new byte[32768]; for (int i = 0; i < bytes.length; i++) bytes[i] = (byte) (i * 13);
        for (int method : new int[]{ZipEntry.STORED, ZipEntry.DEFLATED}) {
            Path archive = Files.createTempFile("deltaconfig-library-source-", ".zip");
            try {
                try (ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(archive))) {
                    ZipEntry entry = new ZipEntry("lib/arm64-v8a/libUE4.so"); entry.setMethod(method);
                    if (method == ZipEntry.STORED) { CRC32 crc = new CRC32(); crc.update(bytes); entry.setSize(bytes.length); entry.setCrc(crc.getValue()); }
                    output.putNextEntry(entry); output.write(bytes); output.closeEntry();
                }
                try (ZipFile zip = new ZipFile(archive.toFile())) {
                    Object source = constructor.newInstance(zip, zip.getEntry("lib/arm64-v8a/libUE4.so"));
                    check(Arrays.equals((byte[]) read.invoke(source, 1000L, 64), Arrays.copyOfRange(bytes, 1000, 1064)));
                    check(Arrays.equals((byte[]) read.invoke(source, 1064L, 60), Arrays.copyOfRange(bytes, 1064, 1124)));
                    check(Arrays.equals((byte[]) read.invoke(source, 16L, 64), Arrays.copyOfRange(bytes, 16, 80)));
                    try { read.invoke(source, 32760L, 64); throw new AssertionError("ZIP source out-of-bounds accepted"); }
                    catch (InvocationTargetException expected) { checks++; }
                    inflated.setLong(source, 1024L * 1024 * 1024);
                    try { read.invoke(source, 80L, 1); throw new AssertionError("ZIP source read budget ignored"); }
                    catch (InvocationTargetException expected) { checks++; }
                    close.invoke(source);
                }
            } finally { Files.deleteIfExists(archive); }
        }
    }

    /** Inject failures around publishing COMMITTED; a possible published marker must never trigger rollback. */
    private static void commitBoundaryRegression() throws Exception {
        Class<?> boundary = Class.forName("io.github.deltaconfig.GameRepository$CommitBoundary");
        Constructor<?> create = boundary.getDeclaredConstructor(); create.setAccessible(true);
        Method attempt = boundary.getDeclaredMethod("markerAttempted"); attempt.setAccessible(true);
        Method confirmed = boundary.getDeclaredMethod("markerConfirmed"); confirmed.setAccessible(true);
        Method synced = boundary.getDeclaredMethod("markerSynced"); synced.setAccessible(true);
        Method rollback = boundary.getDeclaredMethod("canRollback"); rollback.setAccessible(true);
        Method isConfirmed = boundary.getDeclaredMethod("isMarkerConfirmed"); isConfirmed.setAccessible(true);
        Method isSynced = boundary.getDeclaredMethod("isMarkerSynced"); isSynced.setAccessible(true);
        // Marker preparation failed: journal is still PREPARED, so rollback remains safe.
        Object beforePublish = create.newInstance();
        check((Boolean) rollback.invoke(beforePublish));
        check(!(Boolean) isConfirmed.invoke(beforePublish));
        check(!(Boolean) isSynced.invoke(beforePublish));
        // mv may have succeeded even if the su channel reports failure: leave pending for recovery.
        Object uncertainRename = create.newInstance(); attempt.invoke(uncertainRename);
        check(!(Boolean) rollback.invoke(uncertainRename));
        check(!(Boolean) isConfirmed.invoke(uncertainRename));
        check(!(Boolean) isSynced.invoke(uncertainRename));
        // The exact reported bug: mv succeeds, then sync fails. Never roll back beneath COMMITTED.
        Object failedSync = create.newInstance(); attempt.invoke(failedSync); confirmed.invoke(failedSync);
        check(!(Boolean) rollback.invoke(failedSync));
        check((Boolean) isConfirmed.invoke(failedSync));
        check(!(Boolean) isSynced.invoke(failedSync));
        // Index or cleanup failure after sync likewise leaves the validated game configuration committed.
        synced.invoke(failedSync);
        check(!(Boolean) rollback.invoke(failedSync));
        check((Boolean) isConfirmed.invoke(failedSync));
        check((Boolean) isSynced.invoke(failedSync));
        try { synced.invoke(create.newInstance()); throw new AssertionError("Sync accepted before marker publication"); }
        catch (InvocationTargetException expected) { check(expected.getCause() instanceof IllegalStateException); }
        try { confirmed.invoke(create.newInstance()); throw new AssertionError("Marker confirmed without attempt"); }
        catch (InvocationTargetException expected) { check(expected.getCause() instanceof IllegalStateException); }
        try { attempt.invoke(uncertainRename); throw new AssertionError("Marker attempt reset a possible commit"); }
        catch (InvocationTargetException expected) { check(expected.getCause() instanceof IllegalStateException); }
    }
    private static Method accessible(String name, Class<?>... types) throws Exception {
        Method method = GameRepository.class.getDeclaredMethod(name, types); method.setAccessible(true); return method;
    }
    private static void reject(Method method, Object... values) throws Exception {
        try { method.invoke(null, values); throw new AssertionError("Invalid input accepted: " + method.getName()); }
        catch (InvocationTargetException expected) { checks++; }
    }
    private static void check(boolean value) { if (!value) throw new AssertionError(); checks++; }
    private static void equal(Object expected, Object actual) { check(expected.equals(actual)); }
}
