import io.github.deltaconfig.core.ConfigCrypto;
import io.github.deltaconfig.core.LibraryMaskResolver;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;
import java.util.zip.ZipFile;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Synthetic ELF relocation tests; optional explicit private files are read only. */
public final class LibraryMaskResolverTests {
    private static int assertions;
    private static final int XOR = 0xe2e2e2e2;
    private static final long CODE_VA = 0x600000, DATA_VA = 0x900000;
    private interface Action { void run() throws Exception; }
    private static void check(boolean value, String message) { assertions++; if (!value) throw new AssertionError(message); }
    private static void rejects(Action action, String message) throws Exception {
        boolean failed = false;
        try { action.run(); } catch (IOException | GeneralSecurityException | IllegalArgumentException expected) { failed = true; }
        check(failed, message);
    }
    private static void rejectsContaining(Action action, String expected, String message) throws Exception {
        boolean failed = false;
        try { action.run(); }
        catch (IOException | GeneralSecurityException | IllegalArgumentException error) {
            failed = error.getMessage() != null && error.getMessage().contains(expected);
        }
        check(failed, message);
    }
    private static void rejectsAuthenticatedFormat(Action action, String expected, String message) throws Exception {
        boolean failed = false;
        try { action.run(); }
        catch (ConfigCrypto.AuthenticatedFormatException error) {
            failed = error.getMessage() != null && error.getMessage().contains(expected);
        }
        check(failed, message);
    }
    private static final class Bytes implements LibraryMaskResolver.Source {
        final byte[] bytes; boolean random; long reads, total; int largest;
        Bytes(byte[] bytes) { this.bytes = bytes; }
        public long length() { return bytes.length; }
        public boolean efficientRandomAccess() { return random; }
        public byte[] read(long offset, int length) {
            check(offset >= 0 && offset <= bytes.length && length >= 0 && length <= bytes.length - offset, "bounded source read");
            reads++; total += length; largest = Math.max(largest, length);
            return Arrays.copyOfRange(bytes, (int) offset, (int) offset + length);
        }
    }
    private static byte[] mask() { byte[] value = new byte[32]; new Random(9182).nextBytes(value); return value; }
    private static byte[] ini(String field, String text, byte[] key) throws Exception {
        return ini(field, text, key, 0x4502, text.length());
    }
    private static byte[] ini(String field, String text, byte[] key, int magic, int declaredLength) throws Exception {
        byte[] plain = new byte[(text.length() + 6 + 15) & ~15];
        put16(plain, 0, magic); put32(plain, 2, declaredLength);
        for (int i = 0; i < text.length(); i++) plain[6 + i] = (byte) (text.charAt(i) - 1);
        Mac hmac = Mac.getInstance("HmacSHA1"); hmac.init(new SecretKeySpec(key, "HmacSHA1"));
        byte[] tag = hmac.doFinal(plain), aes = key.clone();
        for (int i = 0; i < aes.length; i++) aes[i] ^= tag[i % tag.length];
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding"); cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aes, "AES"));
        byte[] encrypted = cipher.doFinal(plain), envelope = new byte[tag.length + encrypted.length];
        System.arraycopy(tag, 0, envelope, 0, tag.length); System.arraycopy(encrypted, 0, envelope, tag.length, encrypted.length);
        Arrays.fill(aes, (byte) 0); Arrays.fill(plain, (byte) 0);
        return ("[Envelope]\n" + field + "=" + Base64.getEncoder().encodeToString(envelope) + "\n").getBytes(StandardCharsets.US_ASCII);
    }
    private static byte[][] configs(byte[] mask) throws Exception {
        byte[] gameplay = ini("Hash", "0123456789abcdef0123456789abcdef01234567", mask);
        byte[] key = ConfigCrypto.deriveKey(mask, gameplay);
        try { return new byte[][]{gameplay, ini("Token", "[DFMPerfGearConfig]\nDFMQualityLevel=2\n", key)}; }
        finally { Arrays.fill(key, (byte) 0); }
    }
    private static void put16(byte[] b, int at, int n) { b[at] = (byte) n; b[at + 1] = (byte) (n >>> 8); }
    private static void put32(byte[] b, int at, int n) { for (int i = 0; i < 4; i++) b[at + i] = (byte) (n >>> (i * 8)); }
    private static void put64(byte[] b, int at, long n) { for (int i = 0; i < 8; i++) b[at + i] = (byte) (n >>> (i * 8)); }
    private static void program(byte[] b, int index, int flags, long offset, long va, long size) {
        int at = 64 + index * 56;
        put32(b, at, 1); put32(b, at + 4, flags); put64(b, at + 8, offset); put64(b, at + 16, va);
        put64(b, at + 32, size); put64(b, at + 40, size); put64(b, at + 48, 4096);
    }
    private static byte[] elf(int length, int codeOffset, int codeSize, int dataOffset, int dataSize) {
        byte[] bytes = new byte[length]; bytes[0] = 0x7f; bytes[1] = 'E'; bytes[2] = 'L'; bytes[3] = 'F';
        bytes[4] = 2; bytes[5] = 1; bytes[6] = 1;
        put16(bytes, 16, 3); put16(bytes, 18, 183); put32(bytes, 20, 1); put64(bytes, 32, 64);
        put16(bytes, 52, 64); put16(bytes, 54, 56); put16(bytes, 56, 2);
        program(bytes, 0, 5, codeOffset, CODE_VA, codeSize);
        program(bytes, 1, 4, dataOffset, DATA_VA, dataSize);
        return bytes;
    }
    private static int adrp(int register, long pc, long address) {
        long pages = ((address & ~4095L) - (pc & ~4095L)) >> 12;
        long immediate = pages & 0x1fffff;
        return 0x90000000 | (int) ((immediate & 3) << 29) | (int) ((immediate >>> 2) << 5) | register;
    }
    private static int ldr(int q, int base, long address) { return 0x3dc00000 | ((int) (address & 4095) / 16 << 10) | (base << 5) | q; }
    private static void structure(byte[] bytes, int file, long pc, long first, long second, int codeXor, boolean interleaved, boolean reverse) {
        int[] words = interleaved
                ? new int[]{adrp(9, pc, first), ldr(0, 9, first), adrp(10, pc + 8, second), ldr(1, 10, second)}
                : new int[]{adrp(9, pc, first), adrp(10, pc + 4, second), ldr(0, 9, first), ldr(1, 10, second)};
        for (int i = 0; i < 4; i++) put32(bytes, file + i * 4, words[i] ^ codeXor);
        put32(bytes, file + 16, 0x52800029 ^ codeXor); // mov w9,#1
        put32(bytes, file + 20, (0x39000000 | (7 << 5) | 9) ^ codeXor);
        put32(bytes, file + 24, (0xad000000 | (20 << 5) | ((reverse ? 0 : 1) << 10) | (reverse ? 1 : 0)) ^ codeXor);
        put32(bytes, file + 28, (0x14000000 | ((-88 >> 2) & 0x03ffffff)) ^ codeXor);
    }
    private static void material(byte[] bytes, int first, int second, byte[] mask, int dataXor, boolean reverse) {
        for (int i = 0; i < 16; i++) {
            bytes[first + i] = (byte) (mask[(reverse ? 16 : 0) + i] ^ dataXor);
            bytes[second + i] = (byte) (mask[(reverse ? 0 : 16) + i] ^ dataXor);
        }
    }
    private static byte[] sample(int codeXor, int dataXor, boolean interleaved, boolean reverse) {
        byte[] bytes = elf(0x10000, 0x1000, 0x2000, 0x8000, 0x1000);
        structure(bytes, 0x1100, CODE_VA + 0x100, DATA_VA + 0x10, DATA_VA + 0x40, codeXor, interleaved, reverse);
        material(bytes, 0x8010, 0x8040, mask(), dataXor, reverse);
        return bytes;
    }
    private static void synthetic() throws Exception {
        byte[][] config = configs(mask());
        int[] encodings = ConfigCrypto.materialEncodingCandidates();
        check(encodings.length == 256, "every byte encoding is covered");
        check(encodings[0] == 0xe2 && encodings[1] == 0 && encodings[2] == 0x10, "known encodings are attempted first");
        boolean[] seen = new boolean[256];
        for (int encoding : encodings) {
            check(encoding >= 0 && encoding <= 255 && !seen[encoding], "encoding values are unique and bounded");
            seen[encoding] = true;
        }
        encodings[0] = -1;
        check(ConfigCrypto.materialEncodingCandidates()[0] == 0xe2, "encoding order cannot be mutated by callers");
        byte[] hashToken = ConfigCrypto.getField(config[0], "Hash"), tokenCopy = hashToken.clone();
        byte[] keyFromIni = null, keyFromToken = null;
        try {
            keyFromIni = ConfigCrypto.deriveKey(mask(), config[0]);
            keyFromToken = ConfigCrypto.deriveKeyFromHash(mask(), hashToken);
            check(Arrays.equals(keyFromIni, keyFromToken), "pre-extracted Hash derives the same authenticated key");
            check(Arrays.equals(hashToken, tokenCopy), "borrowed Hash token is not modified by derivation");
        } finally {
            Arrays.fill(hashToken, (byte) 0); Arrays.fill(tokenCopy, (byte) 0);
            if (keyFromIni != null) Arrays.fill(keyFromIni, (byte) 0);
            if (keyFromToken != null) Arrays.fill(keyFromToken, (byte) 0);
        }
        for (int cx : new int[]{0, XOR}) for (int dx : new int[]{0, 0xe2, 0x10}) for (boolean interleave : new boolean[]{false, true}) for (boolean reverse : new boolean[]{false, true}) {
            Bytes source = new Bytes(sample(cx, dx, interleave, reverse));
            LibraryMaskResolver.Result result = LibraryMaskResolver.resolve(source, config[0], config[1]);
            check(Arrays.equals(mask(), result.mask), "relocated authenticated material, independent code/data encoding");
            check(result.firstOffset == (reverse ? 0x8040 : 0x8010), "STP register ordering determines first half");
            check(result.description.contains("双重认证"), "read mode requires both authentication checks");
            check(result.materialEncoding == dx && result.codeEncoding == (cx & 255), "successful encoding metadata is recorded");
            check(source.largest <= LibraryMaskResolver.READ_BLOCK_BYTES, "read block bounded");
            Arrays.fill(result.mask, (byte) 0);
        }
        // An odd affine permutation covers every code and every data byte independently,
        // including values not present in either of the real baseline libraries.
        for (int cx = 0; cx < 256; cx++) {
            int dx = (cx * 73 + 19) & 255;
            boolean reverse = (cx & 2) != 0;
            Bytes source = new Bytes(sample(cx * 0x01010101, dx, (cx & 1) != 0, reverse));
            LibraryMaskResolver.Result result = LibraryMaskResolver.resolveByCode(source, config[0], config[1]);
            check(Arrays.equals(mask(), result.mask), "all code/data byte encodings require authenticated material");
            check(result.materialEncoding == dx && result.codeEncoding == cx, "all inferred byte encodings are identified exactly");
            check(result.firstOffset == (reverse ? 0x8040 : 0x8010), "all byte encodings preserve STP ordering");
            check(source.largest <= LibraryMaskResolver.READ_BLOCK_BYTES, "all encodings preserve bounded reads");
            Arrays.fill(result.mask, (byte) 0);
        }
        Bytes restored = new Bytes(sample(0x6a6a6a6a, 0x91, false, false));
        LibraryMaskResolver.Result hashOnly = LibraryMaskResolver.resolve(restored, config[0], null);
        check(Arrays.equals(mask(), hashOnly.mask), "explicit restore context accepts authenticated Hash without current Engine");
        check(hashOnly.description.contains("Hash 认证通过"), "Hash-only result is identified");
        byte[] wrong = mask(); wrong[0] ^= 19;
        byte[][] mismatched = configs(wrong);
        rejects(() -> LibraryMaskResolver.resolve(new Bytes(sample(0, 0, false, false)), mismatched[0], config[1]), "wrong Hash rejected");
        rejects(() -> LibraryMaskResolver.resolve(new Bytes(sample(0, 0, false, false)), config[0], mismatched[1]), "Hash valid and Engine wrong rejected");
        rejects(() -> LibraryMaskResolver.resolve(new Bytes(sample(0, 0x10, false, false)), mismatched[0], config[1]), "XOR 0x10 data still rejects wrong Hash");
        rejectsContaining(() -> LibraryMaskResolver.resolve(new Bytes(sample(0x73737373, 0x91, false, false)), config[0], mismatched[1]),
                "UserGameplay 认证已匹配，但 Engine HMAC 不匹配", "arbitrary encoding retains precise paired Engine mismatch");
        byte[] corrupt = sample(0x55555555, 0x55, false, false); corrupt[0x8013] ^= 1;
        rejects(() -> LibraryMaskResolver.resolve(new Bytes(corrupt), config[0], config[1]), "nonuniform damaged material cannot be authorized by encoding search");
        rejects(() -> LibraryMaskResolver.resolve(new Bytes(sample(0, 0, false, false)), new byte[0], config[1]), "missing Hash rejected before scan");

        byte[] largeEnvelope = new byte[20 + 256 * 1024];
        byte[] largeHash = ("Hash=" + Base64.getEncoder().encodeToString(largeEnvelope) + "\n").getBytes(StandardCharsets.US_ASCII);
        rejectsContaining(() -> LibraryMaskResolver.resolveByCode(new Bytes(sample(0x55555555, 0x55, false, false)), largeHash, config[1]),
                "64 MiB", "large unauthenticated Hash exhausts total candidate calculation budget");

        byte[] changedHashHeader = ini("Hash", "0123456789abcdef0123456789abcdef01234567", mask(), 0x4503, 40);
        rejectsAuthenticatedFormat(() -> LibraryMaskResolver.resolveByCode(new Bytes(sample(0, 0x10, false, false)), changedHashHeader, config[1]),
                "UserGameplay Hash 认证通过", "authenticated changed Hash header is reported instead of HMAC mismatch");
        byte[] changedHashLength = ini("Hash", "0123456789abcdef0123456789abcdef01234567", mask(), 0x4502, 4096);
        rejectsAuthenticatedFormat(() -> LibraryMaskResolver.resolveByCode(new Bytes(sample(0, 0x10, false, false)), changedHashLength, config[1]),
                "UserGameplay Hash 认证通过", "authenticated changed Hash length is reported precisely");
        byte[] changedDigest = ini("Hash", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", mask());
        rejectsAuthenticatedFormat(() -> LibraryMaskResolver.resolveByCode(new Bytes(sample(0, 0x10, false, false)), changedDigest, config[1]),
                "40 位十六进制", "authenticated changed digest format is reported instead of HMAC mismatch");
        byte[] pairedKey = ConfigCrypto.deriveKey(mask(), config[0]);
        try {
            byte[] changedEngineHeader = ini("Token", "[Config]\n", pairedKey, 0x4503, 9);
            rejectsAuthenticatedFormat(() -> LibraryMaskResolver.resolveByCode(new Bytes(sample(0, 0x10, false, false)), config[0], changedEngineHeader),
                    "Engine 认证通过", "authenticated changed Engine header retains format-specific error");
        } finally { Arrays.fill(pairedKey, (byte) 0); }

        byte[] largeWrapper = Arrays.copyOf(config[0], 1024 * 1024);
        Arrays.fill(largeWrapper, config[0].length, largeWrapper.length, (byte) ';');
        LibraryMaskResolver.Result wrapperResult = LibraryMaskResolver.resolveByCode(new Bytes(sample(0x8d8d8d8d, 0xff, false, false)), largeWrapper, config[1]);
        check(Arrays.equals(mask(), wrapperResult.mask), "large unrelated wrapper does not inflate repeated Hash verification input");
        Arrays.fill(wrapperResult.mask, (byte) 0);

        byte[] split = elf(0x150000, 0x1000, LibraryMaskResolver.READ_BLOCK_BYTES + 0x2000, 0x130000, 0x1000);
        int splitPosition = 0x1000 + LibraryMaskResolver.READ_BLOCK_BYTES - 12;
        structure(split, splitPosition, CODE_VA + LibraryMaskResolver.READ_BLOCK_BYTES - 12, DATA_VA + 0x10, DATA_VA + 0x40, XOR, false, false);
        material(split, 0x130010, 0x130040, mask(), 0xe2, false);
        check(Arrays.equals(mask(), LibraryMaskResolver.resolveByCode(new Bytes(split), config[0], config[1]).mask), "pattern across block boundary");

        byte[] duplicate = sample(0, 0, false, false);
        structure(duplicate, 0x1200, CODE_VA + 0x200, DATA_VA + 0x210, DATA_VA + 0x240, 0, true, false);
        material(duplicate, 0x8210, 0x8240, mask(), 0xe2, false);
        check(Arrays.equals(mask(), LibraryMaskResolver.resolveByCode(new Bytes(duplicate), config[0], config[1]).mask), "identical authenticated material from duplicate code deduplicated");

        byte[] ambiguous = sample(0, 0, false, false); put16(ambiguous, 56, 3); program(ambiguous, 2, 4, 0xa000, DATA_VA, 0x1000);
        rejects(() -> LibraryMaskResolver.resolveByCode(new Bytes(ambiguous), config[0], config[1]), "ambiguous VA mappings rejected");
        byte[] writable = sample(0, 0, false, false); put32(writable, 64 + 56 + 4, 6);
        rejects(() -> LibraryMaskResolver.resolveByCode(new Bytes(writable), config[0], config[1]), "material in writable segment not trusted");
        byte[] absent = sample(0, 0, false, false); absent[0x1110] = 0;
        rejects(() -> LibraryMaskResolver.resolve(new Bytes(absent), config[0], config[1]), "unknown instruction idiom rejected");
        byte[] malformed = sample(0, 0, false, false); malformed[18] = 40;
        rejects(() -> LibraryMaskResolver.resolve(new Bytes(malformed), config[0], config[1]), "non ARM64 rejected");
        byte[] endian = sample(0, 0, false, false); endian[5] = 2;
        rejects(() -> LibraryMaskResolver.resolve(new Bytes(endian), config[0], config[1]), "big-endian rejected");
        byte[] overflow = sample(0, 0, false, false); put64(overflow, 64 + 16, Long.MAX_VALUE - 3);
        rejects(() -> LibraryMaskResolver.resolve(new Bytes(overflow), config[0], config[1]), "VA overflow rejected");
        byte[] pastEnd = sample(0, 0, false, false); put64(pastEnd, 64 + 8, 0xffff);
        rejects(() -> LibraryMaskResolver.resolve(new Bytes(pastEnd), config[0], config[1]), "LOAD beyond file rejected");
        byte[] badPh = sample(0, 0, false, false); put64(badPh, 32, 0xffff);
        rejects(() -> LibraryMaskResolver.resolve(new Bytes(badPh), config[0], config[1]), "program table truncated rejected");
        LibraryMaskResolver.Source shortRead = new LibraryMaskResolver.Source() {
            public long length() { return 0x10000; }
            public byte[] read(long o, int n) { return new byte[Math.max(0, n - 1)]; }
        };
        rejects(() -> LibraryMaskResolver.resolve(shortRead, config[0], config[1]), "short Source reads rejected");

        byte[] many = elf(0x12000, 0x1000, 0x3000, 0x8000, 0x3000);
        for (int i = 0; i < 65; i++) structure(many, 0x1100 + i * 32, CODE_VA + 0x100 + i * 32, DATA_VA + i * 32, DATA_VA + i * 32 + 16, 0, false, false);
        rejects(() -> LibraryMaskResolver.resolveByCode(new Bytes(many), config[0], config[1]), "candidate cap rejects excessive structure matches");
        final byte[] largeHeader = elf(0x1000, 0, 0x1000, 0, 0x1000);
        put64(largeHeader, 64 + 32, 600L * 1024 * 1024); put64(largeHeader, 64 + 40, 600L * 1024 * 1024);
        LibraryMaskResolver.Source large = new LibraryMaskResolver.Source() {
            public long length() { return 700L * 1024 * 1024; }
            public byte[] read(long o, int n) { if (o + n > largeHeader.length) throw new AssertionError("scan limit must be checked before code reads"); return Arrays.copyOfRange(largeHeader, (int)o, (int)o + n); }
        };
        rejects(() -> LibraryMaskResolver.resolveByCode(large, config[0], config[1]), "512 MiB scan bound before large reads");

        byte[] legacy = elf(0x1800000, 0x1000, 0x2000, 0x1700000, 0x50000);
        material(legacy, 0x171e1b0, 0x17416f0, mask(), 0xe2, false);
        Bytes quick = new Bytes(legacy);
        LibraryMaskResolver.Result shortcut = LibraryMaskResolver.resolve(quick, config[0], config[1]);
        check(Arrays.equals(mask(), shortcut.mask) && shortcut.description.contains("兼容区段"), "legacy shortcut still authenticates");
        check(shortcut.materialEncoding == 0xe2 && shortcut.codeEncoding == -1, "legacy shortcut does not claim code encoding evidence");
        check(quick.total < 2048, "legacy shortcut does not scan full library or seek section table");
        byte[] moved = Arrays.copyOf(legacy, legacy.length);
        Arrays.fill(moved, 0x171e1b0, 0x171e1b0 + 16, (byte) 0); Arrays.fill(moved, 0x17416f0, 0x17416f0 + 16, (byte) 0);
        structure(moved, 0x1100, CODE_VA + 0x100, DATA_VA + 0x10, DATA_VA + 0x40, XOR, false, false);
        material(moved, 0x1700010, 0x1700040, mask(), 0xe2, false);
        LibraryMaskResolver.Result recovered = LibraryMaskResolver.resolve(new Bytes(moved), config[0], config[1]);
        check(recovered.firstOffset == 0x1700010 && Arrays.equals(mask(), recovered.mask), "wrong fixed offsets continue to relocation");
    }

    private static void real(String library, String fixture) throws Exception {
        byte[] engine, gameplay;
        try (ZipFile zip = new ZipFile(fixture)) {
            engine = readEntry(zip, "1/Engine.ini"); gameplay = readEntry(zip, "1/UserGameplay.ini");
        }
        final long[] bytesRead = {0};
        try (final RandomAccessFile file = new RandomAccessFile(library, "r")) {
            LibraryMaskResolver.Source source = new LibraryMaskResolver.Source() {
                public long length() throws Exception { return file.length(); }
                public boolean efficientRandomAccess() { return true; }
                public byte[] read(long offset, int size) throws Exception {
                    check(size <= LibraryMaskResolver.READ_BLOCK_BYTES, "real read block bounded");
                    file.seek(offset); byte[] bytes = new byte[size]; file.readFully(bytes); bytesRead[0] += size; return bytes;
                }
            };
            LibraryMaskResolver.Result legacy = LibraryMaskResolver.resolve(source, gameplay, engine);
            long before = bytesRead[0], start = System.nanoTime();
            LibraryMaskResolver.Result relocated = LibraryMaskResolver.resolveByCode(source, gameplay, engine);
            check(Arrays.equals(legacy.mask, relocated.mask), "real private fixture forced structural scan equals authenticated fixed path");
            check(relocated.firstOffset == legacy.firstOffset && relocated.secondOffset == legacy.secondOffset, "real structural addresses equal known valid old offsets");
            System.out.println("Private fixture forced code scan passed; scanned MiB=" + ((bytesRead[0] - before) / (1024 * 1024)) + "; elapsed ms=" + ((System.nanoTime() - start) / 1000000));
            Arrays.fill(legacy.mask, (byte) 0); Arrays.fill(relocated.mask, (byte) 0);
        }
    }
    private static byte[] readEntry(ZipFile zip, String name) throws Exception {
        try (java.io.InputStream in = zip.getInputStream(zip.getEntry(name)); java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192]; int n; while ((n = in.read(buffer)) >= 0) out.write(buffer, 0, n); return out.toByteArray();
        }
    }
    public static void main(String[] args) throws Exception {
        synthetic();
        if (args.length == 2) real(args[0], args[1]);
        else if (args.length != 0) throw new IllegalArgumentException("Use no arguments, or explicit <library> <fixture ZIP>");
        System.out.println("Library mask resolver checks passed: " + assertions);
    }
}
