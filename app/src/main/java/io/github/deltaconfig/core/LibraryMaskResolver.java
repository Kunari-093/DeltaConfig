package io.github.deltaconfig.core;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Bounded, read-only ARM64 ELF configuration-material discovery.
 * A code match is only a candidate: authenticated configuration validation is mandatory.
 * This recognizes a compiler idiom, rather than claiming every future format is supported.
 */
public final class LibraryMaskResolver {
    public interface Source {
        long length() throws Exception;
        byte[] read(long offset, int length) throws Exception;
        /** A ZIP stream leaves this false, avoiding an expensive seek to an end-of-file section table. */
        default boolean efficientRandomAccess() { return false; }
    }

    public static final class Result {
        public final byte[] mask;
        public final String description;
        public final long firstOffset, secondOffset;
        /** Non-secret storage encodings; codeEncoding is -1 for the legacy offset shortcut. */
        public final int materialEncoding, codeEncoding;
        private Result(byte[] mask, String description, long firstOffset, long secondOffset,
                       int materialEncoding, int codeEncoding) {
            this.mask = mask.clone(); this.description = description;
            this.firstOffset = firstOffset; this.secondOffset = secondOffset;
            this.materialEncoding = materialEncoding; this.codeEncoding = codeEncoding;
        }
    }

    public static final int READ_BLOCK_BYTES = 1024 * 1024;
    private static final long LEGACY_FIRST = 0x171e1b0L, LEGACY_SECOND = 0x17416f0L;
    private static final long MAX_SCAN_BYTES = 512L * 1024 * 1024;
    private static final int MAX_CANDIDATES = 64, MAX_TABLE_ENTRIES = 1024;
    private LibraryMaskResolver() { }

    public static Result resolve(Source source, byte[] gameplay, byte[] engine) throws Exception {
        return resolve(source, gameplay, engine, true);
    }

    /** Always scan code. Useful for checking relocation without using the legacy shortcut. */
    public static Result resolveByCode(Source source, byte[] gameplay, byte[] engine) throws Exception {
        return resolve(source, gameplay, engine, false);
    }

    private static Result resolve(Source source, byte[] gameplay, byte[] engine, boolean legacy) throws Exception {
        if (source == null || gameplay == null) throw new IllegalArgumentException("缺少游戏库或认证配置");
        // Validate INI envelope fields before a potentially expensive library scan.
        byte[] hashField = ConfigCrypto.getField(gameplay, "Hash");
        try {
            if (engine != null) {
                byte[] token = ConfigCrypto.getField(engine, "Token");
                Arrays.fill(token, (byte) 0);
            }
            return resolveWithHash(source, hashField, engine, legacy);
        } finally { Arrays.fill(hashField, (byte) 0); }
    }

    private static Result resolveWithHash(Source source, byte[] hashField, byte[] engine,
                                          boolean legacy) throws Exception {
        AuthenticationBudget authentication = new AuthenticationBudget(hashField.length);
        Reader reader = new Reader(source);
        Elf elf = Elf.parse(reader);
        if (legacy && range(LEGACY_FIRST, 16, reader.length) && range(LEGACY_SECOND, 16, reader.length)) {
            byte[] combined = join(reader.read(LEGACY_FIRST, 16), reader.read(LEGACY_SECOND, 16));
            try {
                Result result = authenticate(combined, hashField, engine, LEGACY_FIRST, LEGACY_SECOND,
                        "已认证的兼容区段", -1, authentication);
                if (result != null) return result;
            } finally { Arrays.fill(combined, (byte) 0); }
        }
        List<Candidate> candidates = discover(reader, elf);
        if (candidates.isEmpty()) throw new GeneralSecurityException("认证算法或游戏库布局未识别：未找到受支持的 ARM64 材料装载结构");
        // Read every data offset monotonically after scanning, so a ZIP source need only rewind once.
        TreeMap<Long, byte[]> data = new TreeMap<Long, byte[]>();
        for (Candidate candidate : candidates) { data.put(candidate.first, null); data.put(candidate.second, null); }
        Result selected = null;
        boolean returned = false;
        try {
            for (Map.Entry<Long, byte[]> entry : data.entrySet()) entry.setValue(reader.read(entry.getKey(), 16));
            for (Candidate candidate : candidates) {
                byte[] combined = join(data.get(candidate.first), data.get(candidate.second));
                try {
                    Result result = authenticate(combined, hashField, engine, candidate.first, candidate.second,
                            "ELF ARM64 指令重定位（" + encodingDescription(candidate.xor & 255) + "）",
                            candidate.xor & 255, authentication);
                    if (result == null) continue;
                    if (selected != null) {
                        boolean equal = MessageDigest.isEqual(selected.mask, result.mask);
                        Arrays.fill(result.mask, (byte) 0);
                        if (!equal) {
                            Arrays.fill(selected.mask, (byte) 0);
                            throw new GeneralSecurityException("认证材料存在歧义：多个不同候选通过认证，已停止操作");
                        }
                    } else selected = result;
                } finally { Arrays.fill(combined, (byte) 0); }
            }
            if (selected == null) throw new GeneralSecurityException("已定位 ARM64 候选，但配置 HMAC 未匹配；请核对同设备配套配置及游戏库");
            returned = true;
            return selected;
        } finally {
            for (byte[] value : data.values()) if (value != null) Arrays.fill(value, (byte) 0);
            if (!returned && selected != null) Arrays.fill(selected.mask, (byte) 0);
        }
    }

    private static Result authenticate(byte[] stored, byte[] hashToken, byte[] engine, long first,
                                      long second, String description, int codeEncoding,
                                      AuthenticationBudget authentication) throws Exception {
        // Code and data encodings are independent. Trying a storage encoding does
        // not authorize it: Hash and (except explicit restore mode) Engine must match.
        for (int transform : ConfigCrypto.materialEncodingCandidates()) {
            authentication.consume();
            byte[] mask = stored.clone(), key = null;
            for (int i = 0; i < mask.length; i++) mask[i] ^= (byte) transform;
            try {
                try { key = ConfigCrypto.deriveKeyFromHash(mask, hashToken); }
                catch (ConfigCrypto.AuthenticatedFormatException changed) {
                    throw new ConfigCrypto.AuthenticatedFormatException("UserGameplay Hash 认证通过，但配置协议发生变化：" + changed.getMessage(), changed);
                }
                catch (GeneralSecurityException | IllegalArgumentException mismatch) { continue; }
                if (engine != null) {
                    try { ConfigCrypto.decodeIni(engine, key); }
                    catch (ConfigCrypto.AuthenticatedFormatException changed) {
                        throw new ConfigCrypto.AuthenticatedFormatException("Engine 认证通过，但配置协议发生变化：" + changed.getMessage(), changed);
                    }
                    catch (GeneralSecurityException | IllegalArgumentException mismatch) {
                        throw new GeneralSecurityException("UserGameplay 认证已匹配，但 Engine HMAC 不匹配；请核对本机配套配置", mismatch);
                    }
                }
                return new Result(mask, description + "；材料" + encodingDescription(transform) + "；"
                        + (engine == null ? "Hash 认证通过" : "Hash 与 Engine 双重认证通过"),
                        first, second, transform, codeEncoding);
            } finally {
                Arrays.fill(mask, (byte) 0);
                if (key != null) Arrays.fill(key, (byte) 0);
            }
        }
        return null;
    }

    private static String encodingDescription(int encoding) {
        return encoding == 0 ? "原始编码" : "单字节 XOR 0x" + Integer.toHexString(encoding);
    }

    private static final class AuthenticationBudget {
        final int fieldBytes; long remaining = ConfigCrypto.MAX_MATERIAL_AUTH_BYTES;
        AuthenticationBudget(int fieldBytes) { this.fieldBytes = fieldBytes; }
        void consume() throws IOException {
            if (fieldBytes > remaining)
                throw new ConfigCrypto.MaterialAuthenticationBudgetException("配置认证候选计算超过 64 MiB 预算，已停止自动识别");
            remaining -= fieldBytes;
        }
    }

    private static List<Candidate> discover(Reader reader, Elf elf) throws Exception {
        elf.prepareCode(reader);
        long total = 0;
        for (Region region : elf.code) {
            if (region.size > MAX_SCAN_BYTES - total) throw new IOException("游戏库可执行区域超过自动识别的 512 MiB 扫描上限");
            total += region.size;
        }
        LinkedHashMap<String, Candidate> found = new LinkedHashMap<String, Candidate>();
        for (Region region : elf.code) {
            byte[] carry = new byte[0];
            long consumed = 0;
            while (consumed < region.size) {
                int amount = (int) Math.min(READ_BLOCK_BYTES, region.size - consumed);
                byte[] block = reader.read(region.offset + consumed, amount);
                byte[] bytes = new byte[carry.length + block.length];
                System.arraycopy(carry, 0, bytes, 0, carry.length);
                System.arraycopy(block, 0, bytes, carry.length, block.length);
                long relative = consumed - carry.length;
                int start = (int) ((4 - ((region.address + relative) & 3)) & 3);
                for (int at = start; at + 32 <= bytes.length; at += 4) {
                    int marker = int32(bytes, at + 16);
                    // mov wN,#1 has fixed high bytes. Infer the uniform storage XOR
                    // from the high byte, then verify the full marker and strict idiom.
                    int encodingByte = (marker >>> 24) ^ 0x52;
                    int encoding = encodingByte * 0x01010101;
                    if (((marker ^ encoding) & 0xffffffe0) != 0x52800020) continue;
                    Candidate candidate = candidate(bytes, at, region.address + relative + at, encoding, elf);
                    if (candidate != null) {
                        String identity = candidate.first + ":" + candidate.second;
                        found.put(identity, candidate);
                        if (found.size() > MAX_CANDIDATES) throw new IOException("游戏库结构候选超过 64 个，布局存在歧义；已停止自动识别");
                    }
                }
                int retained = Math.min(28, bytes.length);
                carry = Arrays.copyOfRange(bytes, bytes.length - retained, bytes.length);
                consumed += amount;
            }
        }
        return new ArrayList<Candidate>(found.values());
    }

    private static Candidate candidate(byte[] bytes, int at, long pc, int xor, Elf elf) throws IOException {
        int a = int32(bytes, at) ^ xor, b = int32(bytes, at + 4) ^ xor;
        int c = int32(bytes, at + 8) ^ xor, d = int32(bytes, at + 12) ^ xor;
        int mov = int32(bytes, at + 16) ^ xor, store = int32(bytes, at + 20) ^ xor;
        int pair = int32(bytes, at + 24) ^ xor, branch = int32(bytes, at + 28) ^ xor;
        int adrpA, adrpB, loadA, loadB; long pcA, pcB;
        if (adrp(a) && adrp(b) && loadQ(c) && loadQ(d)) {
            adrpA = a; adrpB = b; loadA = c; loadB = d; pcA = pc; pcB = pc + 4;
        } else if (adrp(a) && loadQ(b) && adrp(c) && loadQ(d)) {
            adrpA = a; adrpB = c; loadA = b; loadB = d; pcA = pc; pcB = pc + 8;
        } else return null;
        if (((loadA >>> 5) & 31) != (adrpA & 31) || ((loadB >>> 5) & 31) != (adrpB & 31)) return null;
        if ((mov & 0xffffffe0) != 0x52800020 || (store & 0xffc00000) != 0x39000000 || (store & 31) != (mov & 31)) return null;
        if ((pair & 0xffc00000) != 0xad000000 || (branch & 0xfc000000) != 0x14000000) return null;
        int qa = loadA & 31, qb = loadB & 31, firstQ = pair & 31, secondQ = (pair >>> 10) & 31;
        if (qa == qb || !((firstQ == qa && secondQ == qb) || (firstQ == qb && secondQ == qa))) return null;
        long backwards = signExtend(branch & 0x03ffffffL, 26) << 2;
        if (backwards >= 0 || backwards < -4096) return null;
        long targetA = add(adprAddress(adrpA, pcA), ((loadA >>> 10) & 4095) * 16L);
        long targetB = add(adprAddress(adrpB, pcB), ((loadB >>> 10) & 4095) * 16L);
        long fileA = elf.dataOffset(targetA, 16), fileB = elf.dataOffset(targetB, 16);
        if (fileA < 0 || fileB < 0) return null;
        return firstQ == qa ? new Candidate(fileA, fileB, xor) : new Candidate(fileB, fileA, xor);
    }

    private static boolean adrp(int word) { return (word & 0x9f000000) == 0x90000000; }
    private static boolean loadQ(int word) { return (word & 0xffc00000) == 0x3dc00000; }
    private static long adprAddress(int word, long pc) throws IOException {
        long immediate = ((word >>> 29) & 3) | (((word >>> 5) & 0x7ffffL) << 2);
        return add(pc & ~4095L, signExtend(immediate, 21) << 12);
    }
    private static long signExtend(long value, int bits) { return (value << (64 - bits)) >> (64 - bits); }
    private static byte[] join(byte[] a, byte[] b) {
        byte[] result = new byte[32]; System.arraycopy(a, 0, result, 0, 16); System.arraycopy(b, 0, result, 16, 16); return result;
    }
    private static boolean range(long offset, long size, long length) { return offset >= 0 && size >= 0 && offset <= length && size <= length - offset; }
    private static long add(long a, long b) throws IOException {
        try { long value = Math.addExact(a, b); if (value < 0) throw new ArithmeticException(); return value; }
        catch (ArithmeticException overflow) { throw new IOException("ELF 地址计算越界", overflow); }
    }
    private static int int32(byte[] bytes, int offset) { return (bytes[offset] & 255) | ((bytes[offset + 1] & 255) << 8) | ((bytes[offset + 2] & 255) << 16) | ((bytes[offset + 3] & 255) << 24); }
    private static long u32(byte[] bytes, int offset) { return int32(bytes, offset) & 0xffffffffL; }
    private static int u16(byte[] bytes, int offset) { return (bytes[offset] & 255) | ((bytes[offset + 1] & 255) << 8); }
    private static long u64(byte[] bytes, int offset) throws IOException {
        long value = u32(bytes, offset) | (u32(bytes, offset + 4) << 32);
        if (value < 0) throw new IOException("ELF 使用了超出支持范围的 64 位地址");
        return value;
    }

    private static final class Reader {
        final Source source; final long length;
        Reader(Source source) throws Exception {
            this.source = source; length = source.length();
            if (length < 64 || length > 8L * 1024 * 1024 * 1024) throw new IOException("游戏库长度超出 64 字节至 8 GiB 支持范围");
        }
        byte[] read(long offset, int size) throws Exception {
            if (size > READ_BLOCK_BYTES || !range(offset, size, length)) throw new IOException("ELF 读取范围越界");
            byte[] result = source.read(offset, size);
            if (result == null || result.length != size) throw new IOException("游戏库读取被截断或返回长度不一致");
            return result;
        }
    }

    private static final class Candidate {
        final long first, second; final int xor;
        Candidate(long first, long second, int xor) { this.first = first; this.second = second; this.xor = xor; }
    }
    private static final class Region {
        final long offset, address, size; final int flags;
        Region(long offset, long address, long size, int flags) { this.offset = offset; this.address = address; this.size = size; this.flags = flags; }
    }
    private static final class Elf {
        final List<Region> loads = new ArrayList<Region>(), code = new ArrayList<Region>();
        long sectionOffset; int sectionSize, sectionCount;
        static Elf parse(Reader reader) throws Exception {
            byte[] header = reader.read(0, 64);
            if (header[0] != 0x7f || header[1] != 'E' || header[2] != 'L' || header[3] != 'F'
                    || header[4] != 2 || header[5] != 1 || header[6] != 1 || u16(header, 18) != 183
                    || (u16(header, 16) != 3 && u16(header, 16) != 2) || u32(header, 20) != 1 || u16(header, 52) < 64)
                throw new IOException("游戏库不是受支持的 little-endian ELF64 ARM64 文件");
            long phoff = u64(header, 32); int phsize = u16(header, 54), phnum = u16(header, 56);
            if (phnum == 0 || phnum > MAX_TABLE_ENTRIES || phsize < 56 || phsize > 256 || !range(phoff, (long) phsize * phnum, reader.length))
                throw new IOException("ELF 程序头无效或越界");
            Elf elf = new Elf();
            byte[] programs = reader.read(phoff, phsize * phnum);
            for (int i = 0; i < phnum; i++) {
                int at = i * phsize;
                if (u32(programs, at) != 1) continue;
                long offset = u64(programs, at + 8), address = u64(programs, at + 16);
                long size = u64(programs, at + 32), memorySize = u64(programs, at + 40);
                if (size > memorySize || !range(offset, size, reader.length)) throw new IOException("ELF LOAD 区域无效或越界");
                add(address, memorySize);
                elf.loads.add(new Region(offset, address, size, int32(programs, at + 4)));
            }
            if (elf.loads.isEmpty()) throw new IOException("ELF 没有可读取的 LOAD 区域");
            elf.sectionOffset = u64(header, 40); elf.sectionSize = u16(header, 58); elf.sectionCount = u16(header, 60);
            if (elf.sectionOffset != 0 || elf.sectionCount != 0) {
                if (elf.sectionCount == 0 || elf.sectionCount > MAX_TABLE_ENTRIES || elf.sectionSize < 64 || elf.sectionSize > 256 || !range(elf.sectionOffset, (long) elf.sectionSize * elf.sectionCount, reader.length))
                    throw new IOException("ELF 节表无效或越界");
            }
            boolean executable = false;
            for (Region load : elf.loads) executable |= (load.flags & 1) != 0 && load.size > 0;
            if (!executable) throw new IOException("ELF 没有可执行区域");
            return elf;
        }
        void prepareCode(Reader reader) throws Exception {
            if (!code.isEmpty()) return;
            if (reader.source.efficientRandomAccess() && sectionCount != 0) {
                byte[] sections = reader.read(sectionOffset, sectionSize * sectionCount);
                for (int i = 0; i < sectionCount; i++) {
                    int at = i * sectionSize;
                    if (u32(sections, at + 4) != 1 || (u64(sections, at + 8) & 4) == 0) continue;
                    long address = u64(sections, at + 16), offset = u64(sections, at + 24), size = u64(sections, at + 32);
                    if (!range(offset, size, reader.length) || !executableMapping(offset, address, size)) throw new IOException("ELF 可执行节与 LOAD 映射不一致");
                    if (size > 0) code.add(new Region(offset, address, size, 5));
                }
            }
            if (code.isEmpty()) for (Region load : loads) if ((load.flags & 1) != 0 && load.size > 0) code.add(load);
            if (code.isEmpty()) throw new IOException("ELF 没有可执行区域");
            Collections.sort(code, new Comparator<Region>() { public int compare(Region a, Region b) { return Long.compare(a.offset, b.offset); } });
            for (int i = 1; i < code.size(); i++) if (code.get(i).offset < add(code.get(i - 1).offset, code.get(i - 1).size))
                throw new IOException("ELF 可执行扫描范围重叠，已停止识别");
        }
        boolean executableMapping(long offset, long address, long size) throws IOException {
            for (Region load : loads) if ((load.flags & 1) != 0 && address >= load.address && range(address - load.address, size, load.size))
                if (add(load.offset, address - load.address) == offset) return true;
            return false;
        }
        long dataOffset(long address, int size) throws IOException {
            long selected = -1;
            for (Region load : loads) {
                if (address < load.address || !range(address - load.address, size, load.size)) continue;
                long candidate = add(load.offset, address - load.address);
                if (selected >= 0 && selected != candidate) throw new IOException("ELF 虚拟地址存在歧义映射");
                if ((load.flags & 2) != 0) return -1;
                selected = candidate;
            }
            return selected;
        }
    }
}
