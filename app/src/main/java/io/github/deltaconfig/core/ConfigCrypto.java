package io.github.deltaconfig.core;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Authenticated envelope implementation for the verified Delta Force build. */
public final class ConfigCrypto {
    public static final int MAX_INI_BYTES = 2 * 1024 * 1024;
    public static final long MAX_MATERIAL_AUTH_BYTES = 64L * 1024 * 1024;
    private ConfigCrypto() { }

    /** Authentication succeeded, but the authenticated protocol or payload is unfamiliar. */
    public static final class AuthenticatedFormatException extends GeneralSecurityException {
        public AuthenticatedFormatException(String message) { super(message); }
        public AuthenticatedFormatException(String message, Throwable cause) { super(message, cause); }
    }

    /** Terminal candidate-budget failure; callers must not repeat discovery via another source. */
    public static final class MaterialAuthenticationBudgetException extends IOException {
        public MaterialAuthenticationBudgetException(String message) { super(message); }
    }

    /** Non-secret, single-byte storage encodings; known builds are attempted first. */
    public static int[] materialEncodingCandidates() {
        int[] values = new int[256];
        values[0] = 0xe2; values[1] = 0; values[2] = 0x10;
        int at = 3;
        for (int value = 0; value < 256; value++)
            if (value != 0xe2 && value != 0 && value != 0x10) values[at++] = value;
        return values;
    }

    public static byte[] decodeFixedMask(byte[] encrypted32) {
        requireKey(encrypted32);
        byte[] mask = encrypted32.clone();
        for (int i = 0; i < mask.length; i++) mask[i] ^= (byte) 0xe2;
        return mask;
    }

    public static byte[] deriveKey(byte[] fixedMask, byte[] gameplayIni)
            throws GeneralSecurityException {
        byte[] hashToken = getField(gameplayIni, "Hash");
        try { return deriveKeyFromHash(fixedMask, hashToken); }
        finally { Arrays.fill(hashToken, (byte) 0); }
    }

    /** Reuses one extracted Hash token across bounded material candidates. */
    public static byte[] deriveKeyFromHash(byte[] fixedMask, byte[] hashToken)
            throws GeneralSecurityException {
        requireKey(fixedMask);
        Decoded decoded = decrypt(hashToken, fixedMask);
        String hash = payloadText(decoded.plaintext, decoded.length);
        try {
            if (!hash.matches("[0-9a-fA-F]{40}"))
                throw new AuthenticatedFormatException("UserGameplay Hash 已通过 HMAC，但认证摘要不是受支持的 40 位十六进制格式");
            byte[] digest = new byte[20];
            for (int i = 0; i < digest.length; i++)
                digest[i] = (byte) Integer.parseInt(hash.substring(i * 2, i * 2 + 2), 16);
            byte[] key = repeatXor(fixedMask, digest);
            Arrays.fill(digest, (byte) 0);
            return key;
        } finally {
            Arrays.fill(decoded.plaintext, (byte) 0);
        }
    }

    public static String decodeIni(byte[] ini, byte[] key) throws GeneralSecurityException {
        Decoded decoded = decrypt(getField(ini, "Token"), key);
        try { return payloadText(decoded.plaintext, decoded.length); }
        finally { Arrays.fill(decoded.plaintext, (byte) 0); }
    }

    public static byte[] replaceIni(byte[] original, String newText, byte[] key)
            throws GeneralSecurityException {
        checkSize(original);
        if (newText == null || newText.length() > MAX_INI_BYTES - 32)
            throw new IllegalArgumentException("配置内容过大或为空");
        byte[] oldToken = getField(original, "Token");
        Decoded decoded = decrypt(oldToken, key);
        byte[] token;
        try {
            if (payloadText(decoded.plaintext, decoded.length).equals(newText))
                return original.clone();
            token = encrypt(newText, key, decoded.magic);
        } finally {
            Arrays.fill(decoded.plaintext, (byte) 0);
        }
        String value = new String(token, StandardCharsets.US_ASCII);
        if (oldToken.length == 0 || oldToken[oldToken.length - 1] != '=')
            value = value.replaceAll("=+$", "");
        String raw = new String(original, StandardCharsets.ISO_8859_1);
        Matcher matcher = fieldPattern("Token").matcher(raw);
        if (!matcher.find()) throw new IllegalArgumentException("缺少 Token 字段");
        int start = matcher.start(1), end = matcher.end(1);
        while (start < end && isSpace(raw.charAt(start))) start++;
        while (end > start && isSpace(raw.charAt(end - 1))) end--;
        if (end > start + 1 && raw.charAt(start) == '"' && raw.charAt(end - 1) == '"') {
            start++; end--;
        }
        byte[] result = (raw.substring(0, start) + value + raw.substring(end))
                .getBytes(StandardCharsets.ISO_8859_1);
        checkSize(result);
        if (!decodeIni(result, key).equals(newText))
            throw new GeneralSecurityException("配置重新编码回读不一致");
        return result;
    }

    public static byte[] getField(byte[] ini, String field) {
        checkSize(ini);
        if (field == null || !field.matches("[A-Za-z][A-Za-z0-9_]*"))
            throw new IllegalArgumentException("无效的配置字段名");
        Matcher matcher = fieldPattern(field).matcher(new String(ini, StandardCharsets.ISO_8859_1));
        if (!matcher.find()) throw new IllegalArgumentException("缺少配置字段: " + field);
        String value = matcher.group(1).trim();
        if (matcher.find()) throw new IllegalArgumentException("配置字段重复: " + field);
        if (value.length() >= 2 && value.startsWith("\"") && value.endsWith("\""))
            value = value.substring(1, value.length() - 1);
        if (value.isEmpty()) throw new IllegalArgumentException("配置字段为空: " + field);
        for (int i = 0; i < value.length(); i++)
            if (value.charAt(i) > 127) throw new IllegalArgumentException("认证字段包含非 ASCII 字符");
        return value.getBytes(StandardCharsets.US_ASCII);
    }

    private static Pattern fieldPattern(String field) {
        return Pattern.compile("^" + Pattern.quote(field) + "[ \\t]*=[ \\t]*([^\\r\\n]+)",
                Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);
    }

    private static boolean isSpace(char c) { return c == ' ' || c == '\t'; }

    private static final class Decoded {
        final int magic, length;
        final byte[] plaintext;
        Decoded(int magic, int length, byte[] plaintext) {
            this.magic = magic; this.length = length; this.plaintext = plaintext;
        }
    }

    private static Decoded decrypt(byte[] token, byte[] key) throws GeneralSecurityException {
        requireKey(key);
        checkSize(token);
        byte[] envelope;
        try { envelope = Base64.getDecoder().decode(token); }
        catch (IllegalArgumentException ex) {
            throw new GeneralSecurityException("配置认证封装不是有效的 Base64", ex);
        }
        if (envelope.length <= 20 || (envelope.length - 20) % 16 != 0)
            throw new GeneralSecurityException("配置密文块长度不正确");
        byte[] tag = Arrays.copyOf(envelope, 20);
        byte[] aesKey = repeatXor(key, tag);
        byte[] plain = null;
        boolean returned = false;
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKey, "AES"));
            plain = cipher.doFinal(envelope, 20, envelope.length - 20);
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key, "HmacSHA1"));
            if (!MessageDigest.isEqual(tag, mac.doFinal(plain)))
                throw new GeneralSecurityException("配置认证失败：设备、游戏版本或文件不匹配");
            int magic = (plain[0] & 255) | ((plain[1] & 255) << 8);
            long length = 0;
            for (int i = 0; i < 4; i++) length |= (long) (plain[i + 2] & 255) << (i * 8);
            if ((magic != 0x4501 && magic != 0x4502) || length > plain.length - 6)
                throw new AuthenticatedFormatException("配置已通过 HMAC，但认证头的版本或长度不受支持");
            returned = true;
            return new Decoded(magic, (int) length, plain);
        } finally {
            Arrays.fill(aesKey, (byte) 0);
            Arrays.fill(envelope, (byte) 0);
            if (!returned && plain != null) Arrays.fill(plain, (byte) 0);
        }
    }

    private static byte[] encrypt(String text, byte[] key, int magic)
            throws GeneralSecurityException {
        requireKey(key);
        int length = text.length();
        byte[] plain = new byte[(6 + length + 15) & ~15];
        plain[0] = (byte) magic; plain[1] = (byte) (magic >>> 8);
        for (int i = 0; i < 4; i++) plain[i + 2] = (byte) (length >>> (i * 8));
        byte[] aesKey = null;
        try {
            for (int i = 0; i < length; i++) {
                char c = text.charAt(i);
                if (c < 1 || c > 256)
                    throw new IllegalArgumentException("配置包含该游戏编码无法表示的字符");
                plain[i + 6] = (byte) (c - 1);
            }
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key, "HmacSHA1"));
            byte[] tag = mac.doFinal(plain);
            aesKey = repeatXor(key, tag);
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aesKey, "AES"));
            byte[] ciphertext = cipher.doFinal(plain);
            byte[] envelope = new byte[20 + ciphertext.length];
            System.arraycopy(tag, 0, envelope, 0, 20);
            System.arraycopy(ciphertext, 0, envelope, 20, ciphertext.length);
            return Base64.getEncoder().encode(envelope);
        } finally {
            Arrays.fill(plain, (byte) 0);
            if (aesKey != null) Arrays.fill(aesKey, (byte) 0);
        }
    }

    private static String payloadText(byte[] plain, int length) {
        char[] chars = new char[length];
        for (int i = 0; i < length; i++) chars[i] = (char) ((plain[i + 6] & 255) + 1);
        return new String(chars);
    }

    private static byte[] repeatXor(byte[] key, byte[] digest) {
        byte[] result = new byte[32];
        for (int i = 0; i < 32; i++) result[i] = (byte) (key[i] ^ digest[i % digest.length]);
        return result;
    }

    private static void requireKey(byte[] key) {
        if (key == null || key.length != 32) throw new IllegalArgumentException("认证材料必须为 32 字节");
    }

    private static void checkSize(byte[] value) {
        if (value == null || value.length == 0 || value.length > MAX_INI_BYTES)
            throw new IllegalArgumentException("配置文件为空或超过 2 MiB 限制");
    }
}
