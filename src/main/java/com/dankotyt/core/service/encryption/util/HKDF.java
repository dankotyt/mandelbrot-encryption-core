package com.dankotyt.core.service.encryption.util;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Реализация HMAC-based Key Derivation Function (HKDF) по RFC 5869.
 *
 * <p>Предоставляет методы extract и expand для извлечения псевдослучайного ключа
 * и расширения его в ключевой материал требуемой длины. Использует HMAC-SHA256.</p>
 *
 * @author dankotyt
 * @since 1.1.0
 */
public class HKDF {
    private static final String HMAC_ALGO = "HmacSHA256";

    /**
     * HKDF-Extract: извлекает псевдослучайный ключ (PRK) из salt и входного материала.
     *
     * @param salt соль (может быть null или пустой — тогда используется массив из 32 нулевых байт)
     * @param ikm  входной ключевой материал (не может быть null)
     * @return псевдослучайный ключ длиной 32 байта
     * @throws NoSuchAlgorithmException если HMAC-SHA256 недоступен
     * @throws InvalidKeyException      если соль не может быть использована как ключ
     * @throws IllegalArgumentException если ikm равен null
     */
    public static byte[] extract(byte[] salt, byte[] ikm) throws NoSuchAlgorithmException, InvalidKeyException {
        if (ikm == null) {
            throw new IllegalArgumentException("IKM (input keying material) cannot be null");
        }
        Mac mac = Mac.getInstance(HMAC_ALGO);
        if (salt == null || salt.length == 0) {
            salt = new byte[32];
        }
        mac.init(new SecretKeySpec(salt, HMAC_ALGO));
        return mac.doFinal(ikm);
    }

    /**
     * HKDF-Expand: расширяет псевдослучайный ключ в ключевой материал заданной длины.
     *
     * @param prk    псевдослучайный ключ (не может быть null)
     * @param info   контекстная информация (может быть пустым)
     * @param length желаемая длина выходного материала в байтах
     * @return ключевой материал указанной длины
     * @throws NoSuchAlgorithmException если HMAC-SHA256 недоступен
     * @throws InvalidKeyException      если prk не может быть использован как ключ
     * @throws IllegalArgumentException если prk равен null
     */
    public static byte[] expand(byte[] prk, byte[] info, int length) throws NoSuchAlgorithmException, InvalidKeyException {
        if (prk == null) {
            throw new IllegalArgumentException("PRK (pseudo-random key) cannot be null");
        }
        Mac mac = Mac.getInstance(HMAC_ALGO);
        mac.init(new SecretKeySpec(prk, HMAC_ALGO));
        byte[] result = new byte[length];
        byte[] t = new byte[0];
        int counter = 1;
        int offset = 0;
        while (offset < length) {
            mac.update(t);
            mac.update(info);
            mac.update((byte) counter++);
            t = mac.doFinal();
            int toCopy = Math.min(t.length, length - offset);
            System.arraycopy(t, 0, result, offset, toCopy);
            offset += toCopy;
        }
        return result;
    }
}
