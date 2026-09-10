package com.dankotyt.core.service.encryption.sbox;

import com.dankotyt.core.service.encryption.drbg.ShakeDRBG;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Генерирует динамический S-блок (перестановка 0..255) на основе фрактальных данных и seed'а.
 * Использует SHA3DRBG, инициализированный комбинацией seed'а и хеша фрактального массива.
 */
public class DynamicSBoxGenerator {

    public static byte[] generateSBox(int[][] iterationArray, byte[] seed) {
        byte[] fractalHash = hashIterationArray(iterationArray);
        byte[] combined = concat(seed, fractalHash);
        combined = concat(combined, "DynamicSBox".getBytes());
        ShakeDRBG drbg = new ShakeDRBG(combined);

        List<Integer> list = new ArrayList<>();
        for (int i = 0; i < 256; i++) list.add(i);
        for (int i = 255; i > 0; i--) {
            int j = drbg.nextInt(i + 1);
            Collections.swap(list, i, j);
        }
        byte[] sbox = new byte[256];
        for (int i = 0; i < 256; i++) {
            sbox[i] = list.get(i).byteValue();
        }
        return sbox;
    }

    public static byte[] invertSBox(byte[] sbox) {
        byte[] inverse = new byte[256];
        for (int i = 0; i < 256; i++) {
            int val = sbox[i] & 0xFF;
            inverse[val] = (byte) i;
        }
        return inverse;
    }

    private static byte[] hashIterationArray(int[][] array) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA3-256");
            for (int[] row : array) {
                for (int val : row) {
                    md.update((byte) (val & 0xFF));
                    md.update((byte) ((val >> 8) & 0xFF));
                    md.update((byte) ((val >> 16) & 0xFF));
                    md.update((byte) ((val >> 24) & 0xFF));
                }
            }
            return md.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA3-256 not available", e);
        }
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }
}