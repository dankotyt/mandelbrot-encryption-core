package com.dankotyt.core.service.encryption.drbg;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Детерминированный генератор псевдослучайных чисел на основе SHA-3 (Hash_DRBG по NIST SP 800-90A).
 * Инициализируется seed'ом, полностью детерминирован, не использует системную энтропию.
 */
public class SHA3DRBG {
    private byte[] state;
    private long reseedCounter = 1;
    private final MessageDigest digest;

    public SHA3DRBG(byte[] seed) {
        try {
            this.digest = MessageDigest.getInstance("SHA3-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA3-256 not available", e);
        }
        if (seed == null || seed.length == 0) {
            throw new IllegalArgumentException("Seed cannot be null or empty");
        }
        this.state = digest.digest(concat(seed, new byte[]{0x00}));
        for (int i = 0; i < 10; i++) {
            this.state = digest.digest(concat(this.state, new byte[]{0x01}));
        }
    }

    public byte[] nextBytes(int numBytes) {
        if (numBytes <= 0) return new byte[0];
        byte[] newState = digest.digest(concat(state, new byte[]{0x02}));
        byte[] block = digest.digest(newState);
        byte[] result = new byte[numBytes];
        int generated = 0;
        while (generated < numBytes) {
            int toCopy = Math.min(block.length, numBytes - generated);
            System.arraycopy(block, 0, result, generated, toCopy);
            generated += toCopy;
            if (generated < numBytes) {
                newState = digest.digest(concat(newState, new byte[]{0x03}));
                block = digest.digest(newState);
            }
        }
        this.state = digest.digest(concat(newState, new byte[]{0x04}));
        reseedCounter++;
        return result;
    }

    public int nextInt(int bound) {
        if (bound <= 0) throw new IllegalArgumentException("Bound must be positive");
        int bits = 32 - Integer.numberOfLeadingZeros(bound - 1);
        int bytes = (bits + 7) / 8;
        int result;
        do {
            byte[] rand = nextBytes(bytes);
            result = 0;
            for (byte b : rand) {
                result = (result << 8) | (b & 0xFF);
            }
            result &= (1 << bits) - 1;
        } while (result >= bound);
        return result;
    }

    public double nextDouble() {
        byte[] rand = nextBytes(8);
        long bits = 0;
        for (byte b : rand) {
            bits = (bits << 8) | (b & 0xFF);
        }
        return (bits >>> 11) / (double) (1L << 53);
    }

    public boolean nextBoolean() {
        return (nextBytes(1)[0] & 1) == 1;
    }

    public void reseed(byte[] newSeed) {
        byte[] combined = concat(state, newSeed);
        combined = concat(combined, new byte[]{0x05});
        this.state = digest.digest(combined);
        reseedCounter = 1;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }
}
