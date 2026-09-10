package com.dankotyt.core.service.encryption.drbg;

import org.bouncycastle.crypto.digests.SHAKEDigest;

public class ShakeDRBG {
    private final SHAKEDigest shake;
    private final byte[] buffer = new byte[64];
    private int bufferPos = 0;
    private int bufferLen = 0;

    public ShakeDRBG(byte[] seed) {
        if (seed == null) throw new IllegalArgumentException("Seed cannot be null");
        this.shake = new SHAKEDigest(256);
        this.shake.update(seed, 0, seed.length);
    }

    private void refill() {
        bufferLen = shake.doFinal(buffer, 0, buffer.length);
        bufferPos = 0;
    }

    public void nextBytes(byte[] out, int off, int len) {
        while (len > 0) {
            if (bufferPos >= bufferLen) refill();
            int toCopy = Math.min(len, bufferLen - bufferPos);
            System.arraycopy(buffer, bufferPos, out, off, toCopy);
            bufferPos += toCopy;
            off += toCopy;
            len -= toCopy;
        }
    }

    public byte[] nextBytes(int len) {
        byte[] out = new byte[len];
        nextBytes(out, 0, len);
        return out;
    }

    public int nextInt() {
        byte[] b = new byte[4];
        nextBytes(b, 0, 4);
        return ((b[0] & 0xFF) << 24) | ((b[1] & 0xFF) << 16) |
                ((b[2] & 0xFF) << 8)  |  (b[3] & 0xFF);
    }

    public int nextInt(int bound) {
        if (bound <= 0) throw new IllegalArgumentException("bound must be positive");
        int bits, val;
        do {
            bits = nextInt() >>> 1; // 31-битное неотрицательное
            val = bits % bound;
        } while (bits - val + (bound - 1) < 0);
        return val;
    }

    public long nextLong() {
        byte[] b = new byte[8];
        nextBytes(b, 0, 8);
        return ((long)(b[0] & 0xFF) << 56) | ((long)(b[1] & 0xFF) << 48) |
                ((long)(b[2] & 0xFF) << 40) | ((long)(b[3] & 0xFF) << 32) |
                ((long)(b[4] & 0xFF) << 24) | ((long)(b[5] & 0xFF) << 16) |
                ((long)(b[6] & 0xFF) << 8)  | ((long)(b[7] & 0xFF));
    }

    public double nextDouble() {
        return (nextLong() >>> 11) * 0x1.0p-53;
    }

    public boolean nextBoolean() {
        return (nextInt() & 1) != 0;
    }

    public static byte[] deriveKeyMaterial(byte[] seed, int outputLength) {
        SHAKEDigest shake = new SHAKEDigest(256);
        shake.update(seed, 0, seed.length);
        byte[] output = new byte[outputLength];
        shake.doFinal(output, 0, outputLength);
        return output;
    }
}
