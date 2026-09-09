package com.dankotyt.core.model;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Arrays;

/**
 * Пара ключей Kyber: приватный, публичный и общий секрет.
 */
public class KyberKeyPair {
    private final PrivateKey privateKey;
    private final PublicKey publicKey;
    private final Instant creationTime;
    private byte[] sharedSecret;

    public KyberKeyPair(PrivateKey privateKey, PublicKey publicKey, Instant creationTime) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.creationTime = creationTime;
    }

    public PrivateKey getPrivateKey() { return privateKey; }
    public PublicKey getPublicKey() { return publicKey; }
    public Instant getCreationTime() { return creationTime; }
    public byte[] getSharedSecret() { return sharedSecret; }
    public void setSharedSecret(byte[] sharedSecret) { this.sharedSecret = sharedSecret; }

    public byte[] getPublicKeyBytes() {
        return publicKey.getEncoded();
    }

    public void invalidate() {
        if (sharedSecret != null) {
            Arrays.fill(sharedSecret, (byte) 0);
        }
        sharedSecret = null;
    }
}