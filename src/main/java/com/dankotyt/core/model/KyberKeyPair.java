package com.dankotyt.core.model;

import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters;
import java.time.Instant;
import java.util.Arrays;

/**
 * Пара ключей Kyber: приватный, публичный и общий секрет.
 */
public class KyberKeyPair {
    private final MLKEMPrivateKeyParameters privateKey;
    private final MLKEMPublicKeyParameters publicKey;
    private final Instant creationTime;
    private byte[] sharedSecret;

    public KyberKeyPair(MLKEMPrivateKeyParameters privateKey,
                        MLKEMPublicKeyParameters publicKey,
                        Instant creationTime) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.creationTime = creationTime;
    }

    public MLKEMPrivateKeyParameters getPrivateKey() { return privateKey; }
    public MLKEMPublicKeyParameters getPublicKey() { return publicKey; }
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