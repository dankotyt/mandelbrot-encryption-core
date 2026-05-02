package com.dankotyt.core.model;

import java.math.BigInteger;
import java.time.Instant;
import java.util.Arrays;

/**
 * Пара ключей ECDH: приватный, публичный (точка [x,y]) и опционально вычисленный общий секрет.
 * Поддерживает безопасное стирание секретных данных методом {@link #invalidate()}.
 *
 * @author dankotyt
 * @since 1.1.0
 */
public class ECDHKeyPair {
    private final BigInteger privateKey;
    private final BigInteger[] publicKey; // [x, y]
    private BigInteger[] sharedSecret; // [x, y]
    private final Instant creationTime;
    private byte[] sharedSecretBytes;

    /**
     * Возвращает приватный ключ (скаляр).
     *
     * @return приватный ключ.
     */
    public BigInteger getPrivateKey() {
        return privateKey;
    }

    /**
     * Возвращает публичный ключ — точку на эллиптической кривой в виде массива {@code [x, y]}.
     *
     * @return публичный ключ.
     */
    public BigInteger[] getPublicKey() {
        return publicKey;
    }

    /**
     * Возвращает вычисленный общий секрет — точку {@code [x, y]}.
     * Может быть {@code null}, если обмен ещё не производился.
     *
     * @return общий секрет или {@code null}.
     */
    public BigInteger[] getSharedSecret() {
        return sharedSecret;
    }

    /**
     * Возвращает момент времени создания данной пары ключей.
     *
     * @return время создания.
     */
    public Instant getCreationTime() {
        return creationTime;
    }

    /**
     * Возвращает общий секрет в виде байтового массива, готового для использования в HKDF.
     * Может быть {@code null}, если секрет ещё не вычислен.
     *
     * @return байтовый массив общего секрета или {@code null}.
     */
    public byte[] getSharedSecretBytes() {
        return sharedSecretBytes;
    }

    /**
     * Устанавливает общий секрет, полученный в результате скалярного умножения.
     *
     * @param sharedSecret точка {@code [x, y]}, представляющая общий секрет.
     */
    public void setSharedSecret(BigInteger[] sharedSecret) {
        this.sharedSecret = sharedSecret;
    }

    /**
     * Устанавливает байтовое представление общего секрета.
     *
     * @param sharedSecretBytes массив байтов общего секрета.
     */
    public void setSharedSecretBytes(byte[] sharedSecretBytes) {
        this.sharedSecretBytes = sharedSecretBytes;
    }

    /**
     * Создаёт пару ключей с заданным приватным ключом, публичной точкой и временем создания.
     *
     * @param privateKey  приватный ключ (скаляр)
     * @param publicKey   публичный ключ как массив из двух BigInteger [x, y]
     * @param creationTime момент создания пары
     */
    public ECDHKeyPair(BigInteger privateKey, BigInteger[] publicKey, Instant creationTime) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.creationTime = creationTime;
    }

    /**
     * Безвозвратно затирает общий секрет и его байтовое представление, обнуляя ссылки.
     */
    public void invalidate() {
        if (sharedSecretBytes != null) {
            Arrays.fill(sharedSecretBytes, (byte) 0);
        }
        sharedSecretBytes = null;
        sharedSecret = null;
    }
}