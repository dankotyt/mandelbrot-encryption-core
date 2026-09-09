package com.dankotyt.core.service.network.impl;

import com.dankotyt.core.model.KyberKeyPair;
import com.dankotyt.core.service.network.CryptoKeyManager;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;
import org.springframework.stereotype.Service;

import javax.crypto.KEM;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Реализация {@link CryptoKeyManager} на основе постквантового алгоритма Kyber (ML-KEM).
 * <p>
 * Kyber является KEM (Key Encapsulation Mechanism):
 * - Отправитель генерирует пару ключей, публичный ключ передаёт получателю.
 * - Получатель использует публичный ключ для генерации общего секрета ( encapsulation)
 *   и отправляет его обратно отправителю.
 * - Отправитель расшифровывает (decapsulation) полученный секрет своим приватным ключом.
 * <p>
 * В данной реализации используется упрощённая модель: каждый пир хранит свою пару ключей,
 * а общий секрет вычисляется при регистрации пира.
 */
@Service
public class KyberCryptoKeyManagerImpl implements CryptoKeyManager {

    @Override
    public void addPeer(InetAddress peerAddress, KyberKeyPair peerKeyPair) {

    }

    static {
        // Регистрация провайдеров Bouncy Castle
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());
    }

    private volatile KyberKeyPair currentKeys;
    private final Map<String, KyberKeyPair> peers = new ConcurrentHashMap<>();

    public KyberCryptoKeyManagerImpl() {
        generateNewKeys();
    }

    /**
     * Генерирует новую пару ключей Kyber (уровень Kyber1024).
     */
    @Override
    public void generateNewKeys() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("Kyber", "BCPQC");
            kpg.initialize(KyberParameterSpec.kyber1024);
            KeyPair keyPair = kpg.generateKeyPair();

            this.currentKeys = new KyberKeyPair(
                    keyPair.getPrivate(),
                    keyPair.getPublic(),
                    Instant.now()
            );
        } catch (Exception e) {
            throw new RuntimeException("Ошибка генерации ключей Kyber", e);
        }
    }

    /**
     * Возвращает общий секрет (байты) для зарегистрированного пира.
     * В модели Kyber общий секрет вычисляется при регистрации пира
     * и сохраняется в объекте KyberKeyPair.
     */
    @Override
    public byte[] getMasterSeedFromDH(InetAddress peerAddress) {
        KyberKeyPair peerKeys = peers.get(peerAddress.getHostAddress());
        if (peerKeys == null || peerKeys.getSharedSecret() == null) {
            throw new IllegalStateException("Нет общего секрета для пира: " + peerAddress);
        }
        return peerKeys.getSharedSecret();
    }

    /**
     * Возвращает текущую локальную пару ключей.
     */
    @Override
    public KyberKeyPair getCurrentKyberKeys() {
        return currentKeys;
    }

    /**
     * Регистрирует пира и вычисляет общий секрет.
     * <p>
     * В этой упрощённой модели мы предполагаем, что пир уже имеет наш публичный ключ
     * и прислал свой зашифрованный общий секрет (encapsulated secret).
     *
     * @param peerAddress адрес пира
     * @param encapsulatedSecret зашифрованный общий секрет от пира
     */
    public void addPeer(InetAddress peerAddress, byte[] encapsulatedSecret) {
        if (peerAddress == null || encapsulatedSecret == null) {
            throw new IllegalArgumentException("Адрес пира или encapsulatedSecret не могут быть null");
        }

        try {
            // Используем KEM API для расшифровки (decapsulation)
            KEM kem = KEM.getInstance("Kyber", "BCPQC");
            KEM.Decapsulator decapsulator = kem.newDecapsulator(currentKeys.getPrivateKey());

            // Расшифровываем общий секрет
            SecretKeyWithEncapsulation secretKey = (SecretKeyWithEncapsulation)
                    decapsulator.decapsulate(encapsulatedSecret);

            byte[] sharedSecret = secretKey.getEncoded();

            // Создаём копию ключей для пира и сохраняем общий секрет
            KyberKeyPair peerKeys = new KyberKeyPair(
                    currentKeys.getPrivateKey(),
                    currentKeys.getPublicKey(),
                    currentKeys.getCreationTime()
            );
            peerKeys.setSharedSecret(sharedSecret);

            peers.put(peerAddress.getHostAddress(), peerKeys);

        } catch (Exception e) {
            throw new RuntimeException("Ошибка при расшифровке общего секрета Kyber", e);
        }
    }

    /**
     * Генерирует зашифрованный общий секрет (encapsulation) для публичного ключа пира.
     * Возвращает Encapsulated, который содержит зашифрованный секрет и сам секрет (может быть использован сразу).
     */
    public KEM.Encapsulated generateEncapsulated(byte[] peerPublicKeyBytes) {
        try {
            // Восстанавливаем публичный ключ пира
            KeyFactory kf = KeyFactory.getInstance("Kyber", "BCPQC");
            PublicKey peerPublicKey = kf.generatePublic(new X509EncodedKeySpec(peerPublicKeyBytes));

            KEM kem = KEM.getInstance("Kyber", "BCPQC");
            KEM.Encapsulator encapsulator = kem.newEncapsulator(peerPublicKey);
            // Выполняем encapsulation – получаем зашифрованный секрет и общий секрет

            return encapsulator.encapsulate();

        } catch (Exception e) {
            throw new RuntimeException("Ошибка при генерации зашифрованного секрета Kyber", e);
        }
    }

    /**
     * Удаляет пира и затирает его общий секрет.
     */
    @Override
    public void removePeer(InetAddress peerAddress) {
        if (peerAddress == null) {
            throw new IllegalArgumentException("Адрес пира не может быть null");
        }
        KyberKeyPair removed = peers.remove(peerAddress.getHostAddress());
        if (removed != null) {
            removed.invalidate();
        }
    }

    /**
     * Проверяет, есть ли у пира вычисленный общий секрет.
     */
    @Override
    public boolean hasPeer(InetAddress peerAddress) {
        if (peerAddress == null) {
            throw new IllegalArgumentException("Адрес пира не может быть null");
        }
        KyberKeyPair peerKeys = peers.get(peerAddress.getHostAddress());
        return peerKeys != null && peerKeys.getSharedSecret() != null;
    }

    /**
     * Возвращает копию Map всех активных пиров.
     */
    @Override
    public Map<InetAddress, KyberKeyPair> getActivePeersKyber() {
        Map<InetAddress, KyberKeyPair> result = new ConcurrentHashMap<>();
        for (Map.Entry<String, KyberKeyPair> entry : peers.entrySet()) {
            try {
                result.put(
                        InetAddress.getByName(entry.getKey()),
                        entry.getValue()
                );
            } catch (UnknownHostException e) {
                // Игнорируем
            }
        }
        return result;
    }

    /**
     * Вспомогательный метод для восстановления публичного ключа из байтов.
     */
    private java.security.PublicKey restorePublicKey(byte[] keyBytes) {
        try {
            java.security.KeyFactory kf = java.security.KeyFactory.getInstance("Kyber", "BCPQC");
            java.security.spec.X509EncodedKeySpec spec = new java.security.spec.X509EncodedKeySpec(keyBytes);
            return kf.generatePublic(spec);
        } catch (Exception e) {
            throw new RuntimeException("Ошибка восстановления публичного ключа Kyber", e);
        }
    }
}