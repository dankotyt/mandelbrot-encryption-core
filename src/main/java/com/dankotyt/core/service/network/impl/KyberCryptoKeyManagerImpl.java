package com.dankotyt.core.service.network.impl;

import com.dankotyt.core.model.KyberKeyPair;
import com.dankotyt.core.service.network.CryptoKeyManager;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.generators.MLKEMKeyPairGenerator;
import org.bouncycastle.crypto.kems.MLKEMExtractor;
import org.bouncycastle.crypto.kems.MLKEMGenerator;
import org.bouncycastle.crypto.params.MLKEMKeyGenerationParameters;
import org.bouncycastle.crypto.params.MLKEMParameters;
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.springframework.stereotype.Service;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.SecureRandom;
import java.security.Security;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Реализация {@link CryptoKeyManager} на основе постквантового алгоритма ML-KEM (Kyber).
 * <p>
 * Использует низкоуровневый API Bouncy Castle ({@code org.bouncycastle.crypto.kems})
 * для выполнения операций инкапсуляции и декапсуляции ключей.
 */
@Service
public class KyberCryptoKeyManagerImpl implements CryptoKeyManager {

    static {
        // Регистрация провайдеров Bouncy Castle (все еще нужна для некоторых утилит)
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());
    }

    private volatile KyberKeyPair currentKeys;
    private final Map<String, byte[]> peerSharedSecrets = new ConcurrentHashMap<>();
    private final SecureRandom secureRandom = new SecureRandom();

    public KyberCryptoKeyManagerImpl() {
        generateNewKeys();
    }

    /**
     * Генерирует новую пару ключей ML-KEM (уровень безопасности ML-KEM-1024).
     * Использует низкоуровневый генератор ключей Bouncy Castle.
     */
    @Override
    public void generateNewKeys() {
        try {
            MLKEMKeyPairGenerator keyPairGenerator = new MLKEMKeyPairGenerator();
            keyPairGenerator.init(new MLKEMKeyGenerationParameters(
                    secureRandom, MLKEMParameters.ml_kem_1024));

            AsymmetricCipherKeyPair keyPair = keyPairGenerator.generateKeyPair();

            this.currentKeys = new KyberKeyPair(
                    (MLKEMPrivateKeyParameters) keyPair.getPrivate(),
                    (MLKEMPublicKeyParameters) keyPair.getPublic(),
                    Instant.now()
            );
        } catch (Exception e) {
            throw new RuntimeException("Ошибка генерации ключей ML-KEM", e);
        }
    }

    /**
     * Возвращает общий секрет (master seed) для зарегистрированного пира.
     */
    @Override
    public byte[] getMasterSeedFromDH(InetAddress peerAddress) {
        byte[] secret = peerSharedSecrets.get(peerAddress.getHostAddress());
        if (secret == null) {
            throw new IllegalStateException("Нет общего секрета для пира: " + peerAddress);
        }
        return secret.clone();
    }

    /**
     * Возвращает текущую локальную пару ключей.
     */
    @Override
    public KyberKeyPair getCurrentKyberKeys() {
        return currentKeys;
    }

    /**
     * Регистрирует пира и вычисляет общий секрет, используя {@link MLKEMExtractor}.
     *
     * @param peerAddress        адрес пира
     * @param encapsulatedSecret зашифрованный общий секрет от пира
     */
    public void addPeer(InetAddress peerAddress, byte[] encapsulatedSecret) {
        if (peerAddress == null || encapsulatedSecret == null) {
            throw new IllegalArgumentException("Адрес пира или encapsulatedSecret не могут быть null");
        }
        try {
            MLKEMExtractor extractor = new MLKEMExtractor(currentKeys.getPrivateKey());
            byte[] sharedSecret = extractor.extractSecret(encapsulatedSecret);
            peerSharedSecrets.put(peerAddress.getHostAddress(), sharedSecret);
        } catch (Exception e) {
            throw new RuntimeException("Ошибка при декапсуляции общего секрета ML-KEM", e);
        }
    }

    /**
     * Генерирует зашифрованный общий секрет (encapsulation) для публичного ключа пира.
     * Использует {@link MLKEMGenerator} из низкоуровневого API.
     */
    public SecretWithEncapsulation generateEncapsulated(MLKEMPublicKeyParameters peerPublicKey) {
        try {
            MLKEMGenerator generator = new MLKEMGenerator(secureRandom);
            return generator.generateEncapsulated(peerPublicKey);
        } catch (Exception e) {
            throw new RuntimeException("Ошибка при инкапсуляции секрета ML-KEM", e);
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
        byte[] removed = peerSharedSecrets.remove(peerAddress.getHostAddress());
        if (removed != null) {
            java.util.Arrays.fill(removed, (byte) 0);
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
        byte[] secret = peerSharedSecrets.get(peerAddress.getHostAddress());
        return secret != null && secret.length > 0;
    }

    /**
     * Возвращает копию Map всех активных пиров.
     */
    @Override
    public Map<InetAddress, byte[]> getActivePeersSharedSecrets() {
        Map<InetAddress, byte[]> result = new ConcurrentHashMap<>();
        for (Map.Entry<String, byte[]> entry : peerSharedSecrets.entrySet()) {
            try {
                result.put(InetAddress.getByName(entry.getKey()), entry.getValue().clone());
            } catch (UnknownHostException e) {
                // ignore
            }
        }
        return result;
    }
}