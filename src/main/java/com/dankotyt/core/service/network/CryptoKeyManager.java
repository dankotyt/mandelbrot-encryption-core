package com.dankotyt.core.service.network;

import com.dankotyt.core.model.KyberKeyPair;

import java.net.InetAddress;
import java.util.Map;

/**
 * Управляет ключами ECDH для множества пиров.
 * Хранит локальные ключи и общие секреты, вычисленные для каждого удалённого узла.
 *
 * @author dankotyt
 * @since 1.1.0
 */
public interface CryptoKeyManager {

    /**
     * Возвращает общий секрет (master seed), согласованный с указанным пиром.
     *
     * @param peerAddress адрес пира.
     * @return байтовый массив общего секрета.
     * @throws IllegalStateException если для пира нет секрета.
     */
    byte[] getMasterSeedFromDH(InetAddress peerAddress);

    /**
     * Генерирует новую локальную пару ключей и сохраняет её.
     */
    void generateNewKeys();

    KyberKeyPair getCurrentKyberKeys();

    void addPeer(InetAddress peerAddress, KyberKeyPair peerKeyPair);

    /**
     * Удаляет пира и безопасно стирает его общий секрет.
     *
     * @param peerAddress адрес пира.
     * @throws IllegalArgumentException если адрес null.
     */
    void removePeer(InetAddress peerAddress);

    /**
     * Проверяет наличие активного общего секрета для пира.
     *
     * @param peerAddress адрес пира.
     * @return true, если есть непустой sharedSecretBytes.
     * @throws IllegalArgumentException если адрес null.
     */
    boolean hasPeer(InetAddress peerAddress);

    Map<InetAddress, KyberKeyPair> getActivePeersKyber();
}