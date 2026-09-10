package com.dankotyt.core.console;

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

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.SecureRandom;
import java.security.Security;

/**
 * Управляет сессией с использованием ML-KEM (Kyber) для обмена общим секретом.
 * Заменяет предыдущую реализацию на NTRU.
 */
public class KyberSessionManager {

    private byte[] sharedSecret;
    private MLKEMPrivateKeyParameters privateKey;
    private MLKEMPublicKeyParameters publicKey;
    private byte[] publicKeyBytes;
    private final SecureRandom secureRandom = new SecureRandom();

    static {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());
    }

    /**
     * Генерирует ключевую пару ML-KEM с параметрами ML-KEM-1024.
     */
    public void generateLocalKeys() throws Exception {
        MLKEMKeyPairGenerator keyPairGenerator = new MLKEMKeyPairGenerator();
        keyPairGenerator.init(new MLKEMKeyGenerationParameters(
                secureRandom, MLKEMParameters.ml_kem_1024));

        AsymmetricCipherKeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = (MLKEMPrivateKeyParameters) keyPair.getPrivate();
        this.publicKey = (MLKEMPublicKeyParameters) keyPair.getPublic();
        this.publicKeyBytes = publicKey.getEncoded();
    }

    public byte[] getPublicKeyBytes() {
        return publicKeyBytes;
    }

    public void startServer(int port) throws Exception {
        generateLocalKeys();
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("Ожидание подключения на порту " + port + "...");
            try (Socket socket = serverSocket.accept()) {
                System.out.println("Клиент подключен: " + socket.getRemoteSocketAddress());
                performHandshakeServer(socket);
            }
        }
    }

    public void startClient(String host, int port) throws Exception {
        generateLocalKeys();
        try (Socket socket = new Socket(host, port)) {
            System.out.println("Подключено к серверу " + host + ":" + port);
            performHandshakeClient(socket);
        }
    }

    private void performHandshakeServer(Socket socket) throws Exception {
        DataInputStream dis = new DataInputStream(socket.getInputStream());
        DataOutputStream dos = new DataOutputStream(socket.getOutputStream());

        // 1) Получаем публичный ключ клиента
        int clientKeyLen = dis.readInt();
        byte[] clientPublicKeyBytes = new byte[clientKeyLen];
        dis.readFully(clientPublicKeyBytes);

        // 2) Отправляем свой публичный ключ
        dos.writeInt(publicKeyBytes.length);
        dos.write(publicKeyBytes);
        dos.flush();

        // 3) Получаем encapsulation от клиента
        int encLen = dis.readInt();
        byte[] encapsulatedSecret = new byte[encLen];
        dis.readFully(encapsulatedSecret);

        // 4) Декапсуляция через MLKEMExtractor
        MLKEMExtractor extractor = new MLKEMExtractor(privateKey);
        sharedSecret = extractor.extractSecret(encapsulatedSecret);

        System.out.println("Общий секрет получен (длина: " + sharedSecret.length + " байт)");
    }

    private void performHandshakeClient(Socket socket) throws Exception {
        DataInputStream dis = new DataInputStream(socket.getInputStream());
        DataOutputStream dos = new DataOutputStream(socket.getOutputStream());

        // 1) Отправляем свой публичный ключ
        dos.writeInt(publicKeyBytes.length);
        dos.write(publicKeyBytes);
        dos.flush();

        // 2) Получаем публичный ключ сервера
        int serverKeyLen = dis.readInt();
        byte[] serverPublicKeyBytes = new byte[serverKeyLen];
        dis.readFully(serverPublicKeyBytes);

        // 3) Восстанавливаем публичный ключ сервера
        // Для этого нужно знать параметры. Предполагаем ML-KEM-1024.
        // В реальной системе параметры должны быть согласованы.
        MLKEMPublicKeyParameters serverPublicKey = new MLKEMPublicKeyParameters(
                MLKEMParameters.ml_kem_1024, serverPublicKeyBytes);

        // 4) Инкапсуляция через MLKEMGenerator
        MLKEMGenerator generator = new MLKEMGenerator(secureRandom);
        SecretWithEncapsulation encapsulated = generator.generateEncapsulated(serverPublicKey);

        sharedSecret = encapsulated.getSecret();
        byte[] encSecret = encapsulated.getEncapsulation();

        // 5) Отправляем encapsulation серверу
        dos.writeInt(encSecret.length);
        dos.write(encSecret);
        dos.flush();

        System.out.println("Общий секрет получен (длина: " + sharedSecret.length + " байт)");
    }

    public void saveSecret(String filePath) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            fos.write(sharedSecret);
        }
        System.out.println("Секрет сохранён в " + filePath);
    }

    public void loadSecret(String filePath) throws IOException {
        File file = new File(filePath);
        if (!file.exists()) throw new FileNotFoundException("Файл секрета не найден: " + filePath);
        try (FileInputStream fis = new FileInputStream(file)) {
            sharedSecret = fis.readAllBytes();
        }
        System.out.println("Секрет загружен из " + filePath + " (размер: " + sharedSecret.length + " байт)");
    }

    public byte[] getSharedSecret() {
        return sharedSecret;
    }

    public boolean hasSecret() {
        return sharedSecret != null && sharedSecret.length > 0;
    }
}