package com.dankotyt.core.console;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;

import javax.crypto.KEM;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;

public class KyberSessionManager {

    private byte[] sharedSecret;
    private PrivateKey privateKey;
    private byte[] publicKeyBytes;

    static {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());
    }

    public void generateLocalKeys() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("MLKEM", "BCPQC");
        kpg.initialize(KyberParameterSpec.kyber1024);
        KeyPair keyPair = kpg.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKeyBytes = keyPair.getPublic().getEncoded();
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

        // 1. Получить публичный ключ клиента
        int clientKeyLen = dis.readInt();
        byte[] clientPublicKeyBytes = new byte[clientKeyLen];
        dis.readFully(clientPublicKeyBytes);

        // 2. Отправить свой публичный ключ
        dos.writeInt(publicKeyBytes.length);
        dos.write(publicKeyBytes);
        dos.flush();

        // 3. Получить encapsulation от клиента
        int encLen = dis.readInt();
        byte[] encapsulatedSecret = new byte[encLen];
        dis.readFully(encapsulatedSecret);

        // 4. Decapsulation (получаем SecretKey)
        KEM kem = KEM.getInstance("MLKEM", "BCPQC");
        KEM.Decapsulator decapsulator = kem.newDecapsulator(privateKey);
        SecretKey secretKey = decapsulator.decapsulate(encapsulatedSecret);
        sharedSecret = secretKey.getEncoded();

        System.out.println("Общий секрет получен (длина: " + sharedSecret.length + " байт)");
    }

    private void performHandshakeClient(Socket socket) throws Exception {
        DataInputStream dis = new DataInputStream(socket.getInputStream());
        DataOutputStream dos = new DataOutputStream(socket.getOutputStream());

        // 1. Отправить свой публичный ключ
        dos.writeInt(publicKeyBytes.length);
        dos.write(publicKeyBytes);
        dos.flush();

        // 2. Получить публичный ключ сервера
        int serverKeyLen = dis.readInt();
        byte[] serverPublicKeyBytes = new byte[serverKeyLen];
        dis.readFully(serverPublicKeyBytes);

        // 3. Восстановить публичный ключ сервера
        KeyFactory kf = KeyFactory.getInstance("MLKEM", "BCPQC");
        PublicKey serverPublicKey = kf.generatePublic(new X509EncodedKeySpec(serverPublicKeyBytes));

        // 4. Encapsulation (получаем Encapsulated)
        KEM kem = KEM.getInstance("MLKEM", "BCPQC");
        KEM.Encapsulator encapsulator = kem.newEncapsulator(serverPublicKey);
        KEM.Encapsulated encapsulated = encapsulator.encapsulate();

        // Извлекаем общий секрет и зашифрованный секрет
        SecretKey secretKey = encapsulated.key();
        sharedSecret = secretKey.getEncoded();
        byte[] encSecret = encapsulated.encapsulation();

        // 5. Отправить encapsulation серверу
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