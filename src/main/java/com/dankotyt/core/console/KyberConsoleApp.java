package com.dankotyt.core.console;

import com.dankotyt.core.dto.EncryptedData;
import com.dankotyt.core.service.encryption.ImageDecryptor;
import com.dankotyt.core.service.encryption.ImageEncryptor;
import com.dankotyt.core.service.encryption.SegmentShuffler;
import com.dankotyt.core.utils.ImageUtils;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

import javax.imageio.ImageIO;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.Scanner;

@Configuration
@ComponentScan(basePackages = "com.dankotyt.core")
public class KyberConsoleApp {

    private static final String SECRET_FILE = "session.secret";
    private static final int DEFAULT_PORT = 9999;

    private final ImageEncryptor encryptor;
    private final ImageDecryptor decryptor;
    private final Scanner scanner;
    private byte[] currentSecret;

    private final ImageUtils imageUtils;
    private final SegmentShuffler segmentShuffler;

    public KyberConsoleApp(ImageEncryptor encryptor, ImageDecryptor decryptor,
                           ImageUtils imageUtils, SegmentShuffler segmentShuffler) {
        this.encryptor = encryptor;
        this.decryptor = decryptor;
        this.imageUtils = imageUtils;
        this.segmentShuffler = segmentShuffler;
        this.scanner = new Scanner(System.in, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) throws Exception {
        System.setOut(new PrintStream(System.out, true, StandardCharsets.UTF_8));
        ApplicationContext context = new AnnotationConfigApplicationContext(KyberConsoleApp.class);
        KyberConsoleApp app = context.getBean(KyberConsoleApp.class);
        app.run();
    }

    public void run() throws Exception {
        System.out.println("=== Постквантовое шифрование изображений (Kyber) ===");

        // Попытка загрузить сохранённый секрет
        if (Files.exists(Paths.get(SECRET_FILE))) {
            System.out.println("Найден сохранённый секрет. Загрузить? (y/n)");
            String answer = scanner.nextLine().trim().toLowerCase();
            if (answer.equals("y") || answer.isEmpty()) {
                KyberSessionManager manager = new KyberSessionManager();
                manager.loadSecret(SECRET_FILE);
                currentSecret = manager.getSharedSecret();
                System.out.println("Секрет загружен.");
            }
        }

        while (true) {
            if (currentSecret == null) {
                // Нет активного секрета – предложить создать сессию
                System.out.println("\nВыберите действие:");
                System.out.println("1. Создать новую сессию (сервер)");
                System.out.println("2. Подключиться к сессии (клиент)");
                System.out.println("3. Загрузить секрет из файла");
                System.out.println("4. Выйти");
                System.out.print("> ");
                String choice = scanner.nextLine().trim();
                switch (choice) {
                    case "1":
                        createServerSession();
                        break;
                    case "2":
                        createClientSession();
                        break;
                    case "3":
                        loadSecretFromFile();
                        break;
                    case "4":
                        System.out.println("До свидания.");
                        return;
                    default:
                        System.out.println("Неверный ввод.");
                }
            } else {
                // Секрет есть – перейти в режим шифрования/расшифровки
                showCryptoMenu();
            }
        }
    }

    private void createServerSession() throws Exception {
        System.out.print("Введите порт (по умолчанию " + DEFAULT_PORT + "): ");
        String portStr = scanner.nextLine().trim();
        int port = portStr.isEmpty() ? DEFAULT_PORT : Integer.parseInt(portStr);

        KyberSessionManager manager = new KyberSessionManager();
        manager.startServer(port);
        currentSecret = manager.getSharedSecret();
        manager.saveSecret(SECRET_FILE);
        System.out.println("Сессия создана, секрет сохранён.");
    }

    private void createClientSession() throws Exception {
        System.out.print("Введите IP-адрес сервера: ");
        String host = scanner.nextLine().trim();
        if (host.isEmpty()) {
            System.out.println("IP не может быть пустым.");
            return;
        }
        System.out.print("Введите порт (по умолчанию " + DEFAULT_PORT + "): ");
        String portStr = scanner.nextLine().trim();
        int port = portStr.isEmpty() ? DEFAULT_PORT : Integer.parseInt(portStr);

        KyberSessionManager manager = new KyberSessionManager();
        manager.startClient(host, port);
        currentSecret = manager.getSharedSecret();
        manager.saveSecret(SECRET_FILE);
        System.out.println("Подключение выполнено, секрет сохранён.");
    }

    private void loadSecretFromFile() throws IOException {
        System.out.print("Введите путь к файлу секрета (по умолчанию " + SECRET_FILE + "): ");
        String path = scanner.nextLine().trim();
        if (path.isEmpty()) path = SECRET_FILE;
        KyberSessionManager manager = new KyberSessionManager();
        manager.loadSecret(path);
        currentSecret = manager.getSharedSecret();
        System.out.println("Секрет загружен.");
    }

    private void showCryptoMenu() throws Exception {
        while (true) {
            System.out.println("\n=== Меню шифрования/расшифровки ===");
            System.out.println("1. Зашифровать изображение");
            System.out.println("2. Расшифровать изображение");
            System.out.println("3. Сохранить текущий секрет в файл");
            System.out.println("4. Выйти в главное меню (сбросить секрет)");
            System.out.print("> ");
            String choice = scanner.nextLine().trim();
            switch (choice) {
                case "1":
                    encryptImage();
                    break;
                case "2":
                    decryptImage();
                    break;
                case "3":
                    saveSecretToFile();
                    break;
                case "4":
                    currentSecret = null;
                    System.out.println("Секрет сброшен.");
                    return;
                default:
                    System.out.println("Неверный ввод.");
            }
        }
    }

    private void encryptImage() throws Exception {
        System.out.print("Введите абсолютный путь к изображению: ");
        String imagePath = scanner.nextLine().trim();
        if (!Files.exists(Paths.get(imagePath))) {
            System.out.println("Файл не найден.");
            return;
        }

        encryptor.prepareSession(currentSecret);
        BufferedImage image = ImageIO.read(new File(imagePath));
        if (image == null) {
            System.out.println("Не удалось прочитать изображение.");
            return;
        }

        EncryptedData encryptedData = encryptor.encryptWhole(image);

        Path originalPath = Paths.get(imagePath);
        String baseName = originalPath.getFileName().toString();
        int dotIndex = baseName.lastIndexOf('.');
        String nameWithoutExt = (dotIndex > 0) ? baseName.substring(0, dotIndex) : baseName;

        Path parentDir = originalPath.getParent();
        if (parentDir == null) parentDir = Paths.get(".");
        Path outputDir = parentDir.resolve("cipher_" + nameWithoutExt);
        Files.createDirectories(outputDir);

        // 1. Сохраняем оригинал
        Path originalImagePath = outputDir.resolve("original.png");
        ImageIO.write(image, "PNG", originalImagePath.toFile());

        // 2. Сохраняем зашифрованное изображение (как PNG)
        int fullWidth = encryptedData.originalWidth();
        int fullHeight = encryptedData.originalHeight();
        Dimension paddedFull = segmentShuffler.getPaddedDimensions(fullWidth, fullHeight);
        BufferedImage encryptedImage = imageUtils.bytesToImage(encryptedData.imageBytes(), paddedFull.width, paddedFull.height);
        Path encryptedImagePath = outputDir.resolve("encrypted.png");
        ImageIO.write(encryptedImage, "PNG", encryptedImagePath.toFile());

        // 3. Сохраняем бинарный файл для расшифровки
        Path encryptedFile = outputDir.resolve("encrypted_data.bin");
        try (ObjectOutputStream oos = new ObjectOutputStream(Files.newOutputStream(encryptedFile))) {
            oos.writeObject(encryptedData);
        }

        System.out.println("✅ Изображение зашифровано.");
        System.out.println("  Оригинал сохранён в: " + originalImagePath.toAbsolutePath());
        System.out.println("  Зашифрованное изображение: " + encryptedImagePath.toAbsolutePath());
        System.out.println("  Бинарный файл для расшифровки: " + encryptedFile.toAbsolutePath());
        System.out.println("Для расшифровки передайте бинарный файл и используйте тот же секрет.");
    }

    private void decryptImage() throws Exception {
        System.out.print("Введите абсолютный путь к файлу с зашифрованными данними (encrypted_data.bin): ");
        String filePath = scanner.nextLine().trim();
        if (!Files.exists(Paths.get(filePath))) {
            System.out.println("Файл не найден.");
            return;
        }

        EncryptedData encryptedData;
        try (ObjectInputStream ois = new ObjectInputStream(Files.newInputStream(Paths.get(filePath)))) {
            encryptedData = (EncryptedData) ois.readObject();
        }

        decryptor.prepareSession(currentSecret);
        BufferedImage decryptedImage = decryptor.decryptImage(encryptedData);

        Path encryptedPath = Paths.get(filePath);
        Path outputDir = encryptedPath.getParent();
        if (outputDir == null) outputDir = Paths.get(".");
        Path resultImage = outputDir.resolve("decrypted.png");
        ImageIO.write(decryptedImage, "PNG", resultImage.toFile());

        System.out.println("✅ Изображение расшифровано. Результат: " + resultImage.toAbsolutePath());
    }

    private void saveSecretToFile() throws IOException {
        System.out.print("Введите путь для сохранения секрета (по умолчанию " + SECRET_FILE + "): ");
        String path = scanner.nextLine().trim();
        if (path.isEmpty()) path = SECRET_FILE;
        try (FileOutputStream fos = new FileOutputStream(path)) {
            fos.write(currentSecret);
        }
        System.out.println("Секрет сохранён в " + path);
    }
}