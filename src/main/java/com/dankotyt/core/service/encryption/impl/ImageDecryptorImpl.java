package com.dankotyt.core.service.encryption.impl;

import com.dankotyt.core.dto.EncryptedData;
import com.dankotyt.core.dto.MandelbrotParams;
import com.dankotyt.core.service.encryption.ImageDecryptor;
import com.dankotyt.core.service.encryption.MandelbrotService;
import com.dankotyt.core.service.encryption.SegmentShuffler;
import com.dankotyt.core.service.encryption.drbg.SHA3DRBG;
import com.dankotyt.core.service.encryption.sbox.DynamicSBoxGenerator;
import com.dankotyt.core.service.encryption.util.HKDF;
import com.dankotyt.core.service.network.CryptoKeyManager;
import com.dankotyt.core.utils.ImageUtils;
import com.dankotyt.core.utils.SBoxUtil;
import org.springframework.stereotype.Component;

import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.File;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

@Component
public class ImageDecryptorImpl implements ImageDecryptor {
    private final MandelbrotService mandelbrotService;
    private final SegmentShuffler segmentShuffler;
    private final ImageUtils imageUtils;
    private final SBoxUtil sBoxUtil;
    private final CryptoKeyManager cryptoKeyManager;
    private byte[] sessionSharedSecret;
    private SHA3DRBG paramsDrbg;
    private SHA3DRBG segDrbg;

    /**
     * Создаёт экземпляр дешифратора с необходимыми зависимостями.
     *
     * @param mandelbrotService сервис генерации фракталов Мандельброта.
     * @param segmentShuffler   сервис перемешивания сегментов изображения.
     * @param imageUtils        утилиты для работы с изображениями.
     * @param cryptoKeyManager  менеджер ключей для получения общего секрета.
     */
    public ImageDecryptorImpl(MandelbrotService mandelbrotService,
                              SegmentShuffler segmentShuffler,
                              ImageUtils imageUtils,
                              CryptoKeyManager cryptoKeyManager,
                              SBoxUtil sBoxUtil) {
        this.mandelbrotService = mandelbrotService;
        this.segmentShuffler = segmentShuffler;
        this.imageUtils = imageUtils;
        this.cryptoKeyManager = cryptoKeyManager;
        this.sBoxUtil = sBoxUtil;
    }

    /**
     * Дешифрует изображение из бинарного файла, созданного методом encryptWhole.
     * Процесс включает:
     * <ol>
     *   <li>Чтение соли, количества попыток, координат области и размеров</li>
     *   <li>Восстановление ключей через HKDF с использованием общего секрета</li>
     *   <li>Восстановление параметров фрактала путём прокрутки PRNG</li>
     *   <li>Генерацию фрактала и обратную сегментацию области</li>
     *   <li>XOR для восстановления оригинального изображения</li>
     * </ol>
     *
     * @param encryptedFile файл с зашифрованными данными
     * @param peerAddress   IP-адрес пира, с которым был согласован общий секрет
     * @return восстановленное изображение
     * @throws Exception если произошла ошибка при чтении, дешифровании или отсутствует ключ для пира
     */
    @Override
    public BufferedImage decryptImage(File encryptedFile, InetAddress peerAddress) throws Exception {
        if (encryptedFile == null || !encryptedFile.exists()) {
            throw new IllegalArgumentException("File does not exist");
        }
        if (peerAddress == null) {
            throw new IllegalArgumentException("Peer address is null");
        }

        byte[] fileData = Files.readAllBytes(encryptedFile.toPath());
        ByteBuffer buf = ByteBuffer.wrap(fileData);

        byte[] salt = new byte[16];
        buf.get(salt);
        int attempts = buf.getInt();
        int startX = buf.getInt();
        int startY = buf.getInt();
        int areaWidth = buf.getInt();
        int areaHeight = buf.getInt();
        int fullWidth = buf.getInt();
        int fullHeight = buf.getInt();
        byte[] imageBytes = new byte[buf.remaining()];
        buf.get(imageBytes);

        Dimension paddedFull = segmentShuffler.getPaddedDimensions(fullWidth, fullHeight);
        Dimension paddedArea = segmentShuffler.getPaddedDimensions(areaWidth, areaHeight);

        if (imageBytes.length != paddedFull.width * paddedFull.height * 4) {
            throw new IllegalArgumentException("Invalid image bytes length");
        }

        BufferedImage encryptedFullImage = imageUtils.bytesToImage(imageBytes, paddedFull.width, paddedFull.height);

        byte[] sharedSecret = cryptoKeyManager.getMasterSeedFromDH(peerAddress);

        byte[] prk = HKDF.extract(salt, sharedSecret);
        byte[] keyFractalParams = HKDF.expand(prk, "fractal-params".getBytes(StandardCharsets.UTF_8), 32);
        byte[] keySegmentation = HKDF.expand(prk, "segmentation".getBytes(StandardCharsets.UTF_8), 32);

        SHA3DRBG paramsDrbg = new SHA3DRBG(keyFractalParams);
        SHA3DRBG segDrbg = new SHA3DRBG(keySegmentation);

        MandelbrotParams params = null;
        for (int i = 0; i < attempts; i++) {
            params = mandelbrotService.generateParams(paramsDrbg);
        }
        if (params == null) {
            throw new IllegalStateException("Unable to generate fractal params for decryption");
        }

        BufferedImage fractalImage = mandelbrotService.generateImage(areaWidth, areaHeight,
                params.zoom(), params.offsetX(), params.offsetY(), params.maxIter());
        int[][] iterationArray = mandelbrotService.generateIterationArray(areaWidth, areaHeight,
                params.zoom(), params.offsetX(), params.offsetY(), params.maxIter());

        byte[] sbox = DynamicSBoxGenerator.generateSBox(iterationArray, sharedSecret);
        byte[] invSbox = DynamicSBoxGenerator.invertSBox(sbox);

        BufferedImage encryptedArea = encryptedFullImage.getSubimage(startX, startY, paddedArea.width, paddedArea.height);

        BufferedImage unshuffled = segmentShuffler.unshuffle(encryptedArea, segDrbg);

        BufferedImage unshuffledCore = unshuffled.getSubimage(0, 0, areaWidth, areaHeight);
        BufferedImage decryptedArea = sBoxUtil.applySBox(unshuffledCore, invSbox);

        BufferedImage result = new BufferedImage(fullWidth, fullHeight, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g = result.createGraphics();
        g.drawImage(encryptedFullImage.getSubimage(0, 0, fullWidth, fullHeight), 0, 0, null);
        g.setComposite(AlphaComposite.Src);
        g.drawImage(decryptedArea, startX, startY, null);
        g.dispose();

        return result;
    }

    @Override
    public BufferedImage decryptImage(EncryptedData encryptedData) throws Exception {
        if (encryptedData == null) {
            throw new IllegalArgumentException("EncryptedData is null");
        }
        if (sessionSharedSecret == null) {
            throw new IllegalStateException("prepareSession must be called first");
        }

        byte[] salt = encryptedData.sessionSalt();
        int startX = encryptedData.startX();
        int startY = encryptedData.startY();
        int areaWidth = encryptedData.areaWidth();
        int areaHeight = encryptedData.areaHeight();
        int fullWidth = encryptedData.originalWidth();
        int fullHeight = encryptedData.originalHeight();
        byte[] imageBytes = encryptedData.imageBytes();

        // Используем HKDF как в encryptor
        byte[] prk = HKDF.extract(salt, sessionSharedSecret);
        byte[] keyFractalParams = HKDF.expand(prk, "fractal-params".getBytes(StandardCharsets.UTF_8), 32);
        byte[] keySegmentation = HKDF.expand(prk, "segmentation".getBytes(StandardCharsets.UTF_8), 32);

        this.paramsDrbg = new SHA3DRBG(keyFractalParams);
        this.segDrbg = new SHA3DRBG(keySegmentation);

        // Генерируем параметры фрактала (один раз)
        MandelbrotParams params = mandelbrotService.generateParams(paramsDrbg);

        // Генерируем массив итераций
        int[][] iterArray = mandelbrotService.generateIterationArray(areaWidth, areaHeight,
                params.zoom(), params.offsetX(), params.offsetY(), params.maxIter());

        // Генерируем S-блок и обратный
        byte[] sbox = DynamicSBoxGenerator.generateSBox(iterArray, sessionSharedSecret);
        byte[] invSbox = DynamicSBoxGenerator.invertSBox(sbox);

        // Восстанавливаем изображение из байт
        Dimension paddedFull = segmentShuffler.getPaddedDimensions(fullWidth, fullHeight);
        Dimension paddedArea = segmentShuffler.getPaddedDimensions(areaWidth, areaHeight);

        // Проверка длины
        if (imageBytes.length != paddedFull.width * paddedFull.height * 4) {
            throw new IllegalArgumentException("Invalid image bytes length");
        }

        BufferedImage encryptedFullImage = imageUtils.bytesToImage(imageBytes, paddedFull.width, paddedFull.height);

        // Вырезаем область
        BufferedImage encryptedArea = encryptedFullImage.getSubimage(startX, startY, paddedArea.width, paddedArea.height);

        // Обратное перемешивание
        BufferedImage unshuffled = segmentShuffler.unshuffle(encryptedArea, segDrbg);

        // Обратный S-блок
        BufferedImage unshuffledCore = unshuffled.getSubimage(0, 0, areaWidth, areaHeight);
        BufferedImage decryptedArea = sBoxUtil.applySBox(unshuffledCore, invSbox);

        // Собираем финальное изображение
        BufferedImage result = new BufferedImage(fullWidth, fullHeight, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g = result.createGraphics();
        // Вставляем расшифрованную область в полное изображение (остальные части берём из encryptedFullImage)
        g.drawImage(encryptedFullImage.getSubimage(0, 0, fullWidth, fullHeight), 0, 0, null);
        g.setComposite(AlphaComposite.Src);
        g.drawImage(decryptedArea, startX, startY, null);
        g.dispose();

        return result;
    }

    @Override
    public void prepareSession(byte[] sharedSecret) throws Exception {
        if (sharedSecret == null) throw new IllegalArgumentException("Shared secret cannot be null");
        this.sessionSharedSecret = sharedSecret.clone();
    }
}