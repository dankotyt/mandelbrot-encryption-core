package com.dankotyt.core.service.encryption.impl;

import com.dankotyt.core.dto.MandelbrotParams;
import com.dankotyt.core.service.encryption.ImageDecryptor;
import com.dankotyt.core.service.encryption.MandelbrotService;
import com.dankotyt.core.service.encryption.SegmentShuffler;
import com.dankotyt.core.service.encryption.util.HKDF;
import com.dankotyt.core.service.encryption.util.XOR;
import com.dankotyt.core.service.network.CryptoKeyManager;
import com.dankotyt.core.utils.ImageUtils;
import org.springframework.stereotype.Component;

import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.File;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.SecureRandom;

@Component
public class ImageDecryptorImpl implements ImageDecryptor {
    private final MandelbrotService mandelbrotService;
    private final SegmentShuffler segmentShuffler;
    private final ImageUtils imageUtils;
    private final CryptoKeyManager cryptoKeyManager;

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
                              CryptoKeyManager cryptoKeyManager) {
        this.mandelbrotService = mandelbrotService;
        this.segmentShuffler = segmentShuffler;
        this.imageUtils = imageUtils;
        this.cryptoKeyManager = cryptoKeyManager;
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

        BufferedImage encryptedImage = imageUtils.bytesToImage(imageBytes, paddedFull.width, paddedFull.height);

        byte[] sharedSecret = cryptoKeyManager.getMasterSeedFromDH(peerAddress);

        byte[] prk = HKDF.extract(salt, sharedSecret);
        byte[] keyFractalParams = HKDF.expand(prk, "fractal-params".getBytes(StandardCharsets.UTF_8), 32);
        byte[] keySegmentation = HKDF.expand(prk, "segmentation".getBytes(StandardCharsets.UTF_8), 32);

        SecureRandom paramsPrng = SecureRandom.getInstance("SHA1PRNG");
        paramsPrng.setSeed(keyFractalParams);
        MandelbrotParams params = null;
        for (int i = 0; i < Math.max(1, attempts); i++) {
            params = mandelbrotService.generateParams(paramsPrng);
        }

        SecureRandom segPrng = SecureRandom.getInstance("SHA1PRNG");
        segPrng.setSeed(keySegmentation);

        BufferedImage encryptedArea = encryptedImage.getSubimage(startX, startY, paddedArea.width, paddedArea.height);

        BufferedImage unshuffled = segmentShuffler.unshuffle(encryptedArea, segPrng);
        BufferedImage unshuffledCore = unshuffled.getSubimage(0, 0, areaWidth, areaHeight);
        BufferedImage fractal = mandelbrotService.generateImage(
                areaWidth, areaHeight,
                params.zoom(), params.offsetX(), params.offsetY(), params.maxIter());
        BufferedImage decryptedArea = XOR.performXOR(unshuffledCore, fractal, false);

        BufferedImage result = new BufferedImage(fullWidth, fullHeight, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g = result.createGraphics();
        g.drawImage(encryptedImage.getSubimage(0, 0, fullWidth, fullHeight), 0, 0, null);
        g.setComposite(AlphaComposite.Src);
        g.drawImage(decryptedArea, startX, startY, null);
        g.dispose();

        return result;
    }
}