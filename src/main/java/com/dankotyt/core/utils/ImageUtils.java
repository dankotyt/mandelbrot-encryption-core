package com.dankotyt.core.utils;

import com.dankotyt.core.dto.MandelbrotParams;
import lombok.Getter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.awt.*;
import java.awt.image.BufferedImage;

/**
 * Утилитарный класс для работы с изображениями: конвертация в/из байтовых массивов,
 * преобразование цветовых моделей и хранение временных изображений.
 *
 * @author dankotyt
 * @since 1.1.0
 */
@Getter
@Component
public class ImageUtils {
    private static final Logger logger = LoggerFactory.getLogger(ImageUtils.class);

    private BufferedImage originalImage;
    private BufferedImage mandelbrotImage;
    private MandelbrotParams mandelbrotParams;

    /**
     * Сохраняет оригинальное изображение.
     *
     * @param image изображение для сохранения
     */
    public void setOriginalImage(BufferedImage image) {
        this.originalImage = image;
        logger.info("ImageUtils: оригинальное изображение установлено, размер: {}x{}, instance: {}",
                image.getWidth(), image.getHeight(), this.hashCode());
    }

    /**
     * Проверяет, загружено ли оригинальное изображение.
     *
     * @return true, если оригинальное изображение установлено
     */
    public boolean hasOriginalImage() {
        boolean hasImage = originalImage != null;
        logger.info("ImageUtils: проверка hasOriginalImage() = {}, instance: {}", hasImage, this.hashCode());
        return hasImage;
    }

    /**
     * Сохраняет изображение фрактала Мандельброта и его параметры.
     *
     * @param image  сгенерированное изображение фрактала
     * @param params параметры, использованные для генерации
     */
    public void setMandelbrotImage(BufferedImage image, MandelbrotParams params) {
        this.mandelbrotImage = image;
        this.mandelbrotParams = params;
    }

    /**
     * Проверяет, есть ли сохранённое изображение фрактала.
     *
     * @return true, если изображение фрактала установлено
     */
    public boolean hasMandelbrotImage() {
        return mandelbrotImage != null;
    }

    /**
     * Преобразует изображение в формат TYPE_INT_ARGB, если оно ещё не в нём.
     *
     * @param image исходное изображение
     * @return изображение в формате ARGB (может быть тем же объектом)
     */
    public static BufferedImage convertToARGB(BufferedImage image) {
        if (image.getType() == BufferedImage.TYPE_INT_ARGB) {
            return image;
        }

        BufferedImage argbImage = new BufferedImage(
                image.getWidth(), image.getHeight(), BufferedImage.TYPE_INT_ARGB);

        Graphics2D g = argbImage.createGraphics();
        g.drawImage(image, 0, 0, null);
        g.dispose();

        return argbImage;
    }

    /**
     * Конвертирует BufferedImage в массив байт (RGB, 3 байта на пиксель).
     *
     * @param image изображение для конвертации
     * @return байтовый массив размером width * height * 3
     */
    public byte[] imageToBytes(BufferedImage image) {
        int width = image.getWidth(), height = image.getHeight();
        byte[] bytes = new byte[width * height * 3];
        int idx = 0;
        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                int rgb = image.getRGB(x, y);
                bytes[idx++] = (byte) ((rgb >> 16) & 0xFF);
                bytes[idx++] = (byte) ((rgb >> 8) & 0xFF);
                bytes[idx++] = (byte) (rgb & 0xFF);
            }
        }
        return bytes;
    }

    /**
     * Конвертирует массив байт обратно в BufferedImage.
     *
     * @param bytes  байтовый массив (формат RGB, 3 байта на пиксель)
     * @param width  ширина изображения
     * @param height высота изображения
     * @return восстановленное изображение
     * @throws IllegalArgumentException если размер массива не соответствует width * height * 3
     */
    public BufferedImage bytesToImage(byte[] bytes, int width, int height) {
        if (bytes.length != width * height * 3)
            throw new IllegalArgumentException("Invalid byte array length");
        BufferedImage img = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        int idx = 0;
        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                int r = bytes[idx++] & 0xFF;
                int g = bytes[idx++] & 0xFF;
                int b = bytes[idx++] & 0xFF;
                img.setRGB(x, y, (r << 16) | (g << 8) | b);
            }
        }
        return img;
    }
}
