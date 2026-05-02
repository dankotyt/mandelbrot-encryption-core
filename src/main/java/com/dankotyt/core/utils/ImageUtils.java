package com.dankotyt.core.utils;

import com.dankotyt.core.dto.MandelbrotParams;
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
@Component
public class ImageUtils {

    private BufferedImage originalImage;
    private BufferedImage mandelbrotImage;
    private MandelbrotParams mandelbrotParams;

    /**
     * Возвращает сохранённое оригинальное изображение.
     *
     * @return оригинальное изображение или {@code null}, если оно не было установлено.
     */
    public BufferedImage getOriginalImage() {
        return originalImage;
    }

    /**
     * Возвращает сохранённое изображение фрактала Мандельброта.
     *
     * @return изображение фрактала или {@code null}, если оно не было установлено.
     */
    public BufferedImage getMandelbrotImage() {
        return mandelbrotImage;
    }

    /**
     * Возвращает параметры, с которыми было сгенерировано сохранённое изображение фрактала.
     *
     * @return параметры фрактала или {@code null}.
     */
    public MandelbrotParams getMandelbrotParams() {
        return mandelbrotParams;
    }

    /**
     * Сохраняет оригинальное изображение.
     *
     * @param originalImage изображение для сохранения; может быть {@code null}.
     */
    public void setOriginalImage(BufferedImage originalImage) {
        this.originalImage = originalImage;
    }

    /**
     * Проверяет, загружено ли оригинальное изображение.
     *
     * @return true, если оригинальное изображение установлено
     */
    public boolean hasOriginalImage() {
        return originalImage != null;
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
     * Конвертирует BufferedImage в массив байт (ARGB, 4 байта на пиксель).
     * Порядок каналов: альфа, красный, зелёный, синий.
     *
     * @param image изображение для конвертации
     * @return байтовый массив размером width * height * 4
     *
     * @since 1.2.0
     */
    public byte[] imageToBytes(BufferedImage image) {
        int width = image.getWidth(), height = image.getHeight();
        byte[] bytes = new byte[width * height * 4];
        int idx = 0;
        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                int argb = image.getRGB(x, y);
                bytes[idx++] = (byte) ((argb >> 24) & 0xFF); // alpha
                bytes[idx++] = (byte) ((argb >> 16) & 0xFF); // red
                bytes[idx++] = (byte) ((argb >> 8) & 0xFF);  // green
                bytes[idx++] = (byte) (argb & 0xFF);         // blue
            }
        }
        return bytes;
    }

    /**
     * Конвертирует массив байт обратно в BufferedImage с альфа-каналом.
     *
     * @param bytes  байтовый массив в формате ARGB (4 байта на пиксель)
     * @param width  ширина изображения
     * @param height высота изображения
     * @return восстановленное изображение с типом TYPE_INT_ARGB
     * @throws IllegalArgumentException если размер массива не соответствует width * height * 4
     *
     * @since 1.2.0
     */
    public BufferedImage bytesToImage(byte[] bytes, int width, int height) {
        if (bytes.length != width * height * 4)
            throw new IllegalArgumentException("Invalid byte array length. Expected " + width * height * 4 + " bytes but got " + bytes.length);
        BufferedImage img = new BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB);
        int idx = 0;
        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                int a = bytes[idx++] & 0xFF;
                int r = bytes[idx++] & 0xFF;
                int g = bytes[idx++] & 0xFF;
                int b = bytes[idx++] & 0xFF;
                img.setRGB(x, y, (a << 24) | (r << 16) | (g << 8) | b);
            }
        }
        return img;
    }
}
