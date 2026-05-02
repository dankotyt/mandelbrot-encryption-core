package com.dankotyt.core.service.encryption.util;

import org.springframework.stereotype.Component;

import java.awt.image.BufferedImage;

/**
 * Утилита для побитовой операции XOR над двумя изображениями.
 *
 * <p>Применяет XOR к RGB-компонентам каждого пикселя, сохраняя альфа-канал
 * из первого изображения. Оба изображения должны иметь одинаковые размеры.</p>
 *
 * @author dankotyt
 * @since 1.1.0
 */
@Component
public class XOR {

    /**
     * Выполняет побитовый XOR RGB-компонентов двух изображений одинакового размера.
     *
     * @param source исходное изображение
     * @param fractal фрактальная гамма
     * @return новое изображение с результатом XOR
     * @throws IllegalArgumentException если любое из изображений null или размеры не совпадают
     */
    public static BufferedImage performXOR(BufferedImage source, BufferedImage fractal, boolean encrypt) {
        if (source == null || fractal == null) {
            throw new IllegalArgumentException("Images cannot be null");
        }
        if (source.getWidth() != fractal.getWidth() || source.getHeight() != fractal.getHeight()) {
            throw new IllegalArgumentException("Images must have the same dimensions");
        }

        int width = source.getWidth();
        int height = source.getHeight();
        BufferedImage result = new BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB);

        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                int srcPixel = source.getRGB(x, y);
                int fracPixel = fractal.getRGB(x, y);

                int srcA = (srcPixel >> 24) & 0xFF;
                int srcR = (srcPixel >> 16) & 0xFF;
                int srcG = (srcPixel >> 8) & 0xFF;
                int srcB = srcPixel & 0xFF;

                int fracR = (fracPixel >> 16) & 0xFF;
                int fracG = (fracPixel >> 8) & 0xFF;
                int fracB = fracPixel & 0xFF;

                if (encrypt) {
                    if (srcA == 0) {
                        int markerB = (fracB & 0xFE);
                        result.setRGB(x, y, 0xFF000000 | (fracR << 16) | (fracG << 8) | markerB);
                    } else {
                        int xorR = srcR ^ fracR;
                        int xorG = srcG ^ fracG;
                        int xorB = srcB ^ fracB;
                        xorB = (xorB & 0xFE) | 0x01;
                        result.setRGB(x, y, (srcA << 24) | (xorR << 16) | (xorG << 8) | xorB);
                    }
                } else {
                    int encA = (srcPixel >> 24) & 0xFF;
                    int encR = (srcPixel >> 16) & 0xFF;
                    int encG = (srcPixel >> 8) & 0xFF;
                    int encB = srcPixel & 0xFF;

                    boolean isCat = (encB & 0x01) == 1;

                    if (!isCat) {
                        result.setRGB(x, y, 0x00000000);
                    } else {
                        int origR = encR ^ fracR;
                        int origG = encG ^ fracG;
                        int origB = (encB & 0xFE) ^ fracB;
                        result.setRGB(x, y, (encA << 24) | (origR << 16) | (origG << 8) | origB);
                    }
                }
            }
        }
        return result;
    }
}
