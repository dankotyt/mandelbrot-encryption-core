package com.dankotyt.core.utils;

import org.springframework.stereotype.Component;

import java.awt.image.BufferedImage;

@Component
public class SBoxUtil {
    public BufferedImage applySBox(BufferedImage image, byte[] sbox) {
        int w = image.getWidth();
        int h = image.getHeight();
        BufferedImage result = new BufferedImage(w, h, BufferedImage.TYPE_INT_ARGB);
        for (int y = 0; y < h; y++) {
            for (int x = 0; x < w; x++) {
                int argb = image.getRGB(x, y);
                int a = (argb >> 24) & 0xFF;
                int r = (argb >> 16) & 0xFF;
                int g = (argb >> 8) & 0xFF;
                int b = argb & 0xFF;

                r = sbox[r] & 0xFF;
                g = sbox[g] & 0xFF;
                b = sbox[b] & 0xFF;
                int newArgb = (a << 24) | (r << 16) | (g << 8) | b;
                result.setRGB(x, y, newArgb);
            }
        }
        return result;
    }
}
