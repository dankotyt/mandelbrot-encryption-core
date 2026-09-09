package com.dankotyt.core.service.encryption.impl;

import com.dankotyt.core.dto.EncryptedData;
import com.dankotyt.core.dto.MandelbrotParams;
import com.dankotyt.core.service.encryption.*;
import com.dankotyt.core.service.encryption.drbg.SHA3DRBG;
import com.dankotyt.core.service.encryption.sbox.DynamicSBoxGenerator;
import com.dankotyt.core.service.encryption.util.HKDF;
import com.dankotyt.core.utils.ImageUtils;
import com.dankotyt.core.utils.SBoxUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.awt.*;
import java.awt.geom.Rectangle2D;
import java.awt.image.BufferedImage;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

@Component
public class ImageEncryptorImpl implements ImageEncryptor {
    private static final Logger log = LoggerFactory.getLogger(ImageEncryptorImpl.class);

    private final MandelbrotService mandelbrotService;

    private final SegmentShuffler segmentShuffler;
    private final ImageUtils imageUtils;
    private final SBoxUtil sBoxUtil;

    private byte[] sessionSalt;
    private SHA3DRBG paramsDrbg;
    private SHA3DRBG segDrbg;
    private byte[] sharedSecret;
    private int attemptCount;
    private BufferedImage fractalImage;
    private int[][] iterationArray;

    public ImageEncryptorImpl(MandelbrotService mandelbrotService,
                              SegmentShuffler segmentShuffler,
                              ImageUtils imageUtils, SBoxUtil sBoxUtil) {
        this.mandelbrotService = mandelbrotService;
        this.segmentShuffler = segmentShuffler;
        this.imageUtils = imageUtils;
        this.sBoxUtil = sBoxUtil;
    }

    @Override
    public void prepareSession(byte[] sharedSecret) throws InvalidKeyException, NoSuchAlgorithmException {
        if (sharedSecret == null) throw new IllegalArgumentException("Shared secret cannot be null");
        this.sharedSecret = sharedSecret.clone();

        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        this.sessionSalt = salt;

        byte[] prk = HKDF.extract(salt, sharedSecret);
        byte[] keyFractalParams = HKDF.expand(prk, "fractal-params".getBytes(StandardCharsets.UTF_8), 32);
        byte[] keySegmentation = HKDF.expand(prk, "segmentation".getBytes(StandardCharsets.UTF_8), 32);

        this.paramsDrbg = new SHA3DRBG(keyFractalParams);
        this.segDrbg = new SHA3DRBG(keySegmentation);

        this.attemptCount = 0;
        this.fractalImage = null;
        this.iterationArray = null;
    }

    @Override
    public BufferedImage generateNextFractal(int width, int height) {
        attemptCount++;
        MandelbrotParams params = mandelbrotService.generateParams(paramsDrbg);
        fractalImage = mandelbrotService.generateImage(width, height, params.zoom(),
                params.offsetX(), params.offsetY(), params.maxIter());
        iterationArray = mandelbrotService.generateIterationArray(width, height, params.zoom(),
                params.offsetX(), params.offsetY(), params.maxIter());
        return fractalImage;
    }

    @Override
    public EncryptedData encryptWhole(BufferedImage originalImage) {
        BufferedImage argbImage = ImageUtils.convertToARGB(originalImage);
        int width = argbImage.getWidth();
        int height = argbImage.getHeight();

        if (fractalImage == null || fractalImage.getWidth() != width || fractalImage.getHeight() != height) {
            generateNextFractal(width, height);
        }

        byte[] sbox = DynamicSBoxGenerator.generateSBox(iterationArray, sharedSecret);

        BufferedImage substituted = sBoxUtil.applySBox(argbImage, sbox);

        BufferedImage shuffled = segmentShuffler.segmentAndShuffle(substituted, segDrbg).shuffledImage();

        return new EncryptedData(sessionSalt, attemptCount, 0, 0,
                width, height, width, height,
                imageUtils.imageToBytes(shuffled));
    }

    @Override
    public EncryptedData encryptPart(BufferedImage originalImage, Rectangle2D selectedArea) {
        int sx = (int) selectedArea.getMinX();
        int sy = (int) selectedArea.getMinY();
        int areaWidth = (int) selectedArea.getWidth();
        int areaHeight = (int) selectedArea.getHeight();
        return encryptPart(originalImage, sx, sy, areaWidth, areaHeight);
    }

    @Override
    public EncryptedData encryptPart(BufferedImage originalImage, int sx, int sy, int areaWidth, int areaHeight) {
        BufferedImage argbImage = ImageUtils.convertToARGB(originalImage);
        int origWidth = argbImage.getWidth();
        int origHeight = argbImage.getHeight();

        if (fractalImage == null || fractalImage.getWidth() != areaWidth || fractalImage.getHeight() != areaHeight) {
            generateNextFractal(areaWidth, areaHeight);
        }

        BufferedImage areaImage = argbImage.getSubimage(sx, sy, areaWidth, areaHeight);

        byte[] sbox = DynamicSBoxGenerator.generateSBox(iterationArray, sharedSecret);

        BufferedImage substitutedArea = sBoxUtil.applySBox(areaImage, sbox);

        BufferedImage shuffledArea = segmentShuffler.segmentAndShuffle(substitutedArea, segDrbg).shuffledImage();

        BufferedImage finalImage = new BufferedImage(origWidth, origHeight, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g = finalImage.createGraphics();
        g.drawImage(argbImage, 0, 0, null);
        g.drawImage(shuffledArea, sx, sy, null);
        g.dispose();

        return new EncryptedData(sessionSalt, attemptCount, sx, sy,
                areaWidth, areaHeight, origWidth, origHeight,
                imageUtils.imageToBytes(finalImage));
    }
}