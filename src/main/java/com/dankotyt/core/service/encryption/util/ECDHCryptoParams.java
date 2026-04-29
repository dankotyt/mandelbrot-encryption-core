package com.dankotyt.core.service.encryption.util;

import com.dankotyt.core.service.encryption.impl.ECDHServiceImpl;

import java.math.BigInteger;

/**
 * Параметры эллиптической кривой для операций ECDH (стандарт NIST P-256).
 *
 * <p>Содержит простые числа и координаты генератора, используемые
 * при скалярном умножении точек в {@link ECDHServiceImpl}.</p>
 *
 * @author dankotyt
 * @since 1.1.0
 */
public class ECDHCryptoParams {
    /** Модуль простого числа p. */
    public static final BigInteger P = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);

    /** Коэффициент a кривой. */
    public static final BigInteger A = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16);

    /** X-координата генератора G. */
    public static final BigInteger GX = new BigInteger("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16);

    /** Y-координата генератора G. */
    public static final BigInteger GY = new BigInteger("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16);

    /** Порядок группы (количество точек на кривой). */
    public static final BigInteger N = new BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);

    /**
     * Приватный конструктор — утилитарный класс не предназначен для создания экземпляров.
     */
    private ECDHCryptoParams() {
    }
}
