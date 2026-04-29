package com.dankotyt.core.config;

import com.dankotyt.core.service.encryption.*;
import com.dankotyt.core.service.encryption.impl.*;
import com.dankotyt.core.service.network.CryptoKeyManager;
import com.dankotyt.core.service.network.impl.ECDHCryptoKeyManagerImpl;
import com.dankotyt.core.utils.ImageUtils;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Автоконфигурация Spring Boot для модуля шифрования.
 *
 * <p>Регистрирует все необходимые бины для работы с шифрованием изображений
 * и управления ECDH-ключами в сетевом окружении.</p>
 *
 * <p><b>Включаемые бины:</b>
 * <ul>
 *   <li>{@link ImageUtils} – утилиты для конвертации изображений</li>
 *   <li>{@link MandelbrotService} – генерация фракталов Мандельброта</li>
 *   <li>{@link MandelbrotParamsGenerator} – генератор параметров фрактала</li>
 *   <li>{@link SegmentShuffler} – перемешивание сегментов изображения</li>
 *   <li>{@link SegmentSizeStrategy} – стратегия выбора размера сегмента</li>
 *   <li>{@link ECDHService} – криптография на эллиптических кривых</li>
 *   <li>{@link CryptoKeyManager} – управление ключами и общим секретом</li>
 *   <li>{@link ImageEncryptor} – шифрование изображений</li>
 *   <li>{@link ImageDecryptor} – дешифрование изображений</li>
 * </ul>
 *
 * <p><b>Пример использования в Spring Boot:</b>
 * <pre>{@code
 * @Service
 * public class MyService {
 *     @Autowired
 *     private ImageEncryptor encryptor;
 *     @Autowired
 *     private ImageDecryptor decryptor;
 *     @Autowired
 *     private CryptoKeyManager keyManager;
 *
 *     public void process(BufferedImage image, InetAddress peer) {
 *         byte[] secret = keyManager.getMasterSeedFromDH(peer);
 *         encryptor.prepareSession(secret);
 *         EncryptedData data = encryptor.encryptWhole(image);
 *         // ...
 *     }
 * }
 * }</pre>
 *
 * <p><b>Примечание:</b> Данная конфигурация не зависит от JavaFX и UI-компонентов.
 * Для работы с файлами клиент должен самостоятельно реализовать сохранение зашифрованных данных.</p>
 *
 * @author dankotyt
 * @since 1.1.0
 * @see EncryptionModule
 */
@Configuration
public class EncryptionAutoConfiguration {

    /**
     * Создаёт бин {@link ImageUtils} для конвертации изображений.
     *
     * @return экземпляр ImageUtils
     */
    @Bean
    @ConditionalOnMissingBean
    public ImageUtils imageUtils() {
        return new ImageUtils();
    }

    /**
     * Создаёт бин {@link MandelbrotService} для генерации фракталов Мандельброта.
     *
     * @return экземпляр MandelbrotService с генератором параметров по умолчанию
     */
    @Bean
    @ConditionalOnMissingBean
    public MandelbrotService mandelbrotService() {
        return new MandelbrotService();
    }

    /**
     * Создаёт бин {@link MandelbrotParamsGenerator} с параметрами по умолчанию.
     *
     * @return экземпляр MandelbrotParamsGeneratorImpl
     */
    @Bean
    @ConditionalOnMissingBean
    public MandelbrotParamsGenerator mandelbrotParamsGenerator() {
        return new MandelbrotParamsGeneratorImpl();
    }

    /**
     * Создаёт бин {@link SegmentShuffler} для перемешивания сегментов изображения.
     *
     * @return экземпляр ImageSegmentShufflerImpl со стратегией размера сегментов
     */
    @Bean
    @ConditionalOnMissingBean
    public SegmentShuffler segmentShuffler() {
        return new ImageSegmentShufflerImpl(segmentSizeStrategy());
    }

    /**
     * Создаёт бин {@link SegmentSizeStrategy} с порогами по умолчанию.
     *
     * @return экземпляр SegmentSizeStrategyImpl
     */
    @Bean
    @ConditionalOnMissingBean
    public SegmentSizeStrategy segmentSizeStrategy() {
        return new SegmentSizeStrategyImpl();
    }

    /**
     * Создаёт бин {@link ECDHService} для операций на эллиптической кривой.
     *
     * @return экземпляр ECDHServiceImpl
     */
    @Bean
    @ConditionalOnMissingBean
    public ECDHService ecdhService() {
        return new ECDHServiceImpl();
    }

    /**
     * Создаёт бин {@link CryptoKeyManager} для управления ECDH-ключами.
     *
     * @param ecdhService сервис криптографических операций
     * @return экземпляр ECDHCryptoKeyManagerImpl
     */
    @Bean
    @ConditionalOnMissingBean
    public CryptoKeyManager cryptoKeyManager(ECDHService ecdhService) {
        return new ECDHCryptoKeyManagerImpl(ecdhService);
    }

    /**
     * Создаёт бин {@link ImageEncryptor} для шифрования изображений.
     *
     * @param mandelbrotService сервис генерации фракталов
     * @param segmentShuffler   сервис перемешивания сегментов
     * @param imageUtils        утилиты для работы с изображениями
     * @return экземпляр ImageEncryptorImpl
     */
    @Bean
    @ConditionalOnMissingBean
    public ImageEncryptor imageEncryptor(MandelbrotService mandelbrotService,
                                         SegmentShuffler segmentShuffler,
                                         ImageUtils imageUtils) {
        return new ImageEncryptorImpl(mandelbrotService, segmentShuffler, imageUtils);
    }

    /**
     * Создаёт бин {@link ImageDecryptor} для дешифрования изображений.
     *
     * @param mandelbrotService сервис генерации фракталов
     * @param segmentShuffler   сервис перемешивания сегментов
     * @param imageUtils        утилиты для работы с изображениями
     * @param cryptoKeyManager  менеджер ключей для получения общего секрета
     * @return экземпляр ImageDecryptorImpl
     */
    @Bean
    @ConditionalOnMissingBean
    public ImageDecryptor imageDecryptor(MandelbrotService mandelbrotService,
                                         SegmentShuffler segmentShuffler,
                                         ImageUtils imageUtils,
                                         CryptoKeyManager cryptoKeyManager) {
        return new ImageDecryptorImpl(mandelbrotService, segmentShuffler, imageUtils, cryptoKeyManager);
    }
}