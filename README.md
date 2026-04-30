# Mandelbrot Crypto Core

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Java](https://img.shields.io/badge/Java-21-orange.svg)](https://www.oracle.com/java/)

**Библиотека шифрования изображений на основе ECDH и фракталов Мандельброта.**  
**Image encryption library based on ECDH and Mandelbrot fractals.**

---

## 📖 Описание | Description

**Русский**  
Mandelbrot Crypto Core — это Java-библиотека для шифрования изображений с использованием:

- **ECDH** (Elliptic Curve Diffie-Hellman) для согласования общего секрета между участниками
- **Фракталов Мандельброта** в качестве генератора ключевого потока
- **HKDF** для извлечения производных ключей
- **XOR** для наложения ключевого потока на изображение
- **Сегментного перемешивания** для дополнительной диффузии

Библиотека не зависит от JavaFX и UI-фреймворков. Может использоваться как со Spring Boot (автоконфигурация), так и без него (через фабрику `EncryptionModule`).

**English**  
Mandelbrot Crypto Core is a Java library for image encryption utilizing:

- **ECDH** (Elliptic Curve Diffie-Hellman) for shared secret agreement between parties
- **Mandelbrot fractals** as a keystream generator
- **HKDF** for deriving encryption keys
- **XOR** to apply the keystream to images
- **Segment shuffling** for added diffusion

The library has no dependencies on JavaFX or UI frameworks. It works both with Spring Boot (auto-configuration) and without it (via the `EncryptionModule` factory).

---

## 📦 Подключение | Installation

### Maven

```xml
<dependency>
    <groupId>io.github.dankotyt</groupId>
    <artifactId>mandelbrot-encryption-core</artifactId>
    <version>1.1.0</version>
</dependency>
```

### Gradle
```groovy
implementation 'io.github.dankotyt:mandelbrot-encryption-core:1.1.0'
```

# 🔧 Требования | Requirements
- Java 21 или выше / or higher
- Spring Boot 3.2+ (опционально / optional)

# 📄 Лицензия | License
Данный проект распространяется под лицензией MIT. Подробнее в файле LICENSE.

This project is licensed under the MIT License. See the LICENSE file for details.
