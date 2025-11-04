# Защита от Traffic Flow Watermarking в wstunnel

## Что было реализовано

Добавлена полная система защиты от ML-based анализа трафика, которая противодействует системам DPI (Deep Packet Inspection), использующим машинное обучение для обнаружения туннелей.

## Проблема

Современные системы цензуры (GFW, коммерческие DPI) используют ML-модели для классификации зашифрованного трафика по:
- **Размерам пакетов**: Последовательности вроде [512, 1024, 256, ...]
- **Inter-Arrival Time (IAT)**: Временные промежутки между пакетами
- **Burst patterns**: Группы пакетов, отправленных подряд
- **Статистическим характеристикам**: Среднее, дисперсия, энтропия

Даже через TLS/WebSocket эти метаданные позволяют идентифицировать туннель с точностью >90%.

## Решение

### 1. Adversarial Padding
Добавление padding, который специально разработан для обмана ML-классификаторов:

- **Directional Padding** (рекомендуется): Малые пакеты делаются больше
- **FRONT Padding**: Весь padding в первый пакет burst
- **TOTAL Padding**: Padding до фиксированного размера burst
- **Adaptive Padding**: Динамический выбор стратегии
- **Random Padding**: Случайный padding

### 2. IAT Randomization
Рандомизация времени между пакетами:
- Контролируемые задержки
- Имитация реалистичного поведения приложений
- Интеграция с traffic profiles

### 3. Dummy Packet Injection (опционально)
Инжекция фиктивных пакетов:
- Изменяет статистику потока
- Добавляет overhead (использовать осторожно)

### 4. Frame Splitting
Разбиение данных на фреймы с реалистичными размерами:
- Безопасно для бинарных протоколов (SSH, etc.)
- Не модифицирует tunneled data
- Использует размеры из traffic profiles

## Использование

### Базовое

```bash
# Клиент с защитой от ML (default настройки)
wstunnel client \
  --adversarial-ml-defense \
  -L tcp://8080:example.com:80 \
  wss://server.com
```

### Обход GFW (Great Firewall)

```bash
wstunnel client \
  --adversarial-ml-defense \
  --adversarial-padding-strategy adaptive \
  --adversarial-iat-randomization 0.7 \
  --traffic-profile chrome-browsing \
  -L socks5://127.0.0.1:1080 \
  wss://server.com
```

### SSH через DPI

```bash
# Запустить туннель
wstunnel client \
  --adversarial-ml-defense \
  --adversarial-padding-strategy directional \
  --adversarial-iat-randomization 0.6 \
  -L tcp://2222:target.com:22 \
  wss://tunnel-server.com

# Подключиться через туннель
ssh -p 2222 user@localhost
```

### Максимальная скрытность

```bash
wstunnel client \
  --adversarial-ml-defense \
  --adversarial-padding-strategy adaptive \
  --adversarial-iat-randomization 0.9 \
  --adversarial-dummy-packets \
  --adversarial-dummy-packet-rate 10.0 \
  --traffic-profile chrome-browsing \
  -L socks5://127.0.0.1:1080 \
  wss://server.com
```

## Параметры

### `--adversarial-ml-defense`
Включить защиту от ML (обязательный параметр для использования остальных).

### `--adversarial-padding-strategy <STRATEGY>`
Стратегия padding:
- `directional` (по умолчанию) - эффективно, малый overhead
- `front` - для early classifiers
- `total` - для burst-based classifiers
- `adaptive` - самый продвинутый
- `random` - базовая защита

### `--adversarial-iat-randomization <LEVEL>`
Уровень IAT рандомизации (0.0 - 1.0):
- `0.0` - нет рандомизации
- `0.5` - умеренная (по умолчанию, рекомендуется)
- `0.7` - агрессивная (для высокой цензуры)
- `1.0` - максимальная (добавляет существенную задержку)

### `--adversarial-dummy-packets`
Включить инжекцию dummy packets (добавляет bandwidth overhead).

### `--adversarial-dummy-packet-rate <RATE>`
Частота dummy packets в секунду (по умолчанию: 5.0).

### `--traffic-profile <PROFILE>`
Профиль приложения для имитации:
- `chrome-browsing` - Chrome WebSocket
- `webrtc-video` - WebRTC video
- `discord-voice` - Discord voice
- Или путь к PCAP файлу (требует `--features pcap-learning`)

## Создание custom profile из PCAP

```bash
# 1. Захватить реальный трафик
tcpdump -i any 'host zoom.us and port 443' -w zoom.pcap -c 10000

# 2. Собрать wstunnel с поддержкой PCAP
cargo build --release --features pcap-learning

# 3. Использовать профиль
wstunnel client \
  --adversarial-ml-defense \
  --traffic-profile zoom.pcap \
  -L ... wss://...
```

## Влияние на производительность

| Конфигурация | Bandwidth Overhead | Latency |
|--------------|-------------------|---------|
| Directional padding | ~5-15% | Минимальная |
| + IAT random (0.5) | ~5-15% | +10-30ms |
| + IAT random (0.9) | ~5-15% | +50-100ms |
| + Dummy packets (5/s) | ~20-30% | +10-30ms |
| + Dummy packets (15/s) | ~40-60% | +10-30ms |

## Рекомендации по использованию

### Когда использовать

✅ **Используйте когда:**
- В странах с высокой цензурой (Китай, Иран, и т.д.)
- DPI системы обнаруживают ваш туннель
- Нужна максимальная скрытность
- Коммерческие DPI решения блокируют трафик

### Когда НЕ использовать

❌ **Не используйте когда:**
- Низкий уровень угрозы
- Критична производительность
- Ограничен bandwidth
- Достаточно базовой обфускации

### Рекомендованные настройки

**Общее использование:**
```bash
--adversarial-ml-defense \
--adversarial-padding-strategy directional \
--adversarial-iat-randomization 0.5
```

**Обход GFW:**
```bash
--adversarial-ml-defense \
--adversarial-padding-strategy adaptive \
--adversarial-iat-randomization 0.7 \
--traffic-profile chrome-browsing
```

**Низкая задержка (игры, VoIP):**
```bash
--adversarial-ml-defense \
--adversarial-padding-strategy directional \
--adversarial-iat-randomization 0.3
```

## Безопасность

### Сильные стороны

✅ Специально разработано для обмана ML-классификаторов  
✅ Имитирует легитимный трафик приложений  
✅ Настраиваемый баланс stealth/performance  
✅ Основано на академических исследованиях  

### Ограничения

⚠️ Не идеально - продвинутые adversarial ML могут обнаружить  
⚠️ Не защищает от active probing  
⚠️ Не скрывает общий объем трафика  
⚠️ Dummy packets добавляют overhead  

## Тестирование

```bash
# Включить debug логи
export RUST_LOG=debug

wstunnel client --adversarial-ml-defense -L ... wss://...

# Смотрите логи:
# - "Adversarial ML defense enabled"
# - "Applied adversarial padding"
# - "IAT randomization active"
```

## Дополнительная документация

- **[adversarial_ml_defense.md](./adversarial_ml_defense.md)** - Полная техническая документация
- **[examples_adversarial_ml.md](./examples_adversarial_ml.md)** - Практические примеры
- **[IMPLEMENTATION_SUMMARY.md](./IMPLEMENTATION_SUMMARY.md)** - Детали реализации

## Академические источники

Реализация основана на:

1. **"Walkie-Talkie: An Efficient Defense Against Passive Website Fingerprinting"** (USENIX 2017)
2. **"Effective Attacks and Defenses for Website Fingerprinting"** (USENIX 2014)
3. **"A Multi-tab Website Fingerprinting Attack"** (ACSAC 2020)
4. **"Deep Fingerprinting: Undermining Website Fingerprinting Defenses with Deep Learning"** (CCS 2018)

## Поддержка

Если нашли баг или есть вопросы:
- GitHub Issues: https://github.com/erebe/wstunnel/issues
- Документация: в этой папке (`docs/`)

## Лицензия

Та же что и основной проект wstunnel.

