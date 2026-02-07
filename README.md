# ddos_combo_guard (C++ + libpcap)

`ddos_combo_guard` — это простой IDS/IPS-скрипт на **C++ + libpcap**, который анализирует входящий трафик в реальном времени и обнаруживает (и при необходимости блокирует) **мультивекторные DDoS-атаки** уровня **L3/L4/L7**.

Программа ориентирована на сценарии, где атака идёт “в два слоя”:

- **UDP Flood + HTTP Flood**
- **DNS Amp / Reflection + SYN Flood**
- **HTTPS Flood + Slowloris**
- **Reflection + API Flood**

> ⚠️ Важно: если канал уже полностью забит, никакой pcap-детект не спасёт.  
> Но если трафик ещё проходит — авто-блокировка через **nftables** реально режет нагрузку в ядре.

---

## Возможности

### L3 / L4 защита
- **UDP Flood**
  - считает PPS/Bps глобально и per-source
- **Reflection / Amplification**
  - детектит UDP пакеты с `sport` из списка усиления (DNS/NTP/SSDP/…)
  - считает отдельный поток amp-пакетов
- **SYN Flood**
  - считает `SYN` на порты 80/443 (per-src + global)

### L7 защита
- **HTTP Flood (порт 80)**
  - парсит HTTP request line
  - считает RPS per-src и global
- **API Flood**
  - отдельный лимит для `/api`, `/v1`, `/v2`, `/graphql`
- **Slowloris (порт 80)**
  - если заголовки не завершены (`\r\n\r\n`) дольше N секунд → блок
- **HTTPS Flood (порт 443)**
  - считает новые соединения (SYN) на 443
- **TLS “Slowloris-like”**
  - детектит большое количество открытых 443-соединений с очень маленьким объёмом данных

### Комбо-детект
Дополнительно выводит `[COMBO]` алерты, если одновременно активны 2 вектора атаки.

---

## Требования

- Linux (рекомендуется)
- `libpcap-dev`
- `g++`
- root или capability `cap_net_raw` для sniffing
- (опционально) `nftables` или `iptables`

---

## Запуск
1) Показать интерфейсы
sudo ./ddos_combo_guard -l

2) Запуск (только детект, без блокировок)
sudo ./ddos_combo_guard eth0

3) Запуск с авто-блокировкой (рекомендуется nftables)
sudo ./ddos_combo_guard eth0 --apply --fw nft --block-seconds 300

4) Включить “amp shield” (жёсткий дроп отражёнки)

Если на сервере не нужны входящие ответы с amp-портов (DNS/NTP/SSDP/…):

sudo ./ddos_combo_guard eth0 --apply --fw nft --block-seconds 300 --enable-amp-shield


⚠️ Осторожно: --enable-amp-shield добавляет правило:
drop udp sport @amp_sports

Если сервер реально использует DNS/NTP/и т.д. на вход — это может “сломать” легитимный трафик.

5) Запуск через iptables
sudo ./ddos_combo_guard eth0 --apply --fw iptables --block-seconds 300


⚠️ В текущей версии iptables-блоки без таймаута (iptables не умеет timeout без ipset).
Для продакшна лучше использовать nftables.

| Параметр              | Описание                                                   |
| --------------------- | ---------------------------------------------------------- |
| `-l`                  | Показать список сетевых интерфейсов                        |
| `<iface>`             | Имя интерфейса (например `eth0`, `ens3`, `enp0s3`)         |
| `--apply`             | Включить блокировки IP (режим IPS)                         |
| `--fw nft`            | Использовать nftables (рекомендуется)                      |
| `--fw iptables`       | Использовать iptables                                      |
| `--block-seconds N`   | Время бана IP в секундах                                   |
| `--enable-amp-shield` | Включить дроп UDP пакетов с source-port из списка усиления |

