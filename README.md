# 3x-ui-auto

Автоматическая установка панели [3x-ui](https://github.com/MHSanaei/3x-ui) с nginx, SSL, автосозданием инбаундов, сайтом-заглушкой, self-hosted DoH, fail2ban, защитой от сканеров и торрентов, настройкой DNS в xray и Clash/Mihomo подпиской.

- Debian 12, 13 / Ubuntu 24, 26
- Один домен или поддомен с A-записью на IPv4 VPS: общий для панели, подписок, DoH, REALITY, XHTTP и Hysteria 2.

---

## Что устанавливается

VLESS TCP REALITY и VLESS XHTTP TLS работают через порт 443, [Hysteria 2](https://github.com/apernet/hysteria) по желанию на выбранном UDP-порту.

| Компонент | Описание |
|-----------|----------|
| [3x-ui](https://github.com/MHSanaei/3x-ui) | VPN-панель, ставится штатным установщиком последней версии |
| [nginx](https://nginx.org/) | Обратный прокси, SNI-роутинг на 443 |
| [certbot](https://certbot.eff.org/) | Сертификат Let's Encrypt и автоматическое продление |
| Сайт-заглушка | Случайно сгенерированный статический сайт |
| AdGuard Home | По желанию: self-hosted DNS с блокировкой рекламы (DoH) |
| Защита от сканеров и торрентов | По желанию, см. ниже |
| [fail2ban](https://github.com/fail2ban/fail2ban) | Для IP Limit панели, настраивается самой 3x-ui |
| Гео ROSCOM и RUNET | `geoip_ROSCOM.dat`, `geosite_ROSCOM.dat` ([hydraponique](https://github.com/hydraponique)) и `geoip_RUNET.dat`, `geosite_RUNET.dat` ([runetfreedom](https://github.com/runetfreedom/russia-v2ray-rules-dat)) рядом со стандартными файлами панели. Обновляются раз в неделю, в воскресенье ночью; xray перезапускается, только если файлы изменились. Обновление панели их не удаляет. |
| BBR + FQ, UFW | Настройка сети и firewall. BBR включается и выключается в меню `x-ui`, выбор сохраняется после перезагрузки |

---

## Установка

```bash
curl -fsSL https://raw.githubusercontent.com/ttrroyy/3x-ui-auto/main/3x-ui-auto.sh -o /root/3x-ui-auto.sh && bash /root/3x-ui-auto.sh -install y
```

Скрипт по очереди спрашивает:

1. Домен. Проверяется, что A-запись указывает на IP сервера.
2. Ставить ли AdGuard Home.
3. DNS в xray: по умолчанию, DoH Cloudflare, Google, Quad9, self-hosted (AdGuard) или свой DoH.
4. Добавлять ли Hysteria 2. Если да, спрашивается UDP-порт. **Enter без ввода выберет случайный свободный порт.**
5. Ставить ли защиту от сканеров и торрентов.

Пустой или неверный ответ просто повторяет вопрос. После ответов начинается установка.

Повторный запуск полностью удаляет прежнюю установку и ставит новую после подтверждения. Клиенты и настройки удаляются, сертификаты сохраняются. Чтобы вернуть прежние данные, используйте восстановление из бэкапа.

Панель обновляется штатно, через саму 3x-ui.

**Полное удаление**

```bash
curl -fsSL https://raw.githubusercontent.com/ttrroyy/3x-ui-auto/main/3x-ui-auto.sh -o /root/3x-ui-auto.sh && bash /root/3x-ui-auto.sh -uninstall y
```

Возвращает файлы, пакеты, firewall и планировщик к состоянию до установки. Сертификаты сохраняются.

---

## Компоненты

```bash
curl -fsSL https://raw.githubusercontent.com/ttrroyy/3x-ui-auto/main/3x-ui-auto.sh -o /root/3x-ui-auto.sh && bash /root/3x-ui-auto.sh -components y
```

Выберите **Установить**, **Переустановить** или **Удалить**, затем компонент. В меню видно, какие компоненты активны.

| Компонент | Описание |
|-----------|----------|
| [AdGuard Home](https://github.com/AdguardTeam/AdGuardHome) | DoH: `https://<домен>/dns-query`, админка на случайном пути `/adg-<random>/`. Настройки и пароль сохраняются при переустановке. Если Xray использует этот DoH, удаление потребует подтверждения. |
| Защита от сканеров и торрентов | То же, что отдельный скрипт защиты ниже. |

---

## Защита от сканеров и торрентов

Ставится и удаляется отдельной командой, независимо от панели.

| Защита | Описание |
|--------|----------|
| От сканеров | Блокирует новые входящие соединения из подсетей сканеров РКН и госсетей. Источники списков: [rkn-guard](https://github.com/Flecksis/rkn-guard), [remnanode-antiscan](https://github.com/HikaruApps/remnanode-antiscan) и [lucx-ui](https://github.com/AlexeyLCP/lucx-ui). SSH-порт не блокируется. |
| [VibeHost Guard](https://github.com/VIBEHOST-LLC/vibehost-guard) | Блокировка торрент-трафика по сигнатурам BitTorrent/DHT, без ключа и регистрации. Зашифрованный BitTorrent может не распознаваться. |

Списки сканеров обновляются каждые 6 часов, сигнатуры торрентов раз в сутки. Обновление атомарно подменяет списки в ядре, без перезапуска служб и без разрыва текущих соединений. Если источник недоступен, вернул мусор или сократился больше чем вдвое, остаётся его прошлая копия. Правила проверяются каждые 5 минут и восстанавливаются после перезагрузки.

**Установить**

```bash
curl -fsSL https://raw.githubusercontent.com/ttrroyy/3x-ui-auto/main/guard.sh -o /root/3x-ui-guard.sh && bash /root/3x-ui-guard.sh -install y
```

**Удалить**

```bash
curl -fsSL https://raw.githubusercontent.com/ttrroyy/3x-ui-auto/main/guard.sh -o /root/3x-ui-guard.sh && bash /root/3x-ui-guard.sh -uninstall y
```

**Состояние**

```bash
bash /usr/local/lib/3x-ui-auto/guard.sh -status y
```

Список источников: `/etc/3x-ui-auto/guard-sources.list`, по одному URL на строку.

---

## Параметры запуска

| Параметр | Описание |
|----------|----------|
| `-install y` | Полная установка |
| `-version <версия>` | Версия 3x-ui для установки, например `v3.11.0`, по умолчанию последняя |
| `-uninstall y` | Полное удаление с сохранением сертификатов |
| `-components y` | Меню установки, переустановки и удаления компонентов |

---

## Clash/Mihomo подписка

Работает через определение User-Agent, один URL с разным поведением:

• Clash / Mihomo / Stash получают clash.yaml с готовой конфигурацией

• Обычный браузер и другие клиенты получают стандартную подписку 3x-ui

Ссылка Clash в панели (`https://<домен>/mihomo/<subId>`) отдаёт тот же готовый профиль.

---

## Бэкап и восстановление

**Установить скрипт бэкапа**

```bash
curl -fsSL https://raw.githubusercontent.com/ttrroyy/3x-ui-auto/main/assets/backup/3x-ui-backup.sh -o /usr/local/bin/3x-ui-backup && chmod +x /usr/local/bin/3x-ui-backup
```

Каждая команда ниже скачивает свежую версию скрипта бэкапа, отдельная предварительная установка не нужна.

**Создать бэкап**

```bash
curl -fsSL https://raw.githubusercontent.com/ttrroyy/3x-ui-auto/main/assets/backup/3x-ui-backup.sh -o /usr/local/bin/3x-ui-backup && bash /usr/local/bin/3x-ui-backup backup
```

**Список бэкапов**

```bash
curl -fsSL https://raw.githubusercontent.com/ttrroyy/3x-ui-auto/main/assets/backup/3x-ui-backup.sh -o /usr/local/bin/3x-ui-backup && bash /usr/local/bin/3x-ui-backup list
```

**Восстановить из бэкапа** (на чистом сервере, пакеты ставятся автоматически)

```bash
curl -fsSL https://raw.githubusercontent.com/ttrroyy/3x-ui-auto/main/assets/backup/3x-ui-backup.sh -o /usr/local/bin/3x-ui-backup && bash /usr/local/bin/3x-ui-backup restore /var/backups/x-ui/3x-ui-backup-20260101-120000.tar.gz
```

Бэкап включает: БД и бинарники панели, nginx, SSL, сайт-заглушку, Clash/Mihomo, AdGuard Home, защиту от сканеров и торрентов, BBR/FQ, fail2ban, UFW, systemd и cron. На время бэкапа панель коротко останавливается.

---

## Поддержать проект

Понравилось? Поставьте ⭐ репозиторию: это помогает другим найти проект и поддерживает разработку.
