# 3x-ui-auto

Установка [3x-ui](https://github.com/MHSanaei/3x-ui) одной командой: VLESS REALITY и XHTTP на 443, Hysteria 2, nginx, SSL, сайт-заглушка, AdGuard DoH, Clash/Mihomo подписка, защита от сканеров и торрентов.

Debian 12, 13 / Ubuntu 24, 26. Нужен домен с A-записью на IPv4 сервера, один на всё.

## Установка

```bash
curl -fsSL https://raw.githubusercontent.com/ttrroyy/3x-ui-auto/main/3x-ui-auto.sh -o /root/3x-ui-auto.sh && bash /root/3x-ui-auto.sh -install y
```

Скрипт спросит:

1. Домен (проверяется A-запись)
2. Ставить ли AdGuard Home
3. DNS в xray: по умолчанию, Cloudflare, Google, Quad9, свой AdGuard или свой DoH
4. Добавлять ли Hysteria 2 и её UDP-порт. **Enter выберет случайный свободный порт**
5. Ставить ли защиту от сканеров и торрентов

В конце выводятся адрес панели, логин и пароль. Сохраните их.

Повторный запуск после подтверждения удаляет прежнюю установку вместе с клиентами и ставит заново. Сертификаты сохраняются.

Панель обновляется через саму 3x-ui.

## Удаление

```bash
curl -fsSL https://raw.githubusercontent.com/ttrroyy/3x-ui-auto/main/3x-ui-auto.sh -o /root/3x-ui-auto.sh && bash /root/3x-ui-auto.sh -uninstall y
```

Возвращает сервер к состоянию до установки. Сертификаты сохраняются.

## AdGuard Home

Отдельно ставится и удаляется на уже установленной панели. DoH: `https://<домен>/dns-query`, админка на случайном пути `/adg-<random>/`.

```bash
curl -fsSL https://raw.githubusercontent.com/ttrroyy/3x-ui-auto/main/3x-ui-auto.sh -o /root/3x-ui-auto.sh && bash /root/3x-ui-auto.sh -adguard y
```

```bash
curl -fsSL https://raw.githubusercontent.com/ttrroyy/3x-ui-auto/main/3x-ui-auto.sh -o /root/3x-ui-auto.sh && bash /root/3x-ui-auto.sh -adguard-uninstall y
```

## Защита от сканеров и торрентов

Работает и без панели, ставится и удаляется отдельно.

- **Сканеры:** блокирует подсети сканеров РКН и госсетей по спискам [rkn-guard](https://github.com/Flecksis/rkn-guard), [remnanode-antiscan](https://github.com/HikaruApps/remnanode-antiscan) и [lucx-ui](https://github.com/AlexeyLCP/lucx-ui). SSH не блокируется.
- **Торренты:** блокирует BitTorrent, DHT и трекеры по сигнатурам, в том числе у клиентов VPN. Зашифрованный BitTorrent может не распознаваться.

Списки обновляются сами (сканеры каждые 6 часов, торренты раз в сутки) без перезапусков и разрыва соединений.

```bash
curl -fsSL https://raw.githubusercontent.com/ttrroyy/3x-ui-auto/main/guard.sh -o /root/3x-ui-guard.sh && bash /root/3x-ui-guard.sh -install y
```

```bash
curl -fsSL https://raw.githubusercontent.com/ttrroyy/3x-ui-auto/main/guard.sh -o /root/3x-ui-guard.sh && bash /root/3x-ui-guard.sh -uninstall y
```

Состояние: `bash /usr/local/lib/3x-ui-auto/guard.sh -status y`

## Бэкап

```bash
curl -fsSL https://raw.githubusercontent.com/ttrroyy/3x-ui-auto/main/assets/backup/3x-ui-backup.sh -o /usr/local/bin/3x-ui-backup && bash /usr/local/bin/3x-ui-backup backup
```

Бэкапы лежат в `/var/backups/x-ui`, список: `bash /usr/local/bin/3x-ui-backup list`.

Восстановление, в том числе на чистом сервере:

```bash
curl -fsSL https://raw.githubusercontent.com/ttrroyy/3x-ui-auto/main/assets/backup/3x-ui-backup.sh -o /usr/local/bin/3x-ui-backup && bash /usr/local/bin/3x-ui-backup restore /var/backups/x-ui/<файл>.tar.gz
```

## Что ещё настраивается

- **Подписки:** обычная, JSON и Clash/Mihomo. Clash, Mihomo и Stash по той же ссылке получают готовый профиль, ссылка `/mihomo/` из панели тоже.
- **Гео ROSCOM и RUNET** рядом со стандартными. Скачиваются раз в неделю, применяются при следующем перезапуске x-ui, например при продлении сертификата.
- **Сертификат** Let's Encrypt продлевается сам. Только в момент продления, примерно раз в 60 дней, соединения коротко рвутся.
- **BBR + FQ** включены, переключаются в меню `x-ui`.
- **UFW** открывает SSH, 80, 443 и порт Hysteria 2. **fail2ban** для IP Limit панели.

## Параметры

| Параметр | Действие |
|----------|----------|
| `-install y` | Установка |
| `-version v3.11.0` | Версия 3x-ui вместе с `-install y`, по умолчанию последняя |
| `-uninstall y` | Удаление |
| `-adguard y` | Установить AdGuard Home |
| `-adguard-uninstall y` | Удалить AdGuard Home |
