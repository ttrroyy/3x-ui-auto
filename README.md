# 3x-ui-auto

Устанавливает [3x-ui](https://github.com/MHSanaei/3x-ui), nginx и сертификат Let's Encrypt. VLESS REALITY и VLESS XHTTP работают на одном домене и порту 443. Опционально доступны Hysteria 2, AdGuard Home и guard. Есть заглушка и подписки в обычном, JSON и Clash/Mihomo форматах.

Нужны root, Debian 12/13 или Ubuntu 24.04/26.04 и домен с A-записью на IPv4 сервера.

## Панель

```bash
curl -fsSL https://raw.githubusercontent.com/ttrroyy/3x-ui-auto/main/3x-ui-auto.sh -o /root/3x-ui-auto.sh
bash /root/3x-ui-auto.sh -install y
```

Скрипт спросит домен, DNS и какие компоненты включить. Пустой порт Hysteria 2 означает случайный свободный UDP-порт. Адрес панели и пароль появятся в конце. Обновление версии панели доступно через 3x-ui.

| Параметр | Действие |
| --- | --- |
| `-install y` | Установка. Повторный запуск после подтверждения удаляет старую панель и клиентов, затем устанавливает заново. Сертификат того же домена используется повторно. |
| `-install y -version v3.11.0` | Установка указанной версии панели. По умолчанию ставится последний стабильный релиз. |
| `-uninstall y` | Удаление панели, её компонентов и сертификатов, выпущенных установщиком. Сторонние сертификаты сохраняются. |
| `-adguard y` | Установка AdGuard Home на существующую панель. DoH доступен по `/dns-query`. |
| `-adguard-uninstall y` | Отдельное удаление AdGuard Home. |

**Порты UFW.** Скрипт разрешает входящие TCP-порты SSH (обычно 22), 80 и 443, а также UDP-порт Hysteria 2, если она включена. Политика входящего трафика — deny, исходящего и транзитного — allow. Старые правила UFW сохраняются.

**XHTTP.** Клиент подключается к домену на `443/tcp` по VLESS + TLS, с SNI и Host этого домена, ALPN `h2,http/1.1`, режимом `auto` и путём из инбаунда. nginx завершает TLS на `127.0.0.1:7443` и передаёт XHTTP в `127.0.0.1:10080` через `grpc_pass`.

## Guard

Работает отдельно от панели. Блокирует новые входящие соединения из публичных подсетей IPv4 и IPv6. Из источников принимаются префиксы от `/16` (IPv4) и `/32` (IPv6). Локальные источники и TCP-порты SSH исключены.

BitTorrent проверяется по TCP-рукопожатию, UDP-запросам и ответам DHT и UDP-запросу подключения к трекеру. Фильтр смотрит отдельные пакеты в первых 4 КиБ соединения. Шифрование и разбиение сигнатуры между пакетами могут помешать распознаванию. Профиль Mihomo при установке с guard также блокирует известные торрент-клиенты по имени процесса.

Таймер проверяет правила каждые пять минут, скачивает списки примерно раз в шесть часов и сохраняет последнюю принятую копию каждого источника при ошибке. По умолчанию используются:

- shadow-netlab — [госсети](https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/government_networks.list), [сканеры](https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/antiscanner.list), [SKIPA](https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/skipa.list)
- C24Be — [blacklist.txt](https://raw.githubusercontent.com/C24Be/AS_Network_List/main/blacklists/blacklist.txt)
- CyberOK Skipa — [skipa_cidr.txt](https://raw.githubusercontent.com/tread-lightly/CyberOK_Skipa_ips/main/lists/skipa_cidr.txt)
- greatlists — [gn.lst](https://cdn.jsdelivr.net/gh/notacircle/greatlists@main/gn.lst), [sn.lst](https://cdn.jsdelivr.net/gh/notacircle/greatlists@main/sn.lst)

```bash
curl -fsSL https://raw.githubusercontent.com/ttrroyy/3x-ui-auto/main/guard.sh -o /root/3x-ui-guard.sh
bash /root/3x-ui-guard.sh -install y
bash /usr/local/lib/3x-ui-auto/guard.sh -status y
bash /usr/local/lib/3x-ui-auto/guard.sh -uninstall y
```

Повторная установка пересоздаёт правила, службы и кеш, сохраняя настройки. Удаление убирает и настройки. Для исключений используйте `/etc/3x-ui-auto/guard-allow.cidr` (IP или CIDR на строку), затем выполните `bash /usr/local/lib/3x-ui-auto/guard.sh load`. `/etc/3x-ui-auto/guard-sources.list` заменяет стандартные источники, по одному HTTPS URL на строку.

## Резервные копии

```bash
curl -fsSL https://raw.githubusercontent.com/ttrroyy/3x-ui-auto/main/assets/backup/3x-ui-backup.sh -o /usr/local/bin/3x-ui-backup
bash /usr/local/bin/3x-ui-backup backup
bash /usr/local/bin/3x-ui-backup list
bash /usr/local/bin/3x-ui-backup restore /путь/к/архиву.tar.gz
```

Архивы сохраняются в `/var/backups/x-ui`.
