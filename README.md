# 3x-ui-auto

Устанавливает [3x-ui](https://github.com/MHSanaei/3x-ui) с nginx, Let’s Encrypt и сайтом-заглушкой. VLESS REALITY и XHTTP используют один домен и TCP 443. Hysteria 2, AdGuard Home и guard включаются по выбору.

Нужны root, Debian 12/13 или Ubuntu 24.04/26.04 и домен с A-записью на IPv4 сервера.

```bash
curl -fsSL https://raw.githubusercontent.com/ttrroyy/3x-ui-auto/main/3x-ui-auto.sh -o 3x-ui-auto.sh && bash 3x-ui-auto.sh -install y
```

Для остальных действий запускайте тот же скрипт с нужным флагом.

| Флаг | Действие |
| --- | --- |
| `-install y` | Установить. Повторный запуск после подтверждения удаляет прежнюю панель и клиентов, затем ставит заново. Сертификат того же домена используется повторно. |
| `-install y -version v3.11.0` | Установить указанную версию. |
| `-uninstall y` | Удалить панель, её компоненты и выданный установщиком сертификат. |
| `-adguard y` | Включить AdGuard Home с DoH по `/dns-query`. Повторный запуск применяет настройки и сохраняет данные AdGuard. |
| `-adguard-uninstall y` | Удалить AdGuard Home. |
| `-stguard y` | Установить или переустановить guard. Источники и исключения сохраняются при переустановке. |
| `-stguard status` | Проверить guard и таймер обновлений. |
| `-stguard uninstall` | Удалить guard и его настройки. |
| `-backup y` · `-backup list` · `-backup restore ФАЙЛ` | Создать, показать или восстановить архив. Архивы хранятся в `/var/backups/x-ui`. |

**Порты.** nftables разрешает входящие TCP-порты SSH (обычно 22), 80 и 443, а при включённой Hysteria 2 — её UDP-порт. Пустой ввод выбирает свободный случайный порт. Проект управляет собственными таблицами nftables.

**Guard.** Блокирует новые входящие подключения из публичных подсетей IPv4 и IPv6. SSH и исключения из `/etc/3x-ui-auto/guard-allow.cidr` проходят дальше. Списки обновляются примерно раз в шесть часов. BitTorrent проверяется по началу полезной нагрузки пакета: TCP-рукопожатие, UDP DHT и UDP-трекер. Шифрование и сегментация могут помешать распознаванию.

**Источники:**

- shadow-netlab — [госсети](https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/government_networks.list), [сканеры](https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/antiscanner.list), [SKIPA](https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/skipa.list)
- C24Be — [blacklist.txt](https://raw.githubusercontent.com/C24Be/AS_Network_List/main/blacklists/blacklist.txt)
- CyberOK Skipa — [skipa_cidr.txt](https://raw.githubusercontent.com/tread-lightly/CyberOK_Skipa_ips/main/lists/skipa_cidr.txt)
- greatlists — [gn.lst](https://cdn.jsdelivr.net/gh/notacircle/greatlists@main/gn.lst), [sn.lst](https://cdn.jsdelivr.net/gh/notacircle/greatlists@main/sn.lst)

`/etc/3x-ui-auto/guard-sources.list` заменяет стандартные источники, по одному HTTPS URL на строку. После правки исключений выполните `systemctl restart 3x-ui-guard.service`.
