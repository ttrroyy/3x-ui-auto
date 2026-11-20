# 3x-ui-auto

Устанавливает [3x-ui](https://github.com/MHSanaei/3x-ui) с nginx, Let’s Encrypt и сайтом-заглушкой. VLESS REALITY и XHTTP используют один домен и TCP 443. Hysteria 2, AdGuard Home, блокировка подсетей и фильтр BitTorrent включаются отдельно.

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
| `-sguard y` · `-sguard status` · `-sguard uninstall` | Установить или переустановить блокировку подсетей, проверить статус или удалить. |
| `-btguard y` · `-btguard status` · `-btguard uninstall` | Установить или переустановить серверный фильтр BitTorrent, проверить статус или удалить. |
| `-backup y` · `-backup list` · `-backup restore ФАЙЛ` | Создать, показать или восстановить архив. Архивы хранятся в `/var/backups/x-ui`. |

**Порты.** nftables разрешает входящие TCP-порты SSH (обычно 22), 80 и 443, а при включённой Hysteria 2 — её UDP-порт. Пустой ввод выбирает свободный случайный порт. Проект управляет собственными таблицами nftables.

**Подсети сканеров.** Блокируются новые входящие подключения из списков IPv4 и IPv6. SSH и адреса из `/etc/3x-ui-auto/guard-allow.cidr` исключены. Списки обновляются примерно раз в шесть часов. Переустановка сохраняет источники и исключения.

**BitTorrent.** Локальный [детектор VIBEHOST с nDPI](assets/vh-dpid) проверяет первые пакеты соединения, nftables блокирует подтверждённый поток. Шифрование может скрыть протокол. Правила маршрутизации, заданные в Xray, управляются через 3x-ui.

После обновления старого общего guard фильтр BitTorrent устанавливается командой `-btguard y`.

**Источники:**

- shadow-netlab — [госсети](https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/government_networks.list), [сканеры](https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/antiscanner.list), [SKIPA](https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/skipa.list)
- C24Be — [blacklist.txt](https://raw.githubusercontent.com/C24Be/AS_Network_List/main/blacklists/blacklist.txt)
- CyberOK Skipa — [skipa_cidr.txt](https://raw.githubusercontent.com/tread-lightly/CyberOK_Skipa_ips/main/lists/skipa_cidr.txt)
- greatlists — [gn.lst](https://cdn.jsdelivr.net/gh/notacircle/greatlists@main/gn.lst), [sn.lst](https://cdn.jsdelivr.net/gh/notacircle/greatlists@main/sn.lst)

`/etc/3x-ui-auto/guard-sources.list` заменяет стандартные источники, по одному HTTPS URL на строку. После правки исключений выполните `systemctl restart 3x-ui-guard.service`.
