# 3x-ui-auto

Автоматическая установка панели [3x-ui](https://github.com/MHSanaei/3x-ui) с модулями.

- Debian 12,13 / Ubuntu 24,26

---

## Защита от сканеров и торрентов

Ставится и удаляется отдельной командой, независимо от панели.

| Компонент | Описание |
|-----------|----------|
| Защита от сканеров | Блокирует новые входящие соединения из подсетей сканеров РКН и госсетей. Источники списков: [rkn-guard](https://github.com/Flecksis/rkn-guard), [remnanode-antiscan](https://github.com/HikaruApps/remnanode-antiscan) и [lucx-ui](https://github.com/AlexeyLCP/lucx-ui). SSH-порт не блокируется. |
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
