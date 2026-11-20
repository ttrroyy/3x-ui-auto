# vh-dpid

Детектор взят из [VIBEHOST Guard, коммит 5618743](https://github.com/VIBEHOST-LLC/vibehost-guard/tree/56187430be08bead591c6948c916bd4f9e3275df/vh-dpid) по лицензии [LGPL-3.0-or-later](COPYING). Текст базовой лицензии лежит в [COPYING.GPL-3.0](COPYING.GPL-3.0). При установке детектор собирается с [nDPI 6.0](https://github.com/ntop/nDPI/tree/1a5293396337f9a72dfee1fa070b2c4b0a0a3aaf) и LGPL-набором распознавателей. `bash build.sh /tmp/vh-dpid` позволяет пересобрать локальный бинарник.

Локальная политика помечает соединение по сигнатуре BitTorrent или если nDPI распознал его по содержимому пакетов, а адрес, порт и транспорт пира уже подтверждены. Guard запускает детектор без сохранения адресов и без отправки данных наружу.
