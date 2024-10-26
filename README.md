# tcpdump2

## Описание

Скрипт `tcpdump2` предназначен для автоматизации 
работы с утилитой `tcpdump`, упрощая процесс диагностики и поиска неисправностей в сетевых соединениях. 

В этом скрипте уже предустановлены различные фильтры, которые позволяют быстро и эффективно анализировать трафик, выявлять аномалии и исследовать сетевые атаки. 
Конечно, можно использовать `tcpdump` и без этого скрипта, но с ним ваша работа станет гораздо удобнее и продуктивнее. 

Мы всегда открыты для улучшений: если вы заметите недочёты или у вас есть идеи, как сделать скрипт лучше, будем рады вашим предложениям!

## Установка

Чтобы установить `tcpdump2`, выполните следующие 
команды в терминале:

```bash
git clone https://github.com/mnbarinov/tcpdump2.git
cd tcpdump2
chmod +x tcpdump2.sh
ln -s $(pwd)/tcpdump2.sh /usr/local/bin/tcpdump2
```
## Установка tcpdump

Не забудьте, что на вашем сервере или компьютере 
должен быть установлен tcpdump. Ниже приведены команды для установки tcpdump на популярных дистрибутивах:

### Debian/Ubuntu:
```bash
sudo apt update
sudo apt install tcpdump
```
### CentOS/RHEL
```bash
sudo yum install tcpdump
```
### Fedora
```bash
sudo dnf install tcpdump
```
### Arch Linux
```bash
sudo pacman -S tcpdump
```
# Синтаксис команды

После установки скрипта вы можете использовать его, выполнив команду в следующем формате:
```bash
tcpdump2 -i <имя_интерфейса> <ФИЛЬТР> [другие стандартные фильтры tcpdump]
```
Параметры:

    <имя_интерфейса> — название сетевого интерфейса (например, eth0).
    <ФИЛЬТР> — один из предустановленных фильтров или пользовательский фильтр.
    [другие стандартные фильтры tcpdump] — любые дополнительные параметры, поддерживаемые tcpdump.

    Выполните команду tcpdump2 без параметров, чтобы увидеть доступные фильтры

# Примеры использования

## Для захвата трафика HTTP:

```bash
tcpdump2 -i eth0 web
```

## Для выявления аномалий в сети:

```bash
tcpdump2 -i eth0 anomaly
```

## Для мониторинга BGP:

```bash
tcpdump2 -i eth0 bgp
```


# Контрибьюция

Если у вас есть идеи по улучшению скрипта или вы нашли ошибки, не стесняйтесь открывать запросы на изменение (pull requests) или оставлять свои замечания в разделе Issues.

Спасибо за использование tcpdump2! Надеемся, он станет полезным инструментом в вашей работе.
