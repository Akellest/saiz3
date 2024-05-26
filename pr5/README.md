# Использование технологии Yandex Query для анализа данных сетевой
активности №5

## Цель работы

1.  Изучить возможности СУБД Clickhouse для обработки и анализ больших
    данных
2.  Получить навыки применения Clickhouse совместно с языком
    программирования R
3.  Получить навыки анализа метаинфомации о сетевом трафике
4.  Получить навыки применения облачных технологий хранения, подготовки
    и анализа данных: Managed Service for ClickHouse, Rstudio Server

## Исходные данные

-   Windows 11
-   RStudio
-   Yandex Object Storage
-   Clickhouse

## Общая ситуация

Вы – специалист по информационной безопасности компании “СуперМегатек”.
Вы, являясь специалистом Threat Hunting, часто используете информацию о
сетевом трафике для обнаружения подозрительной и вредоносной активности.
Помогите защитить Вашу компанию от международной хакерской группировки
AnonMasons.

У Вас есть данные сетевой активности в корпоративной сети компании
“СуперМегатек”. Данные хранятся в Yandex Object Storage.

## Задание

Используя язык программирования R, библиотеку ClickhouseHTTP и облачную
IDE Rstudio Server, развернутую в Yandex Cloud, выполнить задания и
составить отчет.

## Задачи

-   Задание 1: Надите утечку данных из Вашей сети
-   Задание 2: Надите утечку данных 2
-   Задание 3: Надите утечку данных 3
-   Задание 4: Обнаружение канала управления
-   Задание 5: Обнаружение P2P трафика
-   Задание 6: Чемпион малвари
-   Задание 7: Скрытая бот-сеть
-   Задание 8: Внутренний сканнер

## Ход работы

Подготовка рабочего пространства

``` r
install.packages("ClickHouseHTTP", repos = "https://cran.r-project.org")
```

    Installing package into '/home/user24/R/x86_64-pc-linux-gnu-library/4.3'
    (as 'lib' is unspecified)

``` r
library(ClickHouseHTTP)
library(dplyr)
```


    Attaching package: 'dplyr'

    The following objects are masked from 'package:stats':

        filter, lag

    The following objects are masked from 'package:base':

        intersect, setdiff, setequal, union

``` r
library(lubridate)
```


    Attaching package: 'lubridate'

    The following objects are masked from 'package:base':

        date, intersect, setdiff, union

``` r
library(tidyverse)
```

    ── Attaching core tidyverse packages ──────────────────────── tidyverse 2.0.0 ──
    ✔ forcats 1.0.0     ✔ stringr 1.5.1
    ✔ ggplot2 3.4.4     ✔ tibble  3.2.1
    ✔ purrr   1.0.2     ✔ tidyr   1.3.1
    ✔ readr   2.1.5     

    ── Conflicts ────────────────────────────────────────── tidyverse_conflicts() ──
    ✖ dplyr::filter() masks stats::filter()
    ✖ dplyr::lag()    masks stats::lag()
    ℹ Use the conflicted package (<http://conflicted.r-lib.org/>) to force all conflicts to become errors

``` r
library(ClickHouseHTTP)
library(DBI)
connection <- dbConnect(
  ClickHouseHTTP::ClickHouseHTTP(),
  host="rc1d-sbdcf9jd6eaonra9.mdb.yandexcloud.net",
  port=8443,
  user="student24dwh",
  password="DiKhuiRIVVKdRt9XON",
  db="TMdata",
  https=TRUE,
  ssl_verifypeer=FALSE)
database<-dbReadTable(connection, "data")
data <- dbGetQuery(connection, "SELECT * FROM data")
```

``` r
data <- data %>%
  mutate(timestamp = as_datetime(timestamp/1000, origin = "1970-01-01", tz = "UTC"))
data %>% glimpse()
```

    Rows: 105,747,730
    Columns: 5
    $ timestamp <dttm> 2020-01-06 16:00:00, 2020-01-06 16:00:00, 2020-01-06 16:00:…
    $ src       <chr> "13.43.52.51", "16.79.101.100", "18.43.118.103", "15.71.108.…
    $ dst       <chr> "18.70.112.62", "12.48.65.39", "14.51.30.86", "14.50.119.33"…
    $ port      <int> 40, 92, 27, 57, 115, 92, 65, 123, 79, 72, 123, 123, 22, 118,…
    $ bytes     <int> 57354, 11895, 898, 7496, 20979, 8620, 46033, 1500, 979, 1036…

### Задание 1: Надите утечку данных из Вашей сети

Важнейшие документы с результатами нашей исследовательской деятельности
в области создания вакцин скачиваются в виде больших заархивированных
дампов. Один из хостов в нашей сети используется для пересылки этой
информации – он пересылает гораздо больше информации на внешние ресурсы
в Интернете, чем остальные компьютеры нашей сети. Определите его
IP-адрес.

``` r
result <- data %>%
  filter(grepl("^12\\.|^13\\.|^14\\.", src)) %>%
  group_by(src) %>%
  summarise(total_bytes = sum(bytes)) %>%
  arrange(desc(total_bytes)) %>%
  head(1)
src1 <- result %>% collect()

src1$src
```

    [1] "13.37.84.125"

### Задание 2: Надите утечку данных 2

Другой атакующий установил автоматическую задачу в системном
планировщике cron для экспорта содержимого внутренней wiki системы. Эта
система генерирует большое количество трафика в нерабочие часы, больше
чем остальные хосты. Определите IP этой системы. Известно, что ее IP
адрес отличается от нарушителя из предыдущей задачи.

``` r
data_local <- collect(data)
data_local <- data_local %>%
  mutate(hour = hour(as.POSIXlt(timestamp, origin = "1970-01-01", tz = "UTC")))

work_time <- data_local %>%
  group_by(hour) %>%
  summarise(traffic = sum(bytes)) %>%
  arrange(traffic)
work_time
```

    # A tibble: 24 × 2
        hour     traffic
       <int>       <dbl>
     1     5 10296318981
     2    15 10297437556
     3    11 10306926607
     4    10 10320411897
     5     1 10324774067
     6     0 10338294625
     7     3 10339156776
     8     9 10339532889
     9     6 10341154093
    10     4 10342139110
    # ℹ 14 more rows

``` r
data2 <- collect(data)
result <- data2 %>%
  filter(grepl("^12\\.|^13\\.|^14\\.", src)) %>%
  filter(between(hour(timestamp), 0, 16)) %>%
  filter(!str_detect(src, "^13.37.84.125$")) %>%
  group_by(src) %>%
  summarise(sum_traffic = sum(bytes)) %>%
  arrange(desc(sum_traffic)) %>%
  head(1)
src2 <- result %>% collect()
src2$src
```

    [1] "12.55.77.96"

### Задание 3: Надите утечку данных 3

Еще один нарушитель собирает содержимое электронной почты и отправляет в
Интернет используя порт, который обычно используется для другого типа
трафика. Атакующий пересылает большое количество информации используя
этот порт, которое нехарактерно для других хостов, использующих этот
номер порта. Определите IP этой системы. Известно, что ее IP адрес
отличается от нарушителей из предыдущих задач.

``` r
average_traffic <- data %>%
  filter(grepl("^12\\.|^13\\.|^14\\.", src)) %>%
  group_by(port) %>%
  summarise(avg_traffic = mean(bytes)) %>%
  collect()

max_traffic <- data %>%
  filter(grepl("^12\\.|^13\\.|^14\\.", src)) %>%
  group_by(port) %>%
  summarise(max_traffic = max(bytes)) %>%
  collect()

result <- data %>%
  filter(grepl("^12\\.|^13\\.|^14\\.", src)) %>%
  filter(!str_detect(src, "^13.37.84.125$")) %>%
  filter(!str_detect(src, "^12.55.77.96$")) %>%
  group_by(src, port) %>%
  summarise(total_traffic = sum(bytes), .groups = 'drop') %>%
  left_join(average_traffic, by = "port") %>%
  left_join(max_traffic, by = "port") %>%
  mutate(traffic_ratio = total_traffic / avg_traffic) %>%
  head(1) %>%
  collect()

s <- result$src
s
```

    [1] "12.30.105.68"

### Задание 4: Обнаружение канала управления

Зачастую в корпоротивных сетях находятся ранее зараженные системы,
компрометация которых осталась незамеченной. Такие системы генерируют
небольшое количество трафика для связи с панелью управления бот-сети, но
с одинаковыми параметрами – в данном случае с одинаковым номером порта.
Какой номер порта используется бот-панелью для управления ботами?

``` r
average_bytes <- mean(data$bytes)

port_counts <- data %>%
  group_by(port) %>%
  summarise(unique_combinations = n_distinct(paste(src, dst))) %>%
  ungroup()

f_port <- port_counts %>%
  left_join(data, by = "port") %>%
  filter(bytes < average_bytes) %>%
  arrange(desc(unique_combinations)) %>%
  slice(1)

f_port$port
```

    [1] 56

### Задание 5: Обнаружение P2P трафика

Иногда компрометация сети проявляется в нехарактерном трафике между
хостами в локальной сети, который свидетельствует о горизонтальном
перемещении (lateral movement). В нашей сети замечена система, которая
ретранслирует по локальной сети полученные от панели управления бот-сети
команды, создав таким образом внутреннюю пиринговую сеть. Какой
уникальный порт используется этой бот сетью для внутреннего общения
между собой?

``` r
average_bytes <- mean(data$bytes)

port_counts <- data %>%
  filter(grepl("^12\\.|^13\\.|^14\\.", src)) %>%
  filter(grepl("^12\\.|^13\\.|^14\\.", dst)) %>%
  group_by(port) %>%
  summarise(unique_combinations = n_distinct(paste(src, dst))) %>%
  ungroup()

f_port <- port_counts %>%
  left_join(data, by = "port") %>%
  filter(bytes < average_bytes) %>%
  arrange(desc(unique_combinations)) %>%
  slice(1)

f_port$port
```

    [1] 40

### Задание 6: Чемпион малвари

Нашу сеть только что внесли в списки спам-ферм. Один из хостов сети
получает множество команд от панели C&C, ретранслируя их внутри сети. В
обычных условиях причин для такого активного взаимодействия внутри сети
у данного хоста нет. Определите IP такого хоста.

``` r
bot_hosts <- data %>%
  filter(grepl("^12\\.|^13\\.|^14\\.", src)) %>%
  filter(grepl("^12\\.|^13\\.|^14\\.", dst)) %>%
  group_by(src) %>%
  summarise(total_commands = n()) %>%
  arrange(desc(total_commands)) %>%
  head(1)
bot_hosts$src
```

    [1] "13.42.70.40"

### Задание 7: Скрытая бот-сеть

В нашем трафике есть еще одна бот-сеть, которая использует очень большой
интервал подключения к панели управления. Хосты этой продвинутой
бот-сети не входят в уже обнаруженную нами бот-сеть. Какой порт
используется продвинутой бот-сетью для коммуникации?

``` r
# Преобразование временных меток в формат POSIXct
l_data <- data %>%
  mutate(timestamp = as.POSIXct(timestamp, origin = "1970-01-01", tz = "UTC"))

ndata <- data %>%
  filter(grepl("^12\\.|^13\\.|^14\\.", src)) %>%
  filter(grepl("^12\\.|^13\\.|^14\\.", dst))

ndata <- ndata %>%
  mutate(timestamp = as.POSIXct(timestamp)) %>%
  group_by(src) %>%
  summarise(
    unique_dst_count = n_distinct(dst),
    avg_timestamp = mean(timestamp)
  ) %>%
  arrange(unique_dst_count, avg_timestamp) %>%
  head(1)

port_ <- ndata$src
port_
```

    [1] "12.35.59.94"

### Задание 8: Внутренний сканнер

Одна из наших машин сканирует внутреннюю сеть. Что это за система?

``` r
result <- data %>%
  filter(grepl("^12\\.|^13\\.|^14\\.", src)) %>%
  filter(grepl("^12\\.|^13\\.|^14\\.", dst)) %>%
  group_by(src) %>%
  summarize(
    unique_dst_count = n_distinct(dst),
    avg_timestamp = mean(timestamp)
  ) %>%
  arrange(desc(unique_dst_count), avg_timestamp) %>%
  head(1)

src <- result$src
src
```

    [1] "13.42.70.40"

## Оценка результатов

Была проделана работа по поиску утечки данных в сети

## Вывод

Поставленная задача была выполнена с использованием инструментов
ClickhouseHTTP и RStudio. В процессе решения задачи был приобретен опыт
работы по нахождению утечек данных
