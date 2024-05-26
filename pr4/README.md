# Использование технологии Yandex Query для анализа данных сетевой
активности №4

## Цель работы

1.  Изучить возможности СУБД DuckDB для обработки и анализ больших
    данных
2.  Получить навыки применения DuckDB совместно с языком
    программирования R
3.  Получить навыки анализа метаинфомации о сетевом трафике
4.  Получить навыки применения облачных технологий хранения, подготовки
    и анализа данных: Yandex Object Storage, Rstudio Server.

## Исходные данные

-   Windows 11
-   RStudio
-   Yandex Object Storage
-   DuckDB

## Общая ситуация

Вы – специалист по информационной безопасности компании “СуперМегатек”.
Вы, являясь специалистом Threat Hunting, часто используете информацию о
сетевом трафике для обнаружения подозрительной и вредоносной активности.
Помогите защитить Вашу компанию от международной хакерской группировки
AnonMasons.

У Вас есть данные сетевой активности в корпоративной сети компании
“СуперМегатек”. Данные хранятся в Yandex Object Storage.

## Задание

Используя язык программирования R, СУБД и пакет duckdb и облачную IDE
Rstudio Server, развернутую в Yandex Cloud, выполнить задания и
составить отчет.

## Задачи

-   Задание 1: Надите утечку данных из Вашей сети
-   Задание 2: Надите утечку данных 2
-   Задание 3: Надите утечку данных 3
-   Задание 4: Обнаружение канала управления
-   Задание 5: Обнаружение P2P трафика
-   Задание 6: Чемпион малвари

## Ход работы

Устанавливаем SSH-туннель по прошлому заданию (user24)

Подготавливаем рабочее пространство

``` r
library(duckdb)
```

    Loading required package: DBI

``` r
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
con <- dbConnect(duckdb::duckdb(), dbdir = ":memory:")
dbExecute(conn = con, "INSTALL httpfs; LOAD httpfs;")
```

    [1] 0

``` r
pqt_data = "https://storage.yandexcloud.net/arrow-datasets/tm_data.pqt"

select <- "SELECT * FROM read_parquet([?])"
data <- dbGetQuery(con, select, list(pqt_data))
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
IP-адрес

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
  summarise(total_traffic = sum(bytes)) %>%
  left_join(average_traffic, by = "port") %>%
  left_join(max_traffic, by = "port") %>%
  mutate(traffic_ratio = total_traffic / avg_traffic) %>%
  collect()
```

    `summarise()` has grouped output by 'src'. You can override using the `.groups`
    argument.

``` r
result %>%
  head(1)
```

    # A tibble: 1 × 6
    # Groups:   src [1]
      src           port total_traffic avg_traffic max_traffic traffic_ratio
      <chr>        <int>         <int>       <dbl>       <int>         <dbl>
    1 12.30.105.68    22       1200192        999.        1731         1201.

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
у данного хоста нет. Определите IP такого хоста

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

``` r
dbDisconnect(con, shutdown=TRUE)
```

## Оценка результатов

Были найдены утечки данных из сети

## Вывод

Поставленная задача была выполнена с использованием инструментов DuckDB
и RStudio. В процессе решения задачи был приобретен опыт работы по
нахождению утечек данных
