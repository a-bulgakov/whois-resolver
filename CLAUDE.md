# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

CLI-инструмент на чистом Python (только стандартная библиотека: `socket`, `ipaddress`, `re`). По IP-адресу или доменному имени делает сырой WHOIS-запрос (TCP/43) и извлекает CIDR-блок, номер автономной системы (ASN) и сведения об организации. Интерфейс и сообщения — на русском.

## Commands

```bash
# Запуск интерактивного CLI
python whois_resolver.py

# Все тесты
python -m unittest tests

# Один класс / один тест
python -m unittest tests.TestExtractCidr
python -m unittest tests.TestLookupWhois.test_domain_addresses_in_same_cidr_collapse

# Подробный вывод
python -m unittest tests -v
```

Внешних зависимостей и тулинга для сборки/линта нет. `pytest` не установлен — используется встроенный `unittest`.

## Architecture

Вся логика в одном модуле [whois_resolver.py](whois_resolver.py). Ключевой принцип — **разделение получения данных и вывода**, чтобы логику можно было тестировать без сети:

- **`lookup_whois(target)`** — единственная точка входа в логику, без `print`. Возвращает структурированный dict `{input, type, all_ipv4, all_ipv6, networks, error}`. `networks` — список уникальных сетей; каждая: `{ip, covered_ips, server, cidr, asn, org, network, raw, _net}`.
- **`print_report(result)`** — весь вывод; принимает результат `lookup_whois`.
- **`main()`** — тонкий REPL: читает ввод → `lookup_whois` → `print_report`.
- **`_query_ip(ip)`** — WHOIS для одного адреса: перебирает `WHOIS_SERVERS` до первого ответа с CIDR, первый непустой ответ держит как запасной для ASN/org.
- Хелперы парсинга: `is_valid_fqdn`, `resolve_domain`, `whois_query`, `extract_cidr`, `extract_asn`, `extract_org`, `get_network_info`.

### Поведение, которое легко сломать при правках

- **Перебор серверов идёт до ответа с CIDR**, а не до первого непустого ответа. Первый сервер (`whois.radb.net`) почти всегда что-то отдаёт, но без полей RIR (`country`/`org-name`) — поэтому ранний выход обесценивает результат.
- **`extract_cidr(response, ip)`** выбирает не первое совпадение, а **самый специфичный** (max prefixlen) блок, реально содержащий `ip`. Без `ip` — первый валидный.
- **Дедупликация по сети**: для домена с несколькими адресами CIDR ищется по каждому, но адрес, уже входящий в найденный ранее CIDR, не порождает нового запроса — добавляется в `covered_ips` (поле `_net` хранит разобранный объект сети для проверки принадлежности).
- IPv6 обрабатывается наравне с IPv4: `route6:`/`inet6num:`, отсутствие netmask (`get_network_info` возвращает `netmask=None`).

## Tests

[tests.py](tests.py) покрывает все функции через `unittest`. Сетевые вызовы (`whois_query`, `resolve_domain`, `socket`) мокаются через `unittest.mock.patch` — тесты не ходят в сеть. При изменении формата результата `lookup_whois` обновляй соответствующие проверки `networks[...]`.

## Conventions

- Имя файла — `whois_resolver.py` (с подчёркиванием), иначе модуль не импортируется в тестах.
- Сообщения пользователю и docstring — на русском; имена идентификаторов — на английском.
