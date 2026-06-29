"""
WHOIS-резолвер для IP-адресов и доменных имён.

Назначение: по введённому IP или FQDN найти CIDR-блок сети, номер
автономной системы (ASN) и сведения об организации-владельце.

Поток данных:
    target (IP | FQDN)
      -> resolve_domain()      # FQDN -> список IP (для домена)
      -> whois_query()         # сырой TCP-запрос на порт 43 WHOIS-сервера
      -> extract_cidr/asn/org  # разбор текстового ответа регэкспами
      -> get_network_info()    # вычисление параметров сети по CIDR

Логика получения данных (lookup_whois) намеренно отделена от вывода
(print_report), поэтому lookup_whois() можно вызывать программно и
тестировать без реальной сети (через моки whois_query/getaddrinfo).
"""

import socket
import ipaddress
import re

# WHOIS-серверы перебираются по порядку. radb (маршрутный реестр) часто
# отдаёт route-объекты с CIDR, RIR-серверы (ripe/arin/apnic) — org/country.
WHOIS_SERVERS = [
    "whois.radb.net",
    "whois.ripe.net",
    "whois.arin.net",
    "whois.apnic.net",
]

WHOIS_PORT = 43          # стандартный порт протокола WHOIS
WHOIS_TIMEOUT = 10       # таймаут соединения/чтения, секунд
WHOIS_MAX_BYTES = 16384  # ограничение на размер ответа, чтобы не зачитать лишнего


def is_valid_fqdn(hostname):
    """Проверяет, что строка похожа на полное доменное имя (не IP, с точкой)."""
    # Пустая строка или длиннее лимита DNS (253 символа) — заведомо не FQDN.
    if not hostname or len(hostname) > 253:
        return False
    # Если строка парсится как IP-адрес — это не доменное имя.
    try:
        ipaddress.ip_address(hostname)
        return False
    except ValueError:
        pass
    # Требуем хотя бы одну точку: одиночные метки (localhost) не считаем FQDN.
    if '.' not in hostname:
        return False
    # Базовая проверка формата меток: буквы/цифры/дефис, до 63 символов в метке.
    return bool(re.match(
        r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$',
        hostname
    ))


def resolve_domain(fqdn):
    """Резолвит FQDN в адреса. Возвращает {'all_ipv4': [...], 'all_ipv6': [...]}
    или None, если DNS-резолв не удался."""
    try:
        addrs = socket.getaddrinfo(fqdn, None)
        # getaddrinfo может вернуть дубли (TCP/UDP/разные протоколы) — снимаем их
        # через dict.fromkeys, который, в отличие от set(), сохраняет порядок.
        ipv4 = list(dict.fromkeys(a[4][0] for a in addrs if a[0] == socket.AF_INET))
        ipv6 = list(dict.fromkeys(a[4][0] for a in addrs if a[0] == socket.AF_INET6))
        return {'all_ipv4': ipv4, 'all_ipv6': ipv6}
    except socket.gaierror:
        return None


def whois_query(ip, server):
    """Делает сырой WHOIS-запрос к серверу по TCP/43.
    Возвращает текст ответа или None при любой сетевой ошибке."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(WHOIS_TIMEOUT)
            s.connect((server, WHOIS_PORT))
            # Протокол WHOIS: посылаем запрос строкой, завершённой CRLF.
            s.sendall(f"{ip}\r\n".encode())
            # Читаем ответ кусками до закрытия соединения или лимита размера.
            response = b""
            while True:
                data = s.recv(4096)
                if not data:  # сервер закрыл соединение — ответ получен полностью
                    break
                response += data
                # Проверяем лимит ПОСЛЕ добавления, иначе на границе терялся бы чанк.
                if len(response) >= WHOIS_MAX_BYTES:
                    break
            # errors='ignore': часть серверов отдаёт не-UTF-8 байты в комментариях.
            return response.decode('utf-8', errors='ignore')
    except Exception:
        return None


def _iter_cidr_candidates(response):
    """Генерирует строки-кандидаты CIDR из WHOIS-ответа (поля и голые префиксы)."""
    field_patterns = [
        r'route6?:\s*([0-9a-fA-F.:/]+)',  # route:/route6: (маршрутные реестры, RADB)
        r'CIDR:\s*([0-9a-fA-F.:/]+)',     # CIDR: (формат ARIN)
        r'Network:\s*([0-9a-fA-F.:/]+)',  # Network: (встречается у части серверов)
    ]
    bare_patterns = [
        r'\b([0-9]{1,3}(?:\.[0-9]{1,3}){3}/[0-9]{1,2})\b',  # голый IPv4-префикс
        r'\b([0-9a-fA-F:]+/[0-9]{1,3})\b',                  # голый IPv6-префикс
    ]
    for pattern in field_patterns + bare_patterns:
        for m in re.findall(pattern, response, re.IGNORECASE):
            yield m

    # Диапазоны inetnum/inet6num конвертируем в CIDR через summarize_address_range
    # (работает и для IPv4, и для IPv6). Берём первую сеть из покрытия диапазона.
    for m in re.finditer(r'inet6?num:\s*([0-9a-fA-F.:]+)\s*-\s*([0-9a-fA-F.:]+)',
                         response, re.IGNORECASE):
        try:
            nets = list(ipaddress.summarize_address_range(
                ipaddress.ip_address(m.group(1)),
                ipaddress.ip_address(m.group(2)),
            ))
            if nets:
                yield str(nets[0])
        except ValueError:
            continue


def extract_cidr(response, ip=None):
    """Извлекает CIDR-блок из WHOIS-ответа.

    Если задан ip, выбирается самый специфичный (с наибольшим префиксом)
    блок, реально содержащий этот адрес. Без ip — первый валидный блок.
    Это важно: в ответе бывает несколько route-объектов, и первый по тексту
    может не покрывать запрошенный адрес."""
    target = ipaddress.ip_address(ip) if ip else None
    best = None
    for candidate in _iter_cidr_candidates(response):
        try:
            net = ipaddress.ip_network(candidate, strict=False)
        except ValueError:
            continue  # мусорное совпадение регэкспа — пропускаем
        if target is not None:
            # Версии должны совпадать, и адрес должен входить в сеть.
            if net.version != target.version or target not in net:
                continue
            # Среди подходящих оставляем самый узкий (max prefixlen).
            if best is None or net.prefixlen > best.prefixlen:
                best = net
        else:
            return str(net)  # ip не задан — достаточно первого валидного
    return str(best) if best else None


def extract_asn(response):
    """Извлекает номер автономной системы (например, AS15169)."""
    for pattern in [
        r'origin:\s*(AS[0-9]+)',     # origin: (route-объекты)
        r'aut-num:\s*(AS[0-9]+)',    # aut-num: (объект автономной системы у RIR)
        r'ASNumber:\s*(AS[0-9]+)',   # ASNumber: (формат ARIN)
    ]:
        m = re.search(pattern, response, re.IGNORECASE)
        if m:
            return m.group(1)
    # Запасной вариант: "ASxxxx" без пробела и минимум из 3 цифр, чтобы не ловить
    # случайные "AS 12" из текста описаний.
    m = re.search(r'\bAS([0-9]{3,})\b', response, re.IGNORECASE)
    if m:
        return f"AS{m.group(1)}"
    return None


def extract_org(response):
    """Извлекает имя организации и код страны (если они есть в ответе)."""
    org = {}
    # Перебираем поля по приоритету: явное имя организации важнее описания/netname.
    for pattern in [
        r'org-name:\s*(.+)',
        r'organization:\s*(.+)',
        r'descr:\s*(.+)',
        r'netname:\s*(.+)',
    ]:
        m = re.search(pattern, response, re.IGNORECASE)
        if m:
            org['name'] = m.group(1).strip()
            break
    m = re.search(r'country:\s*([A-Z]{2})', response, re.IGNORECASE)
    if m:
        org['country'] = m.group(1).upper()
    return org


def get_network_info(cidr):
    """По CIDR вычисляет параметры сети. Возвращает None для некорректного CIDR."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        return {
            # У IPv6 нет понятия маски в привычном виде — отдаём None.
            'netmask': str(net.netmask) if net.version == 4 else None,
            'first': str(net[0]),       # первый адрес сети (network address)
            'last': str(net[-1]),       # последний адрес (broadcast у IPv4)
            'count': net.num_addresses,
            'is_private': net.is_private,
        }
    except ValueError:
        return None


def _query_ip(ip):
    """WHOIS для одного адреса: перебор серверов до первого ответа с CIDR.

    Первый непустой ответ запоминается как запасной — если CIDR не найдётся
    нигде, ASN/org всё равно можно извлечь. Возвращает dict
    {ip, server, cidr, asn, org, network, raw} или None, если ни один сервер
    не ответил.
    """
    fallback = None
    used_server = used_response = None
    for server in WHOIS_SERVERS:
        response = whois_query(ip, server)
        if not response:
            continue
        if fallback is None:
            fallback = (server, response)
        if extract_cidr(response, ip):
            used_server, used_response = server, response
            break
    else:
        # break не сработал — CIDR нигде нет; берём запасной ответ, если он есть.
        if fallback is None:
            return None
        used_server, used_response = fallback

    cidr = extract_cidr(used_response, ip)
    return {
        'ip': ip,
        'server': used_server,
        'cidr': cidr,
        'asn': extract_asn(used_response),
        'org': extract_org(used_response),
        'network': get_network_info(cidr) if cidr else None,
        'raw': used_response,
    }


def lookup_whois(target):
    """Главная логика без вывода: по IP или FQDN собирает сведения о сетях.

    Для домена с несколькими адресами CIDR ищется по каждому адресу, но
    результаты схлопываются: если адрес уже входит в найденный ранее CIDR,
    повторный запрос не делается, а адрес добавляется в covered_ips этой сети.

    Возвращает словарь с ключами:
        input, type ('IP-адрес' | 'домен'), all_ipv4, all_ipv6, networks, error.
    networks — список сетей, каждая: {ip, covered_ips, server, cidr, asn, org,
    network, raw}. При ошибке заполняется error.
    """
    result = {
        'input': target, 'type': None,
        'all_ipv4': [], 'all_ipv6': [],
        'networks': [], 'error': None,
    }

    # 1. Определяем тип ввода и формируем список адресов-кандидатов.
    try:
        ipaddress.ip_address(target)
        result['type'] = 'IP-адрес'
        candidate_ips = [target]
    except ValueError:
        if not is_valid_fqdn(target):
            result['error'] = 'Неверный формат: введите IP или доменное имя.'
            return result
        domain_info = resolve_domain(target)
        if not domain_info or not (domain_info['all_ipv4'] or domain_info['all_ipv6']):
            result['error'] = f'Не удалось разрешить домен: {target}'
            return result
        result['type'] = 'домен'
        result['all_ipv4'] = domain_info['all_ipv4']
        result['all_ipv6'] = domain_info['all_ipv6']
        candidate_ips = domain_info['all_ipv4'] + domain_info['all_ipv6']

    # Прямой ввод приватного IP — отдельное понятное сообщение.
    if result['type'] == 'IP-адрес' and ipaddress.ip_address(target).is_private:
        result['error'] = 'Это приватный IP-адрес. WHOIS информация недоступна.'
        return result

    # 2. Для каждого адреса ищем CIDR, пропуская уже покрытые найденными сетями.
    for ip in candidate_ips:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private:
            continue  # приватные адреса в публичном WHOIS отсутствуют
        # Если адрес уже входит в ранее найденный CIDR — не дублируем запрос.
        covered = next((n for n in result['networks']
                        if n['_net'] is not None and ip_obj in n['_net']), None)
        if covered:
            covered['covered_ips'].append(ip)
            continue
        info = _query_ip(ip)
        if info is None:
            continue
        info['covered_ips'] = [ip]
        # _net — разобранный объект сети для проверок принадлежности (служебный).
        info['_net'] = ipaddress.ip_network(info['cidr'], strict=False) if info['cidr'] else None
        result['networks'].append(info)

    if not result['networks']:
        result['error'] = 'Не удалось получить WHOIS информацию'
    return result


def print_report(result):
    """Печатает результат lookup_whois в человекочитаемом виде."""
    if result['error']:
        print(result['error'])
        return

    is_domain = result['type'] == 'домен'
    if is_domain:
        print(f"Все IPv4 адреса: {', '.join(result['all_ipv4'])}")
        if result['all_ipv6']:
            print(f"IPv6 адреса: {', '.join(result['all_ipv6'])}")

    print("\n" + "=" * 60)
    if is_domain:
        print(f"Информация для домена: {result['input']}")
    else:
        print(f"Информация для IP: {result['networks'][0]['ip']}")
    print(f"Найдено уникальных сетей: {len(result['networks'])}")
    print("=" * 60)

    # Каждую уникальную сеть печатаем отдельным блоком.
    for i, net in enumerate(result['networks'], 1):
        print(f"\n[{i}] CIDR блок: {net['cidr'] or 'Не найден'}")
        # Если в этой сети оказалось несколько адресов — перечисляем их.
        if len(net['covered_ips']) > 1:
            print(f"  Адреса в этой сети: {', '.join(net['covered_ips'])}")
        elif is_domain:
            print(f"  Адрес: {net['ip']}")
        version = ipaddress.ip_address(net['ip']).version
        print(f"  Тип адреса: {'IPv4' if version == 4 else 'IPv6'}")
        print(f"  WHOIS сервер: {net['server']}")
        print(f"  AS номер: {net['asn'] or 'Не найден'}")

        ninfo = net['network']
        if ninfo:
            if ninfo['netmask']:
                print(f"  Маска сети: {ninfo['netmask']}")
            print(f"  Диапазон: {ninfo['first']} - {ninfo['last']}")
            print(f"  Количество адресов: {ninfo['count']:,}")
            print(f"  Приватная сеть: {'Да' if ninfo['is_private'] else 'Нет'}")

        org = net['org']
        if 'name' in org:
            print(f"  Организация: {org['name']}")
        if 'country' in org:
            print(f"  Страна: {org['country']}")

    print("\n" + "=" * 60)


def main():
    """Интерактивный цикл: читает ввод, вызывает lookup_whois и печатает отчёт."""
    print("=== WHOIS IP/Domain Information Tool ===")
    print("Введите IP-адрес или доменное имя (или 'quit' для выхода)")
    print("Примеры: 8.8.8.8, google.com, example.org")

    while True:
        user_input = input("\nВведите IP или домен: ").strip().lower()

        if user_input in ('quit', 'exit', 'q'):
            print("Выход из программы...")
            break
        if not user_input:
            continue

        print("Выполняем WHOIS запрос...")
        result = lookup_whois(user_input)
        print_report(result)


if __name__ == "__main__":
    main()
