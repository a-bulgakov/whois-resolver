import socket
import ipaddress
import re

WHOIS_SERVERS = [
    "whois.radb.net",
    "whois.ripe.net",
    "whois.arin.net",
    "whois.apnic.net",
]


def is_valid_fqdn(hostname):
    if not hostname or len(hostname) > 253:
        return False
    try:
        ipaddress.ip_address(hostname)
        return False
    except ValueError:
        pass
    if '.' not in hostname:
        return False
    return bool(re.match(
        r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$',
        hostname
    ))


def resolve_domain(fqdn):
    """Возвращает {'all_ipv4': [...], 'all_ipv6': [...]} или None при ошибке."""
    try:
        addrs = socket.getaddrinfo(fqdn, None)
        ipv4 = list(dict.fromkeys(a[4][0] for a in addrs if a[0] == socket.AF_INET))
        ipv6 = list(dict.fromkeys(a[4][0] for a in addrs if a[0] == socket.AF_INET6))
        return {'all_ipv4': ipv4, 'all_ipv6': ipv6}
    except socket.gaierror:
        return None


def whois_query(ip, server):
    """Возвращает строку ответа или None при ошибке."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(10)
            s.connect((server, 43))
            s.sendall(f"{ip}\r\n".encode())
            response = b""
            while True:
                data = s.recv(4096)
                if not data or len(response) > 16384:
                    break
                response += data
            return response.decode('utf-8', errors='ignore')
    except Exception:
        return None


def extract_cidr(response):
    for pattern in [
        r'(?:route|CIDR|Network):\s*([0-9a-fA-F.:/]+)',
        r'\b([0-9]{1,3}(?:\.[0-9]{1,3}){3}/[0-9]{1,2})\b',
        r'\b([0-9a-fA-F:]+/[0-9]{1,3})\b',
    ]:
        m = re.search(pattern, response, re.IGNORECASE)
        if m:
            return m.group(1)

    # Конвертируем inetnum диапазон в CIDR
    m = re.search(r'inetnum:\s*([0-9.]+)\s*-\s*([0-9.]+)', response, re.IGNORECASE)
    if m:
        try:
            networks = list(ipaddress.summarize_address_range(
                ipaddress.ip_address(m.group(1)),
                ipaddress.ip_address(m.group(2))
            ))
            if networks:
                return str(networks[0])
        except Exception:
            pass
    return None


def extract_asn(response):
    for pattern in [
        r'origin:\s*(AS[0-9]+)',
        r'aut-num:\s*(AS[0-9]+)',
        r'ASNumber:\s*(AS[0-9]+)',
    ]:
        m = re.search(pattern, response, re.IGNORECASE)
        if m:
            return m.group(1)
    m = re.search(r'\bAS\s*([0-9]+)\b', response, re.IGNORECASE)
    if m:
        return f"AS{m.group(1)}"
    return None


def extract_org(response):
    org = {}
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
        org['country'] = m.group(1)
    return org


def get_network_info(cidr):
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        return {
            'netmask': str(net.netmask) if net.version == 4 else None,
            'first': str(net[0]),
            'last': str(net[-1]),
            'count': net.num_addresses,
            'is_private': net.is_private,
        }
    except ValueError:
        return None


def main():
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

        resolved_ip = None
        original_input = user_input

        try:
            try:
                ip_obj = ipaddress.ip_address(user_input)
                resolved_ip = user_input
                input_type = "IP-адрес"
            except ValueError:
                if is_valid_fqdn(user_input):
                    print(f"Разрешаем домен: {user_input}")
                    domain_info = resolve_domain(user_input)
                    if not domain_info or (not domain_info['all_ipv4'] and not domain_info['all_ipv6']):
                        print(f"Не удалось разрешить домен: {user_input}")
                        continue
                    resolved_ip = (domain_info['all_ipv4'] or domain_info['all_ipv6'])[0]
                    ip_obj = ipaddress.ip_address(resolved_ip)
                    input_type = "домен"
                else:
                    print(f"Неверный формат: {user_input}. Введите IP или доменное имя.")
                    continue

            if ip_obj.is_private:
                print("Это приватный IP-адрес. WHOIS информация недоступна.")
                continue

            print(f"Тип ввода: {input_type}")
            if input_type == "домен":
                print(f"Разрешенный IP: {resolved_ip}")
                print(f"Все IPv4 адреса: {', '.join(domain_info['all_ipv4'])}")
                if domain_info['all_ipv6']:
                    print(f"IPv6 адреса: {', '.join(domain_info['all_ipv6'])}")

            print("Выполняем WHOIS запрос...")

            response = None
            for server in WHOIS_SERVERS:
                print(f"Пробуем сервер: {server}")
                response = whois_query(resolved_ip, server)
                if response:
                    break

            if not response:
                print("Не удалось получить WHOIS информацию")
                continue

            cidr = extract_cidr(response)
            asn = extract_asn(response)
            org = extract_org(response)

            print("\n" + "=" * 60)
            if input_type == "домен":
                print(f"Информация для домена: {original_input}")
                print(f"Разрешен в IP: {resolved_ip}")
            else:
                print(f"Информация для IP: {resolved_ip}")
            print(f"Тип адреса: {'IPv4' if ip_obj.version == 4 else 'IPv6'}")
            print("-" * 60)

            print("\nОсновная информация:")
            print(f"  AS номер: {asn or 'Не найден'}")

            if cidr:
                print(f"  CIDR блок: {cidr}")
                net_info = get_network_info(cidr)
                if net_info:
                    if net_info['netmask']:
                        print(f"  Маска сети: {net_info['netmask']}")
                    print(f"  Диапазон: {net_info['first']} - {net_info['last']}")
                    print(f"  Количество адресов: {net_info['count']:,}")
                    print(f"  Приватная сеть: {'Да' if net_info['is_private'] else 'Нет'}")
            else:
                print("  CIDR блок: Не найден")

            if org:
                print("\nИнформация об организации:")
                if 'name' in org:
                    print(f"  Организация: {org['name']}")
                if 'country' in org:
                    print(f"  Страна: {org['country']}")

            print(f"\nПервые 10 строк WHOIS ответа:")
            shown = 0
            for line in response.split('\n'):
                if line.strip() and not line.strip().startswith('%'):
                    print(f"  {line.strip()}")
                    shown += 1
                    if shown >= 10:
                        break

            print("=" * 60)

        except ValueError:
            print(f"Ошибка: '{original_input}' не является валидным IP-адресом")
        except Exception as e:
            print(f"Произошла ошибка: {e}")


if __name__ == "__main__":
    main()
