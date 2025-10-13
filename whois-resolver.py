import socket
import ipaddress
import sys
import re

def resolve_fqdn_to_ip(fqdn):
    """
    Разрешает FQDN в IP-адрес
    """
    try:
        # Пробуем получить все IP адреса для домена
        ip_addresses = socket.getaddrinfo(fqdn, None)
        
        # Предпочитаем IPv4 адреса
        ipv4_addresses = [addr[4][0] for addr in ip_addresses if addr[0] == socket.AF_INET]
        ipv6_addresses = [addr[4][0] for addr in ip_addresses if addr[0] == socket.AF_INET6]
        
        if ipv4_addresses:
            return ipv4_addresses[0]  # Возвращаем первый IPv4 адрес
        elif ipv6_addresses:
            return ipv6_addresses[0]  # Возвращаем первый IPv6 адрес
        else:
            return None
            
    except socket.gaierror:
        return None
    except Exception as e:
        print(f"Ошибка при разрешении FQDN: {e}")
        return None

def is_valid_fqdn(hostname):
    """
    Проверяет, является ли строка валидным FQDN
    """
    if not hostname or len(hostname) > 253:
        return False
    
    # Проверяем, что это не IP-адрес
    try:
        ipaddress.ip_address(hostname)
        return False  # Это IP, а не FQDN
    except ValueError:
        pass
    
    # Проверяем basic FQDN pattern
    if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$', hostname):
        return False
    
    # Проверяем, что есть хотя бы одна точка (для полного доменного имени)
    if '.' not in hostname:
        return False
    
    return True

def determine_whois_server(ip_address):
    """
    Определяет подходящий WHOIS сервер на основе IP-адреса
    """
    try:
        ip_obj = ipaddress.ip_address(ip_address)
        
        if ip_obj.version == 4:
            # Для IPv4 используем разные серверы в зависимости от региона
            if ip_obj.is_private:
                return None  # Для приватных адресов WHOIS не работает
            
            # Определяем RIR (Regional Internet Registry) по IP
            first_octet = int(ip_address.split('.')[0])
            
            if first_octet <= 127:
                return "whois.arin.net"  # Северная Америка
            elif 128 <= first_octet <= 191:
                return "whois.arin.net"  # Глобально
            elif 192 <= first_octet <= 223:
                return "whois.ripe.net"  # Европа, Ближний Восток, Центральная Азия
            else:
                return "whois.arin.net"
        
        elif ip_obj.version == 6:
            return "whois.ripe.net"  # Для IPv6 часто используется RIPE
        
    except:
        return "whois.radb.net"  # Резервный сервер

def whois_query(ip_address, whois_server=None):
    """
    Выполняет WHOIS запрос к указанному серверу
    """
    if not whois_server:
        whois_server = determine_whois_server(ip_address)
    
    if not whois_server:
        return "Не удалось определить WHOIS сервер для данного IP"
    
    try:
        # Подключаемся к WHOIS серверу
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(10)
            s.connect((whois_server, 43))
            query = f"{ip_address}\r\n"
            s.sendall(query.encode())
            
            # Получаем ответ
            response = b""
            while True:
                data = s.recv(4096)
                if not data:
                    break
                response += data
                if len(response) > 16384:  # Ограничиваем размер ответа
                    break
            
            return response.decode('utf-8', errors='ignore')
            
    except socket.timeout:
        return f"Таймаут при подключении к {whois_server}"
    except Exception as e:
        return f"Ошибка при подключении к {whois_server}: {e}"

def extract_cidr_from_response(response):
    """
    Извлекает CIDR блок из WHOIS ответа используя различные шаблоны
    """
    cidr_patterns = [
        r'route:\s*([0-9a-f.:/]+)',  # route: 192.168.0.0/24
        r'inetnum:\s*([0-9.]+ - [0-9.]+)',  # inetnum: 8.8.8.0 - 8.8.8.255
        r'CIDR:\s*([0-9a-f.:/]+)',  # CIDR: 8.8.8.0/24
        r'Network:\s*([0-9a-f.:/]+)',  # Network: 8.8.8.0/24
        r'([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2})',  # 8.8.8.0/24
        r'([0-9a-f:]+:/[0-9]{1,3})',  # IPv6 CIDR
    ]
    
    for pattern in cidr_patterns:
        matches = re.findall(pattern, response, re.IGNORECASE)
        if matches:
            return matches[0]
    
    # Пытаемся найти диапазон IP и преобразовать в CIDR
    range_pattern = r'inetnum:\s*([0-9.]+)\s*-\s*([0-9.]+)'
    range_match = re.search(range_pattern, response, re.IGNORECASE)
    if range_match:
        try:
            start_ip = range_match.group(1)
            end_ip = range_match.group(2)
            start = ipaddress.ip_address(start_ip)
            end = ipaddress.ip_address(end_ip)
            
            # Преобразуем диапазон в CIDR
            networks = list(ipaddress.summarize_address_range(start, end))
            if networks:
                return str(networks[0])
        except:
            pass
    
    return None

def extract_asn_from_response(response):
    """
    Извлекает AS номер из WHOIS ответа
    """
    asn_patterns = [
        r'origin:\s*(AS[0-9]+)',  # origin: AS15169
        r'aut-num:\s*(AS[0-9]+)',  # aut-num: AS15169
        r'ASNumber:\s*(AS[0-9]+)',  # ASNumber: AS15169
        r'AS\s*([0-9]+)',  # AS 15169
    ]
    
    for pattern in asn_patterns:
        matches = re.findall(pattern, response, re.IGNORECASE)
        if matches:
            return matches[0]
    
    return None

def extract_org_info(response):
    """
    Извлекает информацию об организации
    """
    org_info = {}
    
    org_patterns = [
        r'org-name:\s*(.+)',  # org-name: Google LLC
        r'organization:\s*(.+)',  # organization: Google LLC
        r'descr:\s*(.+)',  # descr: Google LLC
        r'netname:\s*(.+)',  # netname: GOOGLE
    ]
    
    for pattern in org_patterns:
        matches = re.findall(pattern, response, re.IGNORECASE)
        if matches:
            org_info['name'] = matches[0].strip()
            break
    
    # Страна
    country_match = re.search(r'country:\s*([A-Z]{2})', response, re.IGNORECASE)
    if country_match:
        org_info['country'] = country_match.group(1)
    
    return org_info

def get_network_info(cidr_block):
    """
    Получает детальную информацию о сети по CIDR блоку
    """
    try:
        network = ipaddress.ip_network(cidr_block, strict=False)
        return {
            'network': str(network),
            'netmask': str(network.netmask),
            'broadcast': str(network.broadcast_address) if network.version == 4 else "N/A для IPv6",
            'hostmask': str(network.hostmask),
            'num_addresses': network.num_addresses,
            'first_address': str(network[0]),
            'last_address': str(network[-1]),
            'is_private': network.is_private,
            'is_global': network.is_global
        }
    except ValueError:
        return None

def get_domain_info(fqdn):
    """
    Получает дополнительную информацию о домене
    """
    try:
        # Получаем все IP адреса
        ip_addresses = socket.getaddrinfo(fqdn, None)
        ipv4_list = []
        ipv6_list = []
        
        for addr in ip_addresses:
            ip = addr[4][0]
            if addr[0] == socket.AF_INET:
                ipv4_list.append(ip)
            elif addr[0] == socket.AF_INET6:
                ipv6_list.append(ip)
        
        # Пробуем получить MX записи
        try:
            mx_records = socket.getaddrinfo(fqdn, 25)
            mx_servers = [record[4][0] for record in mx_records]
        except:
            mx_servers = []
        
        return {
            'all_ipv4': list(set(ipv4_list)),
            'all_ipv6': list(set(ipv6_list)),
            'mx_servers': mx_servers,
            'resolved_count': len(ipv4_list) + len(ipv6_list)
        }
    except Exception as e:
        return {'error': str(e)}

def main():
    print("=== WHOIS IP/Domain Information Tool ===")
    print("Введите IP-адрес или доменное имя (или 'quit' для выхода)")
    print("Примеры: 8.8.8.8, google.com, example.org")
    
    while True:
        user_input = input("\nВведите IP или домен: ").strip().lower()
        
        if user_input in ['quit', 'exit', 'q']:
            print("Выход из программы...")
            break
        
        if not user_input:
            continue
        
        resolved_ip = None
        original_input = user_input
        
        try:
            # Проверяем, является ли ввод IP-адресом
            try:
                ip_obj = ipaddress.ip_address(user_input)
                resolved_ip = user_input
                input_type = "IP-адрес"
            except ValueError:
                # Если не IP, проверяем как FQDN
                if is_valid_fqdn(user_input):
                    print(f"Разрешаем домен: {user_input}")
                    resolved_ip = resolve_fqdn_to_ip(user_input)
                    if resolved_ip:
                        input_type = "домен"
                        ip_obj = ipaddress.ip_address(resolved_ip)
                    else:
                        print(f"Не удалось разрешить домен: {user_input}")
                        continue
                else:
                    print(f"Неверный формат: {user_input}. Введите IP или доменное имя.")
                    continue
            
            if ip_obj.is_private:
                print("Это приватный IP-адрес. WHOIS информация недоступна.")
                print(f"Сеть: {ip_obj}")
                continue
            
            print(f"Тип ввода: {input_type}")
            if input_type == "домен":
                print(f"Разрешенный IP: {resolved_ip}")
                
                # Получаем дополнительную информацию о домене
                domain_info = get_domain_info(user_input)
                if 'error' not in domain_info:
                    print(f"Все IPv4 адреса: {', '.join(domain_info['all_ipv4'])}")
                    if domain_info['all_ipv6']:
                        print(f"IPv6 адреса: {', '.join(domain_info['all_ipv6'])}")
            
            print("Выполняем WHOIS запрос...")
            
            # Пробуем несколько WHOIS серверов
            servers_to_try = [
                "whois.radb.net",  # Основной
                "whois.ripe.net",  # Для Европы
                "whois.arin.net",  # Для Северная Америка
                "whois.apnic.net",  # Для Азии
            ]
            
            response = None
            for server in servers_to_try:
                print(f"Пробуем сервер: {server}")
                response = whois_query(resolved_ip, server)
                if response and not response.startswith("Ошибка") and not response.startswith("Таймаут"):
                    break
            
            if not response or response.startswith("Ошибка") or response.startswith("Таймаут"):
                print("Не удалось получить WHOIS информацию")
                continue
            
            # Извлекаем информацию
            cidr_block = extract_cidr_from_response(response)
            asn = extract_asn_from_response(response)
            org_info = extract_org_info(response)
            
            # Выводим результаты
            print("\n" + "="*60)
            if input_type == "домен":
                print(f"Информация для домена: {original_input}")
                print(f"Разрешен в IP: {resolved_ip}")
            else:
                print(f"Информация для IP: {resolved_ip}")
            
            print(f"Тип адреса: {'IPv4' if ip_obj.version == 4 else 'IPv6'}")
            print("-" * 60)
            
            print("\nОсновная информация:")
            if asn:
                print(f"  AS номер: {asn}")
            else:
                print("  AS номер: Не найден")
            
            if cidr_block:
                print(f"  CIDR блок: {cidr_block}")
                
                # Детальная информация о сети
                network_info = get_network_info(cidr_block)
                if network_info:
                    print(f"  Маска сети: {network_info['netmask']}")
                    print(f"  Диапазон: {network_info['first_address']} - {network_info['last_address']}")
                    print(f"  Количество адресов: {network_info['num_addresses']:,}")
                    print(f"  Приватная сеть: {'Да' if network_info['is_private'] else 'Нет'}")
            else:
                print("  CIDR блок: Не найден")
            
            if org_info:
                print(f"\nИнформация об организации:")
                if 'name' in org_info:
                    print(f"  Организация: {org_info['name']}")
                if 'country' in org_info:
                    print(f"  Страна: {org_info['country']}")
            
            # Покажем часть сырого ответа
            print(f"\nПервые 10 строк WHOIS ответа:")
            lines = response.split('\n')
            displayed_lines = 0
            for i, line in enumerate(lines):
                if line.strip() and not line.strip().startswith('%'):
                    print(f"  {line.strip()}")
                    displayed_lines += 1
                    if displayed_lines >= 10:
                        break
            
            print("="*60)
            
        except ValueError:
            print(f"Ошибка: '{original_input}' не является валидным IP-адресом")
        except Exception as e:
            print(f"Произошла ошибка: {e}")

if __name__ == "__main__":
    main()