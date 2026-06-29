import socket
import unittest
from unittest.mock import patch, MagicMock

from whois_resolver import (
    is_valid_fqdn,
    resolve_domain,
    whois_query,
    extract_cidr,
    extract_asn,
    extract_org,
    get_network_info,
    lookup_whois,
)


class TestIsValidFqdn(unittest.TestCase):
    def test_valid_domains(self):
        self.assertTrue(is_valid_fqdn("google.com"))
        self.assertTrue(is_valid_fqdn("www.example.org"))
        self.assertTrue(is_valid_fqdn("sub.domain.co.uk"))
        self.assertTrue(is_valid_fqdn("my-host.example.com"))

    def test_rejects_ip_addresses(self):
        self.assertFalse(is_valid_fqdn("8.8.8.8"))
        self.assertFalse(is_valid_fqdn("192.168.1.1"))
        self.assertFalse(is_valid_fqdn("2001:db8::1"))

    def test_rejects_single_label(self):
        self.assertFalse(is_valid_fqdn("localhost"))
        self.assertFalse(is_valid_fqdn("hostname"))

    def test_rejects_empty(self):
        self.assertFalse(is_valid_fqdn(""))
        self.assertFalse(is_valid_fqdn(None))

    def test_rejects_too_long(self):
        self.assertFalse(is_valid_fqdn("a" * 254))

    def test_rejects_invalid_chars(self):
        self.assertFalse(is_valid_fqdn("invalid_domain.com"))
        self.assertFalse(is_valid_fqdn("has space.com"))
        self.assertFalse(is_valid_fqdn("has@at.com"))


class TestResolveDomain(unittest.TestCase):
    def _make_addr(self, family, ip):
        return (family, None, None, None, (ip, 0))

    @patch("whois_resolver.socket.getaddrinfo")
    def test_returns_ipv4_and_ipv6(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            self._make_addr(socket.AF_INET, "1.2.3.4"),
            self._make_addr(socket.AF_INET, "1.2.3.5"),
            self._make_addr(socket.AF_INET6, "2001:db8::1"),
        ]
        result = resolve_domain("example.com")
        self.assertEqual(result["all_ipv4"], ["1.2.3.4", "1.2.3.5"])
        self.assertEqual(result["all_ipv6"], ["2001:db8::1"])

    @patch("whois_resolver.socket.getaddrinfo")
    def test_deduplicates_preserving_order(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            self._make_addr(socket.AF_INET, "1.2.3.4"),
            self._make_addr(socket.AF_INET, "1.2.3.4"),
            self._make_addr(socket.AF_INET, "1.2.3.5"),
        ]
        result = resolve_domain("example.com")
        self.assertEqual(result["all_ipv4"], ["1.2.3.4", "1.2.3.5"])

    @patch("whois_resolver.socket.getaddrinfo", side_effect=socket.gaierror)
    def test_returns_none_on_dns_failure(self, _):
        self.assertIsNone(resolve_domain("nonexistent.invalid"))


class TestWhoisQuery(unittest.TestCase):
    @patch("whois_resolver.socket.socket")
    def test_returns_response_on_success(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value.__enter__.return_value = mock_sock
        mock_sock.recv.side_effect = [b"whois data here\n", b""]
        result = whois_query("8.8.8.8", "whois.example.net")
        self.assertIn("whois data here", result)

    @patch("whois_resolver.socket.socket")
    def test_returns_none_on_timeout(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value.__enter__.return_value = mock_sock
        mock_sock.connect.side_effect = socket.timeout
        self.assertIsNone(whois_query("8.8.8.8", "whois.example.net"))

    @patch("whois_resolver.socket.socket")
    def test_returns_none_on_connection_error(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value.__enter__.return_value = mock_sock
        mock_sock.connect.side_effect = OSError("connection refused")
        self.assertIsNone(whois_query("8.8.8.8", "whois.example.net"))


class TestExtractCidr(unittest.TestCase):
    def test_route_field(self):
        self.assertEqual(extract_cidr("route: 8.8.8.0/24"), "8.8.8.0/24")

    def test_cidr_field(self):
        self.assertEqual(extract_cidr("CIDR: 8.8.8.0/24"), "8.8.8.0/24")

    def test_network_field(self):
        self.assertEqual(extract_cidr("Network: 8.8.8.0/24"), "8.8.8.0/24")

    def test_bare_ipv4_cidr(self):
        self.assertEqual(extract_cidr("some text 8.8.8.0/24 more text"), "8.8.8.0/24")

    def test_inetnum_range_converted_to_cidr(self):
        result = extract_cidr("inetnum: 8.8.8.0 - 8.8.8.255")
        self.assertEqual(result, "8.8.8.0/24")

    def test_inetnum_range_irregular_becomes_supernet(self):
        result = extract_cidr("inetnum: 8.8.8.0 - 8.8.8.127")
        self.assertEqual(result, "8.8.8.0/25")

    def test_ipv6_cidr(self):
        result = extract_cidr("route: 2001:db8::/32")
        self.assertEqual(result, "2001:db8::/32")

    def test_returns_none_when_not_found(self):
        self.assertIsNone(extract_cidr("no network info here"))

    def test_returns_none_on_empty(self):
        self.assertIsNone(extract_cidr(""))

    def test_picks_most_specific_containing_ip(self):
        # В ответе два route-объекта; для 8.8.8.8 нужен самый узкий, /24.
        response = "route: 8.0.0.0/8\nroute: 8.8.8.0/24\n"
        self.assertEqual(extract_cidr(response, "8.8.8.8"), "8.8.8.0/24")

    def test_skips_cidr_not_containing_ip(self):
        # Первый по тексту блок не содержит IP — должен быть выбран второй.
        response = "route: 1.0.0.0/24\nroute: 8.8.8.0/24\n"
        self.assertEqual(extract_cidr(response, "8.8.8.8"), "8.8.8.0/24")

    def test_returns_none_when_no_cidr_contains_ip(self):
        self.assertIsNone(extract_cidr("route: 1.0.0.0/24", "8.8.8.8"))

    def test_route6_field(self):
        self.assertEqual(extract_cidr("route6: 2001:db8::/32"), "2001:db8::/32")

    def test_inet6num_range_converted(self):
        response = "inet6num: 2001:db8:: - 2001:db8:0:ffff:ffff:ffff:ffff:ffff"
        self.assertEqual(extract_cidr(response), "2001:db8::/48")


class TestExtractAsn(unittest.TestCase):
    def test_origin_field(self):
        self.assertEqual(extract_asn("origin: AS15169"), "AS15169")

    def test_aut_num_field(self):
        self.assertEqual(extract_asn("aut-num: AS15169"), "AS15169")

    def test_asnumber_field(self):
        self.assertEqual(extract_asn("ASNumber: AS15169"), "AS15169")

    def test_bare_as_without_space(self):
        self.assertEqual(extract_asn("see AS15169 for details"), "AS15169")

    def test_ignores_short_false_positive(self):
        # "AS 12" с пробелом и коротким числом не должно ловиться как ASN.
        self.assertIsNone(extract_asn("the class AS 12 example"))

    def test_case_insensitive(self):
        self.assertEqual(extract_asn("ORIGIN: AS15169"), "AS15169")

    def test_returns_none_when_not_found(self):
        self.assertIsNone(extract_asn("no asn info here"))


class TestExtractOrg(unittest.TestCase):
    def test_org_name(self):
        result = extract_org("org-name: Google LLC")
        self.assertEqual(result["name"], "Google LLC")

    def test_organization(self):
        result = extract_org("organization: Google LLC")
        self.assertEqual(result["name"], "Google LLC")

    def test_descr(self):
        result = extract_org("descr: Google LLC")
        self.assertEqual(result["name"], "Google LLC")

    def test_netname(self):
        result = extract_org("netname: GOOGLE")
        self.assertEqual(result["name"], "GOOGLE")

    def test_country(self):
        result = extract_org("country: US")
        self.assertEqual(result["country"], "US")

    def test_org_name_takes_priority_over_descr(self):
        result = extract_org("descr: Some ISP\norg-name: Google LLC")
        self.assertEqual(result["name"], "Google LLC")

    def test_returns_empty_dict_when_not_found(self):
        self.assertEqual(extract_org("no org info"), {})

    def test_strips_whitespace(self):
        result = extract_org("org-name:   Google LLC   ")
        self.assertEqual(result["name"], "Google LLC")


class TestGetNetworkInfo(unittest.TestCase):
    def test_ipv4_network(self):
        info = get_network_info("8.8.8.0/24")
        self.assertEqual(info["netmask"], "255.255.255.0")
        self.assertEqual(info["first"], "8.8.8.0")
        self.assertEqual(info["last"], "8.8.8.255")
        self.assertEqual(info["count"], 256)
        self.assertFalse(info["is_private"])

    def test_private_network(self):
        info = get_network_info("192.168.1.0/24")
        self.assertTrue(info["is_private"])

    def test_host_address(self):
        info = get_network_info("8.8.8.8/32")
        self.assertEqual(info["count"], 1)
        self.assertEqual(info["first"], info["last"])

    def test_ipv6_no_netmask(self):
        info = get_network_info("2001:db8::/32")
        self.assertIsNone(info["netmask"])
        self.assertEqual(info["first"], "2001:db8::")

    def test_returns_none_on_invalid(self):
        self.assertIsNone(get_network_info("not-a-cidr"))
        self.assertIsNone(get_network_info(""))


class TestLookupWhois(unittest.TestCase):
    @patch("whois_resolver.whois_query")
    def test_ip_input_full_result(self, mock_query):
        mock_query.return_value = (
            "route: 8.8.8.0/24\norigin: AS15169\norg-name: Google LLC\ncountry: US\n"
        )
        result = lookup_whois("8.8.8.8")
        self.assertIsNone(result["error"])
        self.assertEqual(result["type"], "IP-адрес")
        self.assertEqual(len(result["networks"]), 1)
        net = result["networks"][0]
        self.assertEqual(net["ip"], "8.8.8.8")
        self.assertEqual(net["cidr"], "8.8.8.0/24")
        self.assertEqual(net["asn"], "AS15169")
        self.assertEqual(net["org"]["name"], "Google LLC")
        self.assertEqual(net["org"]["country"], "US")
        self.assertIsNotNone(net["network"])

    @patch("whois_resolver.whois_query")
    def test_stops_at_first_server_with_cidr(self, mock_query):
        # Первый сервер без CIDR, второй — с CIDR: должен выбраться второй.
        mock_query.side_effect = [
            "no route here\n",
            "route: 8.8.8.0/24\n",
        ]
        result = lookup_whois("8.8.8.8")
        net = result["networks"][0]
        self.assertEqual(net["cidr"], "8.8.8.0/24")
        self.assertEqual(net["server"], "whois.ripe.net")
        self.assertEqual(mock_query.call_count, 2)

    @patch("whois_resolver.whois_query")
    def test_falls_back_when_no_cidr_anywhere(self, mock_query):
        # Ни один сервер не дал CIDR, но ASN извлекается из первого ответа.
        mock_query.return_value = "origin: AS15169\n"
        result = lookup_whois("8.8.8.8")
        net = result["networks"][0]
        self.assertIsNone(net["cidr"])
        self.assertEqual(net["asn"], "AS15169")
        self.assertEqual(net["server"], "whois.radb.net")

    @patch("whois_resolver.whois_query", return_value=None)
    def test_error_when_all_servers_fail(self, _):
        result = lookup_whois("8.8.8.8")
        self.assertIsNotNone(result["error"])
        self.assertEqual(result["networks"], [])

    def test_private_ip_error(self):
        result = lookup_whois("192.168.1.1")
        self.assertIn("приватный", result["error"])

    def test_invalid_input_error(self):
        result = lookup_whois("not a valid input!!!")
        self.assertIsNotNone(result["error"])
        self.assertEqual(result["networks"], [])

    @patch("whois_resolver.whois_query")
    @patch("whois_resolver.resolve_domain")
    def test_domain_single_ip(self, mock_resolve, mock_query):
        mock_resolve.return_value = {"all_ipv4": ["8.8.8.8"], "all_ipv6": []}
        mock_query.return_value = "route: 8.8.8.0/24\n"
        result = lookup_whois("dns.google")
        self.assertEqual(result["type"], "домен")
        self.assertEqual(result["all_ipv4"], ["8.8.8.8"])
        self.assertEqual(len(result["networks"]), 1)
        self.assertEqual(result["networks"][0]["cidr"], "8.8.8.0/24")

    @patch("whois_resolver.whois_query")
    @patch("whois_resolver.resolve_domain")
    def test_domain_addresses_in_same_cidr_collapse(self, mock_resolve, mock_query):
        # Два адреса из одной /24: должен быть один сетевой блок, второй адрес
        # попадает в covered_ips, повторный WHOIS-запрос не делается.
        mock_resolve.return_value = {"all_ipv4": ["8.8.8.8", "8.8.8.9"], "all_ipv6": []}
        mock_query.return_value = "route: 8.8.8.0/24\n"
        result = lookup_whois("dns.google")
        self.assertEqual(len(result["networks"]), 1)
        self.assertEqual(result["networks"][0]["covered_ips"], ["8.8.8.8", "8.8.8.9"])
        # Запрос ушёл только для первого адреса (перебор серверов до CIDR = 1 вызов).
        self.assertEqual(mock_query.call_count, 1)

    @patch("whois_resolver.whois_query")
    @patch("whois_resolver.resolve_domain")
    def test_domain_addresses_in_different_cidrs(self, mock_resolve, mock_query):
        # Два адреса из разных сетей: должно получиться два блока.
        mock_resolve.return_value = {"all_ipv4": ["8.8.8.8", "1.1.1.1"], "all_ipv6": []}
        mock_query.side_effect = ["route: 8.8.8.0/24\n", "route: 1.1.1.0/24\n"]
        result = lookup_whois("example.com")
        self.assertEqual(len(result["networks"]), 2)
        cidrs = {n["cidr"] for n in result["networks"]}
        self.assertEqual(cidrs, {"8.8.8.0/24", "1.1.1.0/24"})

    @patch("whois_resolver.resolve_domain", return_value=None)
    def test_domain_resolve_failure(self, _):
        result = lookup_whois("nonexistent.invalid")
        self.assertIn("разрешить", result["error"])


if __name__ == "__main__":
    unittest.main()
