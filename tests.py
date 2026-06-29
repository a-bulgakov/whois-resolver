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


class TestExtractAsn(unittest.TestCase):
    def test_origin_field(self):
        self.assertEqual(extract_asn("origin: AS15169"), "AS15169")

    def test_aut_num_field(self):
        self.assertEqual(extract_asn("aut-num: AS15169"), "AS15169")

    def test_asnumber_field(self):
        self.assertEqual(extract_asn("ASNumber: AS15169"), "AS15169")

    def test_bare_as_with_space(self):
        self.assertEqual(extract_asn("AS 15169"), "AS15169")

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


if __name__ == "__main__":
    unittest.main()
