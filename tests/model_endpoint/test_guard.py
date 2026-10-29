"""CONF-MEQ-001A: the base-URL guard admits only loopback and private-range IP literals and localhost (mapped without a
resolver call), and refuses every other class with its own code. No resolver or connection function may be called.

Public-address vectors are documentation addresses (RFC 5737 and RFC 3849).
"""
import socket
import unittest
from unittest import mock

import _client


def _forbidden(name):
    def call(*args, **kwargs):
        raise AssertionError(name + " was called")
    return call


class GuardTests(unittest.TestCase):
    def setUp(self):
        # A resolver or connection call anywhere in the guard fails the test.
        for name in ("getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr", "create_connection"):
            patcher = mock.patch.object(socket, name, _forbidden("socket." + name))
            patcher.start()
            self.addCleanup(patcher.stop)

    def admitted(self, url, scheme, address, port, base_path=""):
        target = _client.guard_base_url(url)
        self.assertEqual((target.scheme, target.address, target.port, target.base_path), (scheme, address, port, base_path))

    def refused(self, url, code):
        with self.assertRaises(_client.MeqError) as caught:
            _client.guard_base_url(url)
        self.assertEqual(caught.exception.code, code, url)

    def test_loopback_literals_are_admitted(self):
        self.admitted("http://127.0.0.1:11434", "http", "127.0.0.1", 11434)
        self.admitted("http://127.255.255.254:8080/", "http", "127.255.255.254", 8080)
        self.admitted("http://[::1]:8080/v1", "http", "::1", 8080, "/v1")

    def test_private_range_literals_are_admitted(self):
        for host, address in (("10.0.0.1", "10.0.0.1"), ("10.255.255.254", "10.255.255.254"), ("172.16.0.1", "172.16.0.1"),
                              ("172.31.255.254", "172.31.255.254"), ("192.168.1.10", "192.168.1.10"),
                              ("[fc00::1]", "fc00::1"), ("[fd12:3456:789a::1]", "fd12:3456:789a::1")):
            with self.subTest(host=host):
                self.admitted("http://" + host + ":8000/v1", "http", address, 8000, "/v1")

    def test_localhost_is_mapped_to_loopback_without_a_resolver(self):
        self.admitted("http://localhost:11434", "http", "127.0.0.1", 11434)
        self.admitted("http://LocalHost:11434/v1/", "http", "127.0.0.1", 11434, "/v1")

    def test_http_and_https_with_default_ports(self):
        self.admitted("http://127.0.0.1", "http", "127.0.0.1", 80)
        self.admitted("https://127.0.0.1", "https", "127.0.0.1", 443)
        self.admitted("HTTPS://10.0.0.2:8443/api/v1", "https", "10.0.0.2", 8443, "/api/v1")

    def test_link_local_v4_and_v6_are_refused(self):
        for url in ("http://169.254.169.254/", "http://169.254.0.1:80", "http://[fe80::1]:8080", "http://[febf::1]/"):
            with self.subTest(url=url):
                self.refused(url, "MEQ_GUARD_LINK_LOCAL")

    def test_public_addresses_are_refused(self):
        for url in ("http://192.0.2.10:8080", "http://198.51.100.7/", "http://203.0.113.5", "http://[2001:db8::1]:8080",
                    "http://172.32.0.1", "http://172.15.255.254", "http://0.0.0.0", "http://255.255.255.255",
                    "http://[::ffff:127.0.0.1]/", "http://[::ffff:169.254.169.254]/", "http://[::]/"):
            with self.subTest(url=url):
                self.refused(url, "MEQ_GUARD_HOST_CLASS")

    def test_dns_names_are_refused_without_a_resolver_call(self):
        for url in ("http://engine.example:11434", "http://localhost.example/", "http://localhost./", "http://example/",
                    "http://127.1/", "http://2130706433/", "http://0x7f000001/", "http://010.0.0.1/", "http://xn--e1a.example/"):
            with self.subTest(url=url):
                self.refused(url, "MEQ_GUARD_NAME")

    def test_userinfo_is_refused(self):
        for url in ("http://user@127.0.0.1/", "http://user:pass@127.0.0.1:8080", "http://@127.0.0.1/",
                    "http://192.0.2.10@127.0.0.1/"):
            with self.subTest(url=url):
                self.refused(url, "MEQ_GUARD_USERINFO")

    def test_query_and_fragment_are_refused(self):
        self.refused("http://127.0.0.1:8080/?a=1", "MEQ_GUARD_QUERY")
        self.refused("http://127.0.0.1:8080?a=1", "MEQ_GUARD_QUERY")
        self.refused("http://127.0.0.1:8080/v1#x", "MEQ_GUARD_FRAGMENT")
        self.refused("http://127.0.0.1#@192.0.2.10/", "MEQ_GUARD_FRAGMENT")

    def test_bad_schemes_are_refused(self):
        for url in ("ftp://127.0.0.1/", "file:///etc", "ws://127.0.0.1/", "127.0.0.1:8080", "//127.0.0.1/", "http:/127.0.0.1",
                    "httpx://127.0.0.1"):
            with self.subTest(url=url):
                self.refused(url, "MEQ_GUARD_SCHEME")

    def test_bad_ports_are_refused(self):
        for url in ("http://127.0.0.1:0", "http://127.0.0.1:65536", "http://127.0.0.1:abc", "http://127.0.0.1:/",
                    "http://127.0.0.1:-1", "http://127.0.0.1:123456", "http://[::1]:99999/"):
            with self.subTest(url=url):
                self.refused(url, "MEQ_GUARD_PORT")

    def test_an_empty_host_is_refused(self):
        for url in ("http://", "http:///v1", "http://:8080/", "http://[]:8080/"):
            with self.subTest(url=url):
                self.refused(url, "MEQ_GUARD_EMPTY_HOST")

    def test_malformed_urls_are_refused(self):
        for url in ("", " http://127.0.0.1", "http://127.0.0.1/a b", "http://127.0.0.1\\@192.0.2.10/", "http://[::1/",
                    "http://[::1]x/", "http://::1/", "http://%31%32%37.0.0.1/", "http://[fe80::1%25en0]/",
                    "http://[127.0.0.1]/", "http://127.0.0.1/v1/../admin", "http://127.0.0.1//v1", "http://caf\u00e9/",
                    None, b"http://127.0.0.1/"):
            with self.subTest(url=url):
                self.refused(url, "MEQ_GUARD_MALFORMED")

    def test_each_refusal_class_has_its_own_code(self):
        codes = [code for code in _client.ERROR_CODES if code.startswith("MEQ_GUARD_")]
        self.assertEqual(len(codes), len(set(codes)))
        self.assertEqual(set(codes), {"MEQ_GUARD_MALFORMED", "MEQ_GUARD_SCHEME", "MEQ_GUARD_EMPTY_HOST",
                                      "MEQ_GUARD_USERINFO", "MEQ_GUARD_QUERY", "MEQ_GUARD_FRAGMENT", "MEQ_GUARD_PORT",
                                      "MEQ_GUARD_NAME", "MEQ_GUARD_LINK_LOCAL", "MEQ_GUARD_HOST_CLASS"})


if __name__ == "__main__":
    unittest.main()
