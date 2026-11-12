import unittest
from ui_widgets import destination_rules,normalize_cidr_destinations


class DestinationInputTests(unittest.TestCase):
    def test_pasted_url_loses_path_query_and_fragment(self):
        self.assertEqual(destination_rules('https://Example.COM/account?token=test#section'),['*.example.com'])

    def test_many_websites_and_subdomains(self):
        self.assertEqual(destination_rules('example.com, https://example.com/\n*.sub.example.org'),['*.example.com','*.sub.example.org'])

    def test_rejects_credentials_wrong_scheme_and_empty(self):
        for value in ('https://user:password@example.com/','ftp://example.com','', 'not a domain'):
            with self.assertRaises(ValueError):destination_rules(value)

    def test_ip_url_becomes_ipv4_host_route(self):
        self.assertEqual(destination_rules('http://203.0.113.10/luna/'),['203.0.113.10/32'])
        self.assertEqual(destination_rules('https://203.0.113.10:8443/luna/'),['203.0.113.10/32'])

    def test_ipv6_url_is_rejected(self):
        with self.assertRaisesRegex(ValueError,'IPv4'):destination_rules('http://[2001:db8::1]/')

    def test_urls_in_advanced_cidr_field_normalize_to_one_host_route(self):
        value='/203.0.113.10/ui/#/workbench/,http://203.0.113.10/luna/'
        self.assertEqual(normalize_cidr_destinations(value),(['203.0.113.10/32'],[]))
        self.assertEqual(normalize_cidr_destinations('10.20.0.0/16,https://example.com/path'),(['10.20.0.0/16'],['*.example.com']))

    def test_exact_domain_option_preserves_explicit_wildcard(self):
        self.assertEqual(destination_rules('example.com *.sub.example.com',False),['example.com','*.sub.example.com'])
