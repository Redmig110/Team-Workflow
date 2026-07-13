import unittest

from team_protocol.playwright_proxy import PlaywrightProxyLease, apply_playwright_proxy


class PlaywrightProxyTests(unittest.TestCase):
    def test_authenticated_socks5_uses_loopback_adapter_without_credentials(self):
        proxy = "socks5://tenant-sid-Stable90:password@proxy.example:1000"

        with PlaywrightProxyLease(proxy) as lease:
            config = dict(lease.playwright_proxy or {})
            options = apply_playwright_proxy({"headless": True}, lease)

        self.assertRegex(config["server"], r"^http://127\.0\.0\.1:\d+$")
        self.assertNotIn("tenant", str(config))
        self.assertNotIn("password", str(config))
        self.assertEqual(options["proxy"], config)

    def test_http_proxy_credentials_are_split_from_server(self):
        with PlaywrightProxyLease(
            "http://tenant:password@proxy.example:8080"
        ) as lease:
            self.assertEqual(
                lease.playwright_proxy,
                {
                    "server": "http://proxy.example:8080",
                    "username": "tenant",
                    "password": "password",
                },
            )


if __name__ == "__main__":
    unittest.main()
