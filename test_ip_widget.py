"""Unit tests for the pure logic in ip_widget.py: the geolocation response
parsers and the traffic-path classifier.

Run (Windows CMD, in the project directory):
    python -m unittest test_ip_widget.py -v
"""

from __future__ import annotations

import json
import unittest

from ip_widget import (
    PATH_DIRECT,
    PATH_OFFLINE,
    PATH_PROXY,
    PATH_VPN,
    GeoInfo,
    NetworkState,
    _parse_ip_api,
    _parse_ipinfo,
    _parse_ipwhois,
    is_loopback_proxy,
    looks_like_vpn,
    parse_proxy_endpoint,
)


def _encode(payload: dict) -> bytes:
    return json.dumps(payload).encode("utf-8")


class ParseIpApiTests(unittest.TestCase):
    def test_success_response(self) -> None:
        info = _parse_ip_api(_encode({
            "status": "success", "country": "Germany", "countryCode": "DE",
            "city": "Falkenstein", "query": "143.14.59.34", "isp": "Hetzner Online GmbH",
        }))
        assert info is not None
        self.assertEqual(info.ip, "143.14.59.34")
        self.assertEqual(info.country, "Germany")
        self.assertEqual(info.country_code, "de")  # normalized to lowercase
        self.assertEqual(info.city, "Falkenstein")
        self.assertEqual(info.isp, "Hetzner Online GmbH")

    def test_org_is_used_when_isp_is_absent(self) -> None:
        info = _parse_ip_api(_encode({
            "status": "success", "countryCode": "DE", "query": "1.1.1.1",
            "org": "Some Org",
        }))
        assert info is not None
        self.assertEqual(info.isp, "Some Org")

    def test_fail_status_returns_none(self) -> None:
        self.assertIsNone(_parse_ip_api(_encode({"status": "fail", "message": "quota"})))

    def test_missing_fields_do_not_raise(self) -> None:
        info = _parse_ip_api(_encode({"status": "success"}))
        assert info is not None
        self.assertEqual(info.ip, "")
        self.assertEqual(info.city, "")


class ParseIpWhoisTests(unittest.TestCase):
    def test_success_response(self) -> None:
        info = _parse_ipwhois(_encode({
            "success": True, "ip": "5.6.7.8", "country": "Iran",
            "country_code": "IR", "city": "Tehran",
            "connection": {"isp": "Irancell", "org": "MTN"},
        }))
        assert info is not None
        self.assertEqual(info.ip, "5.6.7.8")
        self.assertEqual(info.country_code, "ir")
        self.assertEqual(info.isp, "Irancell")

    def test_missing_connection_block_is_not_fatal(self) -> None:
        info = _parse_ipwhois(_encode({
            "success": True, "ip": "5.6.7.8", "country_code": "IR",
        }))
        assert info is not None
        self.assertEqual(info.isp, "")

    def test_failure_returns_none(self) -> None:
        self.assertIsNone(_parse_ipwhois(_encode({"success": False})))


class ParseIpInfoTests(unittest.TestCase):
    def test_success_uses_code_as_country_name(self) -> None:
        info = _parse_ipinfo(_encode({"ip": "1.2.3.4", "country": "NL", "city": "Amsterdam"}))
        assert info is not None
        self.assertEqual(info.country, "NL")
        self.assertEqual(info.country_code, "nl")

    def test_as_number_is_stripped_from_org(self) -> None:
        info = _parse_ipinfo(_encode({
            "ip": "1.2.3.4", "country": "NL", "org": "AS15169 Google LLC",
        }))
        assert info is not None
        self.assertEqual(info.isp, "Google LLC")

    def test_org_without_as_prefix_is_kept_verbatim(self) -> None:
        info = _parse_ipinfo(_encode({"ip": "1.2.3.4", "country": "NL", "org": "Google LLC"}))
        assert info is not None
        self.assertEqual(info.isp, "Google LLC")

    def test_missing_ip_returns_none(self) -> None:
        self.assertIsNone(_parse_ipinfo(_encode({"country": "NL"})))


class TrafficPathTests(unittest.TestCase):
    """The badge answers "how does traffic leave this machine", so the
    classifier order matters: a tunnel adapter outranks a system proxy."""

    def test_no_route_is_offline(self) -> None:
        self.assertEqual(NetworkState().path, PATH_OFFLINE)

    def test_plain_wifi_is_direct(self) -> None:
        state = NetworkState(local_ip="192.168.1.10",
                             adapter="Generic 802.11ac Wireless Adapter", if_type=71)
        self.assertEqual(state.path, PATH_DIRECT)

    def test_system_proxy_on_a_physical_nic_is_proxy(self) -> None:
        state = NetworkState(local_ip="192.168.1.10", proxy="http://127.0.0.1:1080",
                             adapter="Realtek PCIe GbE Family Controller", if_type=6)
        self.assertEqual(state.path, PATH_PROXY)

    def test_tunnel_iftype_is_vpn(self) -> None:
        state = NetworkState(local_ip="10.2.0.2", adapter="Unnamed", if_type=131)
        self.assertEqual(state.path, PATH_VPN)

    def test_tunnel_adapter_name_is_vpn_even_at_iftype_ethernet(self) -> None:
        # WireGuard/wintun adapters report ifType 6, so the name check is
        # what catches them.
        state = NetworkState(local_ip="10.2.0.2", adapter="WireGuard Tunnel", if_type=6)
        self.assertEqual(state.path, PATH_VPN)

    def test_tunnel_outranks_proxy(self) -> None:
        state = NetworkState(local_ip="10.2.0.2", proxy="http://127.0.0.1:8080",
                             adapter="TAP-Windows Adapter V9", if_type=6)
        self.assertEqual(state.path, PATH_VPN)

    def test_signature_ignores_the_adapter(self) -> None:
        # Only the route and the proxy trigger a re-fetch; the adapter name is
        # derived from them, so including it would be redundant churn.
        first = NetworkState(local_ip="10.0.0.1", proxy="", adapter="A", if_type=6)
        second = NetworkState(local_ip="10.0.0.1", proxy="", adapter="B", if_type=131)
        self.assertEqual(first.signature, second.signature)


class VpnAdapterHeuristicTests(unittest.TestCase):
    def test_known_clients_match_case_insensitively(self) -> None:
        for name in ("WireGuard Tunnel", "TAP-Windows Adapter V9", "wintun",
                     "Cloudflare WARP", "Proton VPN TUN", "sing-box tun"):
            self.assertTrue(looks_like_vpn(name, 6), name)

    def test_physical_adapters_do_not_match(self) -> None:
        for name in ("Realtek PCIe GbE Family Controller",
                     "Intel(R) Wi-Fi 6 AX201 160MHz",
                     "Generic 802.11ac Wireless Adapter"):
            self.assertFalse(looks_like_vpn(name, 6), name)


class ProxyEndpointTests(unittest.TestCase):
    """Windows writes ProxyServer in several shapes."""

    def test_bare_host_port(self) -> None:
        self.assertEqual(parse_proxy_endpoint("127.0.0.1:12334"), ("127.0.0.1", 12334))

    def test_scheme_qualified(self) -> None:
        self.assertEqual(parse_proxy_endpoint("http://10.0.0.5:3128"), ("10.0.0.5", 3128))

    def test_per_protocol_list_uses_the_first_entry(self) -> None:
        self.assertEqual(
            parse_proxy_endpoint("http=127.0.0.1:8080;https=127.0.0.1:8081"),
            ("127.0.0.1", 8080),
        )

    def test_unparseable_values_return_none(self) -> None:
        for value in ("", "garbage", "host-without-port", "host:notaport"):
            self.assertIsNone(parse_proxy_endpoint(value), value)

    def test_loopback_detection(self) -> None:
        self.assertTrue(is_loopback_proxy("127.0.0.1:1080"))
        self.assertTrue(is_loopback_proxy("http://localhost:8080"))
        self.assertFalse(is_loopback_proxy("http://10.0.0.5:3128"))
        self.assertFalse(is_loopback_proxy(""))


class DeadProxyTests(unittest.TestCase):
    """A VPN client that exits without clearing ProxyEnable leaves the
    registry advertising a proxy that nothing serves. Reporting PROXY then is
    wrong: urllib falls back to a direct connection and that is where the
    traffic actually goes. This is the bug behind a widget showing PROXY next
    to a domestic ISP.
    """

    def _state(self, **kw):
        base = dict(local_ip="192.168.1.10", proxy="http://127.0.0.1:12334",
                    adapter="Generic 802.11ac Wireless Adapter", if_type=71)
        base.update(kw)
        return NetworkState(**base)

    def test_dead_proxy_reads_as_direct(self) -> None:
        self.assertEqual(self._state(proxy_alive=False).path, PATH_DIRECT)

    def test_live_proxy_reads_as_proxy(self) -> None:
        self.assertEqual(self._state(proxy_alive=True).path, PATH_PROXY)

    def test_unprobed_proxy_trusts_the_registry(self) -> None:
        # None means "not probed yet"; the registry is the best guess until
        # a probe or a fetch says otherwise.
        self.assertEqual(self._state(proxy_alive=None).path, PATH_PROXY)

    def test_tunnel_outranks_even_a_live_proxy(self) -> None:
        state = self._state(adapter="WireGuard Tunnel", if_type=6, proxy_alive=True)
        self.assertEqual(state.path, PATH_VPN)

    def test_no_route_is_offline_regardless_of_proxy(self) -> None:
        self.assertEqual(self._state(local_ip="", proxy_alive=True).path, PATH_OFFLINE)


class EventBindingTests(unittest.TestCase):
    """One user gesture must reach its handler exactly once.

    Every child widget's bindtags already contain the toplevel, so binding a
    handler on the children AND on the toplevel runs it twice. That shipped:
    tk_popup posted two stacked menus, so the first click on an entry only
    dismissed the top one and a second click was needed to reach it, and a
    single wheel notch stepped opacity and size twice.
    """

    widget = None
    counts: dict = {}

    @classmethod
    def setUpClass(cls) -> None:
        try:
            import tkinter  # noqa: F401
        except Exception as exc:
            raise unittest.SkipTest(f"tkinter unavailable: {exc}")

        import ip_widget

        cls.module = ip_widget
        cls.counts = {"menu": 0, "opacity": 0, "scale": 0}

        # Patch BEFORE constructing: bind() captures the bound method, so a
        # handler swapped in afterwards is never the one that runs.
        cls._originals = {}
        for attr, key in (("_show_menu", "menu"),
                          ("_on_wheel_opacity", "opacity"),
                          ("_on_wheel_scale", "scale")):
            cls._originals[attr] = getattr(ip_widget.IPWidget, attr)

            def counting(self, *a, _key=key, **k):
                EventBindingTests.counts[_key] += 1

            setattr(ip_widget.IPWidget, attr, counting)

        # Keep it offline and single-threaded: no tray, no hotkey thread, no
        # fetch, no timers. Only the widget tree and its bindings are tested.
        for attr in ("_init_tray", "_start_hotkey_listener", "_start_fetch",
                     "_self_heal", "_poll", "_watch_network"):
            cls._originals[attr] = getattr(ip_widget.IPWidget, attr)
            setattr(ip_widget.IPWidget, attr, lambda self, *a, **k: None)

        try:
            cls.widget = ip_widget.IPWidget()
        except Exception as exc:
            cls._restore()
            raise unittest.SkipTest(f"no display: {exc}")
        cls.widget.root.update()

    @classmethod
    def _restore(cls) -> None:
        for attr, original in getattr(cls, "_originals", {}).items():
            setattr(cls.module.IPWidget, attr, original)

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.widget is not None:
            cls.widget.root.destroy()
            cls.widget = None
        cls._restore()

    def _fire(self, key: str, sequence: str, **event_kwargs) -> None:
        """Fire one event over the toplevel and over a nested child; each
        must reach the handler exactly once."""
        w = self.widget
        for target in (w.root, w.country_label, w.detail_label):
            EventBindingTests.counts[key] = 0
            target.event_generate(sequence, x=3, y=3, **event_kwargs)
            w.root.update()
            self.assertEqual(
                EventBindingTests.counts[key], 1,
                f"one {sequence} on {target} reached the handler "
                f"{EventBindingTests.counts[key]}x, expected exactly 1",
            )

    def test_right_click_posts_the_menu_once(self) -> None:
        self._fire("menu", "<Button-3>")

    def test_shift_wheel_steps_opacity_once(self) -> None:
        self._fire("opacity", "<MouseWheel>", delta=120, state=0x0001)

    def test_control_wheel_steps_size_once(self) -> None:
        self._fire("scale", "<MouseWheel>", delta=120, state=0x0004)

    def test_failed_fetch_does_not_leave_a_contradictory_reading(self) -> None:
        """A failed fetch used to print "No connection" while leaving the
        previous IP, city and ISP on screen, so the widget contradicted
        itself. The last reading may stay, but it must be marked."""
        w = self.widget
        w._current_info = GeoInfo(ip="203.0.113.7", country="Germany",
                                  country_code="de", city="Berlin",
                                  isp="Example GmbH")
        w._render_isp()
        w._apply_result(w._fetch_seq, None, None, w._tier["flag"])
        w.root.update()

        detail = w.detail_label.cget("text")
        self.assertIn("203.0.113.7", detail, "the last reading should survive")
        self.assertIn("last known", detail, "and it must be marked as stale")
        self.assertNotEqual(
            w.country_label.cget("text"), "No connection",
            "'No connection' above a full IP is the contradiction being fixed",
        )

    def test_failed_fetch_with_no_history_says_no_connection(self) -> None:
        w = self.widget
        w._current_info = None
        w._apply_result(w._fetch_seq, None, None, w._tier["flag"])
        w.root.update()
        self.assertEqual(w.country_label.cget("text"), "No connection")
        self.assertEqual(w.detail_label.cget("text"), "")

    def test_direct_fallback_marks_the_proxy_dead(self) -> None:
        """If a proxy is configured but the direct fallback carried the
        request, the badge must stop claiming PROXY."""
        w = self.widget
        w._net_state = NetworkState(local_ip="192.168.1.10",
                                    proxy="http://127.0.0.1:12334",
                                    adapter="Generic 802.11ac Wireless Adapter",
                                    if_type=71, proxy_alive=True)
        info = GeoInfo(ip="203.0.113.7", country="Iran", country_code="ir",
                       city="Rasht", isp="Example ISP")
        w._apply_result(w._fetch_seq, info, None, w._tier["flag"], via_proxy=False)
        w.root.update()
        self.assertIs(w._net_state.proxy_alive, False)
        self.assertEqual(w.path_badge.cget("text"), PATH_DIRECT)

    def test_only_the_toplevel_carries_the_bindings(self) -> None:
        w = self.widget
        self.assertIn("<Button-3>", w.root.bind())
        for child in (w.frame, w.top_row, w.country_label, w.detail_label,
                      w.status_dot, w.path_badge, w.flag_label, w.isp_label):
            self.assertEqual(
                child.bind(), (),
                f"{child} has its own bindings; they would double-fire "
                f"because the toplevel is already in its bindtags",
            )


class MalformedInputTests(unittest.TestCase):
    def test_invalid_json_raises_for_caller_to_catch(self) -> None:
        # fetch_geo() wraps each parser call in try/except; parsers themselves
        # are allowed to raise on garbage input.
        for parser in (_parse_ip_api, _parse_ipwhois, _parse_ipinfo):
            with self.assertRaises(Exception):
                parser(b"<html>blocked by filter</html>")


if __name__ == "__main__":
    unittest.main()
