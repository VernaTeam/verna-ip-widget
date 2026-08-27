# Verna IP Widget

**English** · [فارسی](README.fa.md)

A small always-on-top desktop widget for Windows that answers one question at a
glance: **where does my traffic come out, and is it going through a tunnel?**

It shows the public IP, country flag and name, city, ISP, and a traffic-path
badge — and it reacts to a VPN connecting or disconnecting within about two
seconds, without polling any geolocation API in the meantime.

```
┌──────────────────────────────┐
│ 🇺🇸  United States   VPN   ● │
│ 203.0.113.7  ·  Dallas       │
│ Example Datacenter Inc       │
└──────────────────────────────┘
```

## Why the badge matters

Country alone is not the answer. If your VPN egress and your ISP geolocate to
the same place, or a tunnel is up but traffic is not actually going through it,
a flag tells you nothing. The badge reports how traffic leaves the machine:

| Badge | Meaning |
|---|---|
| `VPN` | The outbound route belongs to a tunnel adapter |
| `PROXY` | A Windows system proxy is set (v2rayN, Nekoray, …) |
| `DIRECT` | Physical adapter, no proxy |
| `OFFLINE` | No route to the internet |

The ISP line is the second half of that picture — a datacenter name where you
expect a residential ISP (or the reverse) is usually the first sign something
is not routed the way you think.

## How the detection works

Two ideas do most of the work.

**Change detection generates no internet traffic.** Every two seconds the
widget computes a purely local signature: the local outbound IP — obtained by
`connect()`ing a UDP socket, which performs only a routing-table lookup and
sends no packets — plus the Windows system-proxy registry values. TUN-mode
VPNs change the former; system-proxy clients change the latter. Only when that
signature changes does a geolocation fetch run, after a short debounce (the
network flaps several times while a VPN connects). A 15-second poll remains as
a safety net for public-IP changes with no local footprint, such as switching
servers inside the VPN app.

**The path is read from the routing table, not guessed from the IP range.** A
VPN handing out `10.x` is indistinguishable from a LAN by address alone, so the
widget calls `GetAdaptersAddresses` to find which interface actually owns the
outbound address, then classifies it by `ifType` *and* by adapter name —
WireGuard and wintun adapters report `ifType 6` (ethernet), so the type check
alone would miss them.

## Features

- Frameless, draggable, always-on-top (toggleable), with adjustable size and opacity
- Transparent-background mode: only the text and flag float over the desktop
- **Lock position** so a stray drag cannot move it
- System tray icon showing the current country's flag; tooltip carries path, IP, ISP and adapter
- Double-click to copy the IP
- Country name flashes when the public IP changes
- Global hotkey `Ctrl+Alt+I` summons the widget from anywhere
- Optional launch at Windows startup (per-user registry, no admin needed)
- Three geolocation providers tried in order, with automatic failover

### Self-healing

The window is `overrideredirect` — frameless, with no taskbar button and no
Alt+Tab entry. That is what makes it a widget, and it is also a hazard: nothing
that hides such a window is recoverable by normal means. A watchdog runs every
three seconds and will:

- restore the window if the shell hid or minimised it (checked against Win32
  `IsWindowVisible`/`IsIconic`, because Tk's own `winfo_viewable()` does not see
  a shell-level hide)
- move it back if it ends up outside the virtual desktop, e.g. after a
  resolution or monitor change
- re-assert always-on-top periodically
- refuse to stay hidden when no tray icon exists to restore it from
- re-create the tray icon after `explorer.exe` restarts, which pystray does not
  handle on its own

## Controls

| Gesture | Action |
|---|---|
| Drag | Move (unless locked) |
| Double-click | Copy IP |
| Right-click | Menu |
| `Ctrl` + wheel | Size |
| `Shift` + wheel | Opacity |
| `Ctrl+Alt+I` | Summon from anywhere |

## Install and run

Requires Windows and Python 3.10+.

```bash
python -m venv venv
venv\Scripts\pip install -r requirements.txt
venv\Scripts\pythonw.exe ip_widget.pyw
```

`pystray` and `pillow` are optional — without them the widget runs exactly the
same, just without a tray icon.

### Build a standalone executable

```bash
venv\Scripts\python.exe -m PyInstaller --clean --noconfirm VernaIPWidget.spec
```

Produces a console-less single-file `dist/VernaIPWidget.exe`.

## Tests

```bash
python -m unittest test_ip_widget.py -v
```

Covers the geolocation response parsers, the traffic-path classifier, and the
event bindings. The binding tests exist because of a real bug: handlers were
bound on the child widgets *and* on the toplevel, but a child's `bindtags`
already contain the toplevel, so every gesture fired twice — the right-click
menu posted two stacked menus and needed two clicks to reach an entry. The
tests skip cleanly where there is no display.

## Configuration

Settings live in `%APPDATA%\VernaIPWidget\config.json` (position, size tier,
opacity, transparency, always-on-top, lock) and are written atomically.

A rotating log sits beside it at `%APPDATA%\VernaIPWidget\widget.log` —
reachable from the right-click menu via *Open log folder*. A console-less build
has no stderr, so this file is the only diagnostic.

## Credits

Icons by [Icons8](https://icons8.com). Flags from
[flagcdn.com](https://flagcdn.com). Geolocation from
[ip-api.com](https://ip-api.com), [ipwho.is](https://ipwho.is) and
[ipinfo.io](https://ipinfo.io) — all free tiers, no API key required.

## License

MIT — see [LICENSE](LICENSE).
