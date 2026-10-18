# NetSpy v1.0

**See which programs on your Windows PC talk to the internet, and what Microsoft collects, live.**

NetSpy is a single Python script that shows every program using the network: how much it sends and receives, where it goes, and, for Microsoft connections, *what they are for* (telemetry, ads, Bing search, remote settings, updates…).

- **All in one:** per-program traffic, DNS lookups, Microsoft purpose labels, beacon detection, file checks (hash and signature), firewall control and Windows network tools, in one window.
- **Private by default:** in the default mode NetSpy itself sends **nothing** over the network.
- **Lightweight:** about 3–6% of one CPU core and about 100 MB of RAM in our tests.
- **No disk wear:** everything stays in RAM. No logs, no database, no temp files.
- **Transparent:** one readable script. No installer, no service, no driver in the default mode.

> NetSpy only **watches**. It does not hide your IP address and is not a VPN. When Windows sends telemetry, Microsoft still receives it; NetSpy shows you that it happens.

---

## Contents
1. [Requirements](#1-requirements)
2. [Install](#2-install)
3. [Open an Administrator terminal](#3-open-an-administrator-terminal)
4. [The three modes](#4-the-three-modes)
5. [All commands](#5-all-commands)
6. [Wi-Fi, Ethernet (LAN), VPN and choosing an adapter](#6-wi-fi-ethernet-lan-vpn-and-choosing-an-adapter)
7. [Private / offline use](#7-private--offline-use)
8. [Keyboard controls](#8-keyboard-controls)
9. [Reading the main screen](#9-reading-the-main-screen)
10. [Firewall: allow and block programs](#10-firewall-allow-and-block-programs)
11. [Privacy: exactly what NetSpy sends](#11-privacy-exactly-what-netspy-sends)
12. [Limits (what NetSpy cannot see)](#12-limits-what-netspy-cannot-see)
13. [Troubleshooting](#13-troubleshooting)
14. [Uninstall / clean up](#14-uninstall--clean-up)
15. [License](#15-license)

---

## 1. Requirements

| | Needed for |
|---|---|
| **Windows 10 or 11** | everything |
| **Python 3.10 or newer** ([python.org](https://www.python.org/downloads/), tick *"Add python.exe to PATH"* during setup) | everything |
| **Administrator terminal** | per-program byte counts (BASIC and ADVANCED) and firewall changes |
| **Npcap** (free driver, [npcap.com](https://npcap.com/#download), default install options) | ADVANCED mode only |

A terminal window at least **120 characters wide** is recommended. Windows Terminal, maximised, works best.

---

## 2. Install

Download or clone this repository, open a terminal in its folder, then run:

```powershell
python -m pip install -r requirements.txt
```

That installs everything. For **BASIC mode only**, two packages are enough:

```powershell
python -m pip install psutil rich
```

For **ADVANCED mode**, also install **Npcap** from <https://npcap.com/#download> (keep the default options).

> If `python` is not found, use `py` instead, for example `py -m pip install -r requirements.txt` and `py netspy.py`.

---

## 3. Open an Administrator terminal

NetSpy reads Windows' own network events (ETW), which Windows only allows for administrators.

1. Press **Start** and type **Terminal** (or **PowerShell**).
2. Right-click it and choose **Run as administrator**, then click **Yes**.
3. Go to the NetSpy folder, for example:
   ```powershell
   cd "$env:USERPROFILE\Downloads\netspy"
   ```

The header shows `Elevated: yes` when this worked.

---

## 4. The three modes

| | **BASIC** (default) | **ADVANCED** | **LIMITED** (automatic) |
|---|---|---|---|
| Start with | `python netspy.py` | `python netspy.py --advanced` | used when the terminal is **not** Administrator |
| Needs | Administrator | Administrator + Npcap + scapy | nothing |
| Per-program bytes sent/received | ✅ from Windows' events | ✅ from captured packets | ❌ |
| Short-lived programs named (even 50 ms) | ✅ | ✅ | ❌ |
| DNS lookups per program (also with encrypted DNS) | ✅ | ✅ | ❌ |
| Microsoft purpose labels | ✅ from DNS names | ✅ + TLS site names | ❌ |
| Site name from the TLS handshake, TLS version | ❌ | ✅ | ❌ |
| Ping traffic (ICMP) | ❌ | ✅ | ❌ |
| "Microsoft network" for unnamed IPs, country | ❌ | ✅ (online lookup) | ❌ |
| **Network requests made by NetSpy itself** | **none** | reverse DNS + IP owner lookups | none |
| CPU (our tests) | ≈3% of one core | ≈6% of one core | lowest |

**Which one should I use?**
- **BASIC** if you want privacy and no extra driver. It shows almost everything.
- **ADVANCED** if you want maximum detail and don't mind the online lookups described in [Privacy](#11-privacy-exactly-what-netspy-sends).

**Why BASIC and ADVANCED byte totals differ slightly:** BASIC counts the data bytes Windows reports, while ADVANCED counts whole network frames including headers. ADVANCED is usually a few percent higher. Both are correct.

The first header line always shows the active mode.

---

## 5. All commands

Run these in an **Administrator** terminal, inside the NetSpy folder.

| Command | What it does |
|---|---|
| `python netspy.py` | **BASIC mode**: private, no driver. Recommended start. |
| `python netspy.py --advanced` | **ADVANCED mode**: packet capture on every connected adapter, plus online lookups. |
| `python netspy.py --advanced --iface "WiFi"` | ADVANCED, capture **Wi-Fi only**. |
| `python netspy.py --advanced --iface "Ethernet"` | ADVANCED, capture **wired LAN only**. |
| `python netspy.py --list-interfaces` | Lists your adapter names (for `--iface`) and exits. |
| `python netspy.py --test` | Starts a **test traffic burst** after launch (see below). |
| `python netspy.py --blocklist bad_ips.txt` | Highlights connections to IPs in your own blocklist file. |
| `python netspy.py --connection-retention 300` | Keep idle connections in the list for 300 s (default 120). |
| `python netspy.py --max-connections-per-process 200` | Track up to 200 connections per program (default 100). |
| `python netspy.py --flash-window 3` | Keep the "active" highlight for 3 s (default 1.5). |
| `python netspy.py --help` | Shows all options. |

Options can be combined:

```powershell
python netspy.py --advanced --iface "WiFi" --connection-retention 300 --blocklist bad_ips.txt
```

**Blocklist file format:** one IP address or range per line, `#` starts a comment.

```text
# known bad hosts
203.0.113.7
198.51.100.0/24
```

**Test burst (`--test` or the `g` key):** runs `nslookup`, `ping`, `curl`, a PowerShell web request, `winget source update`, a Windows Update check and `w32tm /resync`. It also opens the Microsoft Store and, if installed, Edge, Chrome and Firefox on example.com. Use it to confirm NetSpy sees each program. It really contacts those sites.

Press **`q`** to quit.

---

## 6. Wi-Fi, Ethernet (LAN), VPN and choosing an adapter

**BASIC mode** works on **every adapter at once** (Wi-Fi, Ethernet, VPN, mobile hotspot, virtual machines). Windows reports the traffic itself, so there's nothing to choose. `--iface` has no effect in BASIC.

**ADVANCED mode** captures **every connected adapter automatically**: any adapter with a real (non-link-local) address. New adapters, such as a VPN you connect later, are picked up within about 5 seconds. The header shows `Adapters: N`.

To capture **one adapter only**:

```powershell
python netspy.py --list-interfaces          # shows e.g.  WiFi, Ethernet, VMware Network Adapter VMnet8
python netspy.py --advanced --iface "WiFi"
python netspy.py --advanced --iface "Ethernet"
```

Use the exact name shown, in quotes if it contains spaces.

**VPN:** both modes show traffic per program. In ADVANCED you can capture the VPN adapter itself (`--iface "<VPN adapter name>"`) or the physical adapter, where you'll only see the encrypted tunnel.

---

## 7. Private / offline use

- **BASIC mode is the private mode.** NetSpy makes **zero** network requests: no reverse-DNS queries, no IP-owner or country lookups. Fields that would need a lookup say *"not looked up (BASIC mode is private)"*.
- NetSpy also works **without any internet connection** in both modes. It then shows local network traffic only.
- In both modes NetSpy writes **nothing to disk**. When you quit, everything it collected is gone.

---

## 8. Keyboard controls

**Everywhere**

| Key | Action |
|---|---|
| ↑ ↓ / PgUp PgDn / Home End | scroll or move the selection |
| Enter | open: program → its connections → one connection |
| Esc | go back one step |
| 1 – 5 | sort the current list |
| q | quit |

**Screens** (press the key again or Esc to return)

| Key | Screen |
|---|---|
| d | **Domains:** every site or service this PC talks to |
| p | **Program → domain:** which program talks to which site |
| t | **Timeline:** new connections and DNS lookups, newest first |
| s | **System summary:** the whole PC on one screen, incl. Microsoft / telemetry totals |
| b | **Beacon watch:** servers contacted on a fixed rhythm |
| f | **Firewall:** allow or block programs (see section 10) |
| w | **Windows tools:** Windows' own network commands (DNS cache, proxy, resets…) |
| i | **File investigation** of the program behind the selected connection |
| h | **Help** |
| ? | **Concepts:** plain-language explanations of every term |

**Toggles**

| Key | Action |
|---|---|
| e | beginner tips bar ("what am I looking at?") |
| l | listening ports panel |
| y | process tree panel |
| m | hide the program list while viewing connections |
| o | hide programs idle for more than 10 minutes (they are dimmed otherwise) |
| c | reset all counters |
| g | run the test traffic burst |
| j | developer statistics |

Press **`e`** on any screen for a short explanation of what you're looking at.

---

## 9. Reading the main screen

| Column | Meaning |
|---|---|
| **Process** | the program. `svchost.exe (DiagTrack)` names the Windows service inside, here Windows telemetry. |
| **PID** | Windows' number for the running program |
| **Sent / Received / Total** | bytes since NetSpy started; bright = data moving right now |
| **Last seen** | time since its last network activity |
| **Top remote** | the server it exchanged the most data with. Cyan underlined = name known, blue = your own network. |
| **Microsoft** | what its Microsoft traffic is for (below). `+2` = two more purposes. |
| **Conns** | open connections right now |
| **Rate** | current speed (^ up, v down) |
| **Location** | where the program file lives: `Windows` / `Installed` = normal; `! AppData`, `! Temp`, `! Downloads` = worth a look |

**Microsoft purpose colours**

| Colour | Purposes |
|---|---|
| 🔴 red (data about you / ads) | Telemetry, Crash reports, Ads / Spotlight, Bing search, News / Widgets, Activity history |
| 🟡 yellow (settings / security lookups) | Remote config, Defender cloud, SmartScreen |
| 🔵 cyan (normal services) | Windows Update, Microsoft account, OneDrive, Store, Office, connectivity check… |

Microsoft totals count **everything since NetSpy started**, including connections that have since closed.

Special rows:
- **System:** Windows itself (file sharing, NetBIOS).
- **System / Unknown:** connections no program owns any more (already closing).
- **Unresolved / short-lived:** traffic whose program could not be identified (rare with ETW).

---

## 10. Firewall: allow and block programs

Press **`f`**. The firewall controls need an **Administrator** terminal.

| Key | Action |
|---|---|
| ↑ ↓ | select a program |
| a | **Allow** it (creates an outbound allow rule) |
| b | **Block** it (blocks outbound and inbound) |
| x | remove NetSpy's rules for it (back to Windows' default) |
| Enter | details: signature, location, matching Windows rules |
| i / u | switch between active programs, running programs and all installed apps |
| n | (app lists) cycle user / system / all apps |
| Space / k | (app lists) mark one / all apps as reviewed (memory only) |
| r | raw Windows Firewall rules; there **a**/**b** change the marked (top) rule |

Important:
- These are **real Windows Firewall rules**. They **stay after NetSpy closes**, so a blocked program stays blocked until you press `x` or remove the rule.
- Every rule NetSpy creates is named `NetSpy …`. See [Uninstall](#14-uninstall--clean-up) to remove them all.
- `svchost.exe` cannot be blocked here, because all Windows services share that one file. Disable the service itself in `services.msc` instead.
- Two different programs with the same file name (e.g. two `python.exe`) share one NetSpy rule.

---

## 11. Privacy: exactly what NetSpy sends

| Mode | Requests NetSpy makes by itself |
|---|---|
| **BASIC** (default) | **None.** |
| **ADVANCED** | For each public IP address it sees: a **reverse-DNS** query to your DNS provider, and an **owner/country lookup** at `ipwho.is`, then `ip-api.com` (plain HTTP), then `rdap.org` if the first fails. Results are cached in RAM for up to a day, with at most 8 lookups at a time. |

These lookups tell those services **which IP addresses you are looking at**. If that matters to you, use BASIC.

Only when **you** trigger them, NetSpy also:
- runs the test traffic burst (`g` / `--test`)
- runs Windows' own tools from the `w` screen (some ping your router or `1.1.1.1`)
- runs PowerShell on your PC to read firewall rules and file signatures (local only)

NetSpy never sends any data about you anywhere and has no telemetry of its own.

---

## 12. Limits (what NetSpy cannot see)

- **Content:** almost all traffic is encrypted (HTTPS). NetSpy shows who, where, when and how much, never what.
- **Unnamed Microsoft IPs:** without a site name, only the network owner is known (ADVANCED only).
- **Shared service hosts:** some `svchost.exe` processes host several services at once, and their traffic can't be split further.
- **Browser DNS:** browsers that use their own encrypted DNS (Firefox, Chrome "secure DNS") hide those lookups from Windows. ADVANCED still reads the name from the TLS handshake.
- **Hidden site names:** Encrypted Client Hello (ECH) can hide the site name; you then see a generic name such as `cloudflare-ech.com`.
- **BASIC mode** cannot show ping (ICMP) traffic or TLS versions.
- **Purpose labels** come from a list of known Microsoft endpoints. They are best-effort, not a complete list of Microsoft's infrastructure.

---

## 13. Troubleshooting

| Problem | Fix |
|---|---|
| Header says **LIMITED** / `ETW: off: needs admin` | Start the terminal with **Run as administrator** (section 3). |
| `--advanced needs scapy and Npcap` | `python -m pip install scapy dpkt` and install Npcap from <https://npcap.com/#download>. |
| `Packet capture failed` / falls back to BASIC | Npcap is missing or was installed without its service running. Reinstall Npcap and reboot. |
| `Capture warning: <adapter>` in the header | One adapter (often a VM adapter) can't be captured; the others still work. |
| `dpkt not available - … slower` | `python -m pip install dpkt` |
| Columns cut off or squashed | Make the window wider or maximise it. Narrow windows hide the least important columns. |
| Strange characters instead of lines | Use **Windows Terminal** instead of the old console. |
| `python` not found | Use `py netspy.py`, or reinstall Python with *"Add python.exe to PATH"*. |
| You start it from Python's `>>>` prompt | NetSpy asks for the mode (1 = BASIC, 2 = ADVANCED), then opens in a new Administrator window (accept the Windows prompt). Don't add `--advanced` to the file name; `open()` only takes a file name. |
| `Packets: N (dropped X)` in red | NetSpy fell behind during very heavy traffic; byte totals are too low. Use BASIC, or `--iface` for one adapter. |
| NetSpy was killed and ETW says it already exists | It is cleaned up automatically on the next start. |

---

## 14. Uninstall / clean up

NetSpy installs nothing and leaves no files behind. The only thing that can remain is the **firewall rules you created** with `a`/`b`.

List them (Administrator PowerShell):

```powershell
Get-NetFirewallRule -Name 'NetSpy *' | Format-Table Name, Enabled, Action
```

Remove them all:

```powershell
Get-NetFirewallRule -Name 'NetSpy *' | Remove-NetFirewallRule
```

Then delete the NetSpy folder. To remove the Python packages as well:

```powershell
python -m pip uninstall psutil rich scapy dpkt
```

Npcap can be removed under **Settings → Apps → Installed apps**.

---

## 15. License

MIT. See [LICENSE](LICENSE). Use it, change it and share it freely.
