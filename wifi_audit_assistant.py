#######################################################################
# Author: Lehlohonolo Adolf Matobakele  
# Email: lehlohonolo.matobakele@gov.ls
# Contacxt: 00266 62320704
#######################################################################
"""Step-by-step WiFi security audit assistant.

This is a defensive tool for networks you own or are authorized to review. It
does not automate WiFi hacking, deauthentication, handshakes, cracking,
credential capture, monitor mode, packet injection, or password dumping.
"""

from __future__ import annotations

import argparse
import csv
import getpass
import json
import math
import platform
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


console = Console()


@dataclass
class RiskFinding:
    """One defensive WiFi security observation."""

    severity: str
    category: str
    target: str
    issue: str
    evidence: str
    remediation: str


@dataclass
class WirelessInterface:
    """A local wireless adapter summary."""

    name: str
    state: str = "unknown"
    ssid: str = ""
    radio_type: str = ""
    authentication: str = ""
    cipher: str = ""
    channel: str = ""
    signal: str = ""


@dataclass
class VisibleNetwork:
    """A nearby SSID from normal operating-system WiFi scanning."""

    ssid: str
    authentication: str = "unknown"
    encryption: str = "unknown"
    signal: str = ""
    channel: str = ""
    bssids: list[str] = field(default_factory=list)
    radios: list[str] = field(default_factory=list)


@dataclass
class SavedProfile:
    """A saved WiFi profile without revealing stored passwords."""

    name: str
    authentication: str = "unknown"
    cipher: str = "unknown"
    connection_mode: str = ""
    cost: str = ""


@dataclass
class AuditReport:
    """Complete audit output."""

    generated_at: str
    host_platform: str
    interfaces: list[WirelessInterface] = field(default_factory=list)
    visible_networks: list[VisibleNetwork] = field(default_factory=list)
    saved_profiles: list[SavedProfile] = field(default_factory=list)
    findings: list[RiskFinding] = field(default_factory=list)


SEVERITY_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

LEARNING_MODULES = [
    (
        "Authorization and Scope",
        "Only test WiFi networks you own or are explicitly authorized to review. "
        "Define the SSIDs, devices, time window, and allowed checks before you begin.",
    ),
    (
        "Encryption Basics",
        "Open and WEP networks are unsafe. WPA2-AES is still common, while WPA3 "
        "is preferred when all devices support it. TKIP should be disabled.",
    ),
    (
        "Passphrase Strength",
        "A long unique passphrase resists guessing better than a short complex one. "
        "Use a password manager and avoid reused or personal phrases.",
    ),
    (
        "WPS and Router Admin",
        "Disable WPS where possible, change default router admin passwords, update "
        "firmware, and restrict router management to trusted devices.",
    ),
    (
        "Rogue or Evil-Twin Awareness",
        "Duplicate SSIDs and unexpected open networks should be investigated. "
        "Confirm access points by inventory and location rather than by SSID alone.",
    ),
    (
        "What This Assistant Avoids",
        "It does not automate deauthentication, handshake capture, packet injection, "
        "credential capture, monitor mode, or password cracking.",
    ),
]


def clean(value: str, limit: int = 220) -> str:
    """Normalize command output for tables and reports."""

    value = re.sub(r"\s+", " ", value.replace("\r", " ").replace("\n", " ")).strip()
    return value[:limit]


def run_command(command: list[str], timeout: int = 30) -> str:
    """Run an OS command and return combined output without raising."""

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return str(exc)
    return "\n".join(part for part in [result.stdout, result.stderr] if part).strip()


def require_authorization(confirm_authorized: bool) -> None:
    """Require the user to acknowledge authorized defensive use."""

    if confirm_authorized:
        return

    console.print(
        Panel.fit(
            "Use this assistant only on WiFi networks and devices you own or "
            "have explicit permission to review.\n\n"
            "This tool performs safe OS-level inventory and configuration "
            "checks. It does not crack passwords, capture handshakes, inject "
            "packets, or disconnect clients.",
            title="Authorization Required",
            border_style="yellow",
        )
    )
    answer = console.input("Type YES to confirm authorized defensive use: ").strip()
    if answer != "YES":
        raise SystemExit("Authorization was not confirmed.")


def ask_yes_no(prompt: str, assume_yes: bool = False, default: bool = True) -> bool:
    """Ask a yes/no question for wizard mode."""

    if assume_yes:
        return True
    suffix = "[Y/n]" if default else "[y/N]"
    answer = console.input(f"{prompt} {suffix} ").strip().lower()
    if not answer:
        return default
    return answer in {"y", "yes"}


def section(title: str, message: str) -> None:
    """Print a wizard step panel."""

    console.print(Panel.fit(message, title=title, border_style="cyan"))


def parse_windows_key_value(line: str) -> tuple[str, str] | None:
    """Parse `key : value` lines from netsh output."""

    if ":" not in line:
        return None
    key, value = line.split(":", 1)
    return key.strip(), value.strip()


def windows_interfaces() -> list[WirelessInterface]:
    """Return wireless interface details from netsh."""

    output = run_command(["netsh", "wlan", "show", "interfaces"])
    interfaces: list[WirelessInterface] = []
    current: dict[str, str] = {}

    for raw_line in output.splitlines():
        parsed = parse_windows_key_value(raw_line)
        if not parsed:
            continue
        key, value = parsed
        normalized = key.lower()
        if normalized == "name" and current:
            if current.get("name"):
                interfaces.append(interface_from_windows_map(current))
            current = {}
        current[normalized] = value

    if current.get("name"):
        interfaces.append(interface_from_windows_map(current))
    return interfaces


def interface_from_windows_map(values: dict[str, str]) -> WirelessInterface:
    """Convert parsed netsh interface output to a dataclass."""

    return WirelessInterface(
        name=values.get("name", "unknown"),
        state=values.get("state", "unknown"),
        ssid=values.get("ssid", ""),
        radio_type=values.get("radio type", ""),
        authentication=values.get("authentication", ""),
        cipher=values.get("cipher", ""),
        channel=values.get("channel", ""),
        signal=values.get("signal", ""),
    )


def windows_visible_networks() -> list[VisibleNetwork]:
    """Return visible WiFi networks from netsh without packet capture."""

    output = run_command(["netsh", "wlan", "show", "networks", "mode=bssid"])
    networks: list[VisibleNetwork] = []
    current: VisibleNetwork | None = None

    for raw_line in output.splitlines():
        line = raw_line.strip()
        ssid_match = re.match(r"SSID\s+\d+\s*:\s*(.*)", line, flags=re.IGNORECASE)
        if ssid_match:
            if current:
                networks.append(current)
            ssid = ssid_match.group(1).strip() or "<hidden>"
            current = VisibleNetwork(ssid=ssid)
            continue

        if not current:
            continue

        parsed = parse_windows_key_value(line)
        if not parsed:
            continue
        key, value = parsed
        lowered = key.lower()
        if lowered == "authentication":
            current.authentication = value
        elif lowered == "encryption":
            current.encryption = value
        elif lowered.startswith("bssid"):
            current.bssids.append(value)
        elif lowered == "signal" and not current.signal:
            current.signal = value
        elif lowered == "radio type":
            if value not in current.radios:
                current.radios.append(value)
        elif lowered == "channel" and not current.channel:
            current.channel = value

    if current:
        networks.append(current)
    return networks


def windows_saved_profiles() -> list[SavedProfile]:
    """Return saved WiFi profiles without reading stored keys."""

    output = run_command(["netsh", "wlan", "show", "profiles"])
    profile_names: list[str] = []
    for line in output.splitlines():
        parsed = parse_windows_key_value(line)
        if parsed and parsed[0].strip().lower() == "all user profile" and parsed[1].strip():
            profile_names.append(parsed[1])

    profiles: list[SavedProfile] = []
    for name in dict.fromkeys(profile_names):
        details = run_command(["netsh", "wlan", "show", "profile", f"name={name}"])
        values: dict[str, str] = {}
        for line in details.splitlines():
            parsed = parse_windows_key_value(line.strip())
            if parsed:
                values[parsed[0].lower()] = parsed[1]
        profiles.append(
            SavedProfile(
                name=name,
                authentication=values.get("authentication", "unknown"),
                cipher=values.get("cipher", "unknown"),
                connection_mode=values.get("connection mode", ""),
                cost=values.get("cost", ""),
            )
        )
    return profiles


def linux_visible_networks() -> list[VisibleNetwork]:
    """Return nearby WiFi networks using nmcli when available."""

    if not shutil.which("nmcli"):
        return []
    output = run_command(
        ["nmcli", "-t", "-f", "SSID,SECURITY,SIGNAL,CHAN,BSSID", "dev", "wifi", "list", "--rescan", "yes"],
        timeout=45,
    )
    networks: dict[str, VisibleNetwork] = {}
    for line in output.splitlines():
        parts = line.split(":")
        if len(parts) < 5:
            continue
        ssid, security, signal, channel, bssid = parts[0], parts[1], parts[2], parts[3], ":".join(parts[4:])
        name = ssid or "<hidden>"
        network = networks.setdefault(
            name,
            VisibleNetwork(ssid=name, authentication=security or "Open", encryption=security or "Open"),
        )
        network.signal = network.signal or f"{signal}%"
        network.channel = network.channel or channel
        if bssid and bssid not in network.bssids:
            network.bssids.append(bssid)
    return list(networks.values())


def collect_interfaces() -> list[WirelessInterface]:
    """Collect wireless adapter details for the current platform."""

    if platform.system().lower() == "windows":
        return windows_interfaces()
    return []


def collect_visible_networks() -> list[VisibleNetwork]:
    """Collect visible WiFi networks with safe OS-level commands."""

    if platform.system().lower() == "windows":
        return windows_visible_networks()
    return linux_visible_networks()


def collect_saved_profiles() -> list[SavedProfile]:
    """Collect saved WiFi profile security settings without secrets."""

    if platform.system().lower() == "windows":
        return windows_saved_profiles()
    return []


def add_finding(
    findings: list[RiskFinding],
    severity: str,
    category: str,
    target: str,
    issue: str,
    evidence: str,
    remediation: str,
) -> None:
    """Append a finding."""

    findings.append(
        RiskFinding(
            severity=severity,
            category=category,
            target=target,
            issue=issue,
            evidence=clean(evidence),
            remediation=remediation,
        )
    )


def analyze_visible_networks(networks: list[VisibleNetwork]) -> list[RiskFinding]:
    """Create risk findings for visible WiFi networks."""

    findings: list[RiskFinding] = []
    seen: dict[str, int] = {}

    for network in networks:
        auth = f"{network.authentication} {network.encryption}".lower()
        seen[network.ssid] = seen.get(network.ssid, 0) + 1

        if network.ssid == "<hidden>":
            add_finding(
                findings,
                "INFO",
                "SSID",
                network.ssid,
                "Hidden SSID observed. Hidden names are not a security control.",
                "SSID is blank in scan output.",
                "Use strong encryption instead of relying on hidden SSIDs.",
            )

        if "open" in auth or "none" in auth:
            add_finding(
                findings,
                "HIGH",
                "Encryption",
                network.ssid,
                "Network appears open or unauthenticated.",
                f"Authentication={network.authentication}, Encryption={network.encryption}",
                "Use WPA3-Personal/Enterprise or WPA2-AES with a strong passphrase.",
            )
        elif "wep" in auth:
            add_finding(
                findings,
                "HIGH",
                "Encryption",
                network.ssid,
                "WEP is obsolete and can be broken quickly.",
                f"Authentication={network.authentication}, Encryption={network.encryption}",
                "Replace WEP with WPA3 or WPA2-AES immediately.",
            )
        elif "tkip" in auth:
            add_finding(
                findings,
                "MEDIUM",
                "Encryption",
                network.ssid,
                "TKIP is legacy encryption and should be disabled.",
                f"Authentication={network.authentication}, Encryption={network.encryption}",
                "Use AES/CCMP only.",
            )
        elif "wpa3" in auth:
            add_finding(
                findings,
                "INFO",
                "Encryption",
                network.ssid,
                "WPA3 is advertised.",
                f"Authentication={network.authentication}, Encryption={network.encryption}",
                "Keep firmware updated and use a strong passphrase or enterprise authentication.",
            )
        elif "wpa2" in auth:
            add_finding(
                findings,
                "LOW",
                "Encryption",
                network.ssid,
                "WPA2 is advertised. Confirm AES/CCMP and a strong passphrase.",
                f"Authentication={network.authentication}, Encryption={network.encryption}",
                "Prefer WPA3 where supported; otherwise use WPA2-AES and a long unique passphrase.",
            )

        if len(network.bssids) > 3:
            add_finding(
                findings,
                "INFO",
                "Coverage",
                network.ssid,
                "Multiple access points advertise this SSID.",
                f"BSSID count={len(network.bssids)}",
                "Confirm all access points are managed, patched, and using consistent security.",
            )

    for ssid, count in seen.items():
        if ssid != "<hidden>" and count > 1:
            add_finding(
                findings,
                "INFO",
                "SSID",
                ssid,
                "Duplicate SSID entries were observed.",
                f"SSID appeared {count} times.",
                "Confirm duplicates are expected access points and not an unauthorized evil-twin SSID.",
            )

    return findings


def analyze_saved_profiles(profiles: list[SavedProfile]) -> list[RiskFinding]:
    """Create risk findings for saved profiles without reading passwords."""

    findings: list[RiskFinding] = []
    for profile in profiles:
        auth = f"{profile.authentication} {profile.cipher}".lower()
        if "open" in auth or "none" in auth:
            add_finding(
                findings,
                "MEDIUM",
                "Saved Profile",
                profile.name,
                "Saved profile appears to use open authentication.",
                f"Authentication={profile.authentication}, Cipher={profile.cipher}",
                "Remove saved open networks unless they are required and trusted.",
            )
        if "wep" in auth:
            add_finding(
                findings,
                "HIGH",
                "Saved Profile",
                profile.name,
                "Saved profile uses WEP.",
                f"Authentication={profile.authentication}, Cipher={profile.cipher}",
                "Remove the profile and migrate the network to WPA3 or WPA2-AES.",
            )
        if "tkip" in auth:
            add_finding(
                findings,
                "MEDIUM",
                "Saved Profile",
                profile.name,
                "Saved profile uses TKIP.",
                f"Authentication={profile.authentication}, Cipher={profile.cipher}",
                "Update the network and profile to AES/CCMP.",
            )
        if profile.connection_mode.lower() == "connect automatically" and ("open" in auth or "none" in auth):
            add_finding(
                findings,
                "HIGH",
                "Auto Join",
                profile.name,
                "Device may auto-join an open network.",
                f"Connection mode={profile.connection_mode}",
                "Disable auto-join or remove the saved profile.",
            )
    return findings


def render_interfaces(interfaces: list[WirelessInterface]) -> None:
    """Print interface table."""

    table = Table(title="Wireless Interfaces", show_lines=True)
    table.add_column("Name")
    table.add_column("State")
    table.add_column("SSID")
    table.add_column("Auth")
    table.add_column("Cipher")
    table.add_column("Signal")
    if not interfaces:
        table.add_row("-", "-", "-", "-", "-", "-")
    for item in interfaces:
        table.add_row(item.name, item.state, item.ssid or "-", item.authentication or "-", item.cipher or "-", item.signal or "-")
    console.print(table)


def render_networks(networks: list[VisibleNetwork]) -> None:
    """Print visible network table."""

    table = Table(title="Visible WiFi Networks", show_lines=True)
    table.add_column("SSID", overflow="fold")
    table.add_column("Auth")
    table.add_column("Encryption")
    table.add_column("Signal")
    table.add_column("Channel")
    table.add_column("BSSIDs")
    if not networks:
        table.add_row("-", "-", "-", "-", "-", "-")
    for item in networks:
        table.add_row(
            item.ssid,
            item.authentication,
            item.encryption,
            item.signal or "-",
            item.channel or "-",
            str(len(item.bssids)),
        )
    console.print(table)


def render_profiles(profiles: list[SavedProfile]) -> None:
    """Print saved profile table."""

    table = Table(title="Saved WiFi Profiles", show_lines=True)
    table.add_column("Name", overflow="fold")
    table.add_column("Auth")
    table.add_column("Cipher")
    table.add_column("Connection")
    if not profiles:
        table.add_row("-", "-", "-", "-")
    for item in profiles:
        table.add_row(item.name, item.authentication, item.cipher, item.connection_mode or "-")
    console.print(table)


def render_findings(findings: list[RiskFinding]) -> None:
    """Print findings sorted by severity."""

    table = Table(title="WiFi Security Findings", show_lines=True)
    table.add_column("Severity")
    table.add_column("Category")
    table.add_column("Target", overflow="fold")
    table.add_column("Issue", overflow="fold")
    table.add_column("Remediation", overflow="fold")

    if not findings:
        table.add_row("INFO", "-", "-", "No risky settings found in collected data.", "Keep firmware and passwords updated.")
    for item in sorted(findings, key=lambda row: SEVERITY_ORDER.get(row.severity, 0), reverse=True):
        style = "red" if item.severity in {"HIGH", "CRITICAL"} else "yellow" if item.severity == "MEDIUM" else "green" if item.severity == "LOW" else "cyan"
        table.add_row(
            Text(item.severity, style=style),
            item.category,
            item.target,
            item.issue,
            item.remediation,
        )
    console.print(table)


def build_report(
    interfaces: list[WirelessInterface],
    networks: list[VisibleNetwork],
    profiles: list[SavedProfile],
    findings: list[RiskFinding],
) -> AuditReport:
    """Create report dataclass."""

    return AuditReport(
        generated_at=datetime.now(timezone.utc).isoformat(),
        host_platform=f"{platform.system()} {platform.release()}",
        interfaces=interfaces,
        visible_networks=networks,
        saved_profiles=profiles,
        findings=findings,
    )


def write_json_report(path: Path, report: AuditReport) -> None:
    """Write JSON report."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(asdict(report), indent=2), encoding="utf-8")


def write_csv_findings(path: Path, findings: list[RiskFinding]) -> None:
    """Write findings as CSV."""

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["severity", "category", "target", "issue", "evidence", "remediation"],
        )
        writer.writeheader()
        for item in findings:
            writer.writerow(asdict(item))


def render_learning_modules() -> None:
    """Print high-level defensive WiFi learning modules."""

    table = Table(title="Safe WiFi Security Learning Path", show_lines=True)
    table.add_column("#")
    table.add_column("Topic", overflow="fold")
    table.add_column("What To Learn", overflow="fold")

    for index, (topic, detail) in enumerate(LEARNING_MODULES, start=1):
        table.add_row(str(index), topic, detail)
    console.print(table)


def run_learn(args: argparse.Namespace) -> int:
    """Run safe learning mode."""

    require_authorization(args.confirm_authorized)
    render_learning_modules()
    console.print(
        "[dim]This learning mode explains defensive concepts only. It does not "
        "include offensive WiFi procedures or attack automation.[/dim]"
    )
    return 0


def passphrase_pool_size(passphrase: str) -> int:
    """Estimate character pool size for a passphrase."""

    pool = 0
    if re.search(r"[a-z]", passphrase):
        pool += 26
    if re.search(r"[A-Z]", passphrase):
        pool += 26
    if re.search(r"\d", passphrase):
        pool += 10
    if re.search(r"[^A-Za-z0-9]", passphrase):
        pool += 33
    return max(pool, 1)


def passphrase_warnings(passphrase: str) -> list[str]:
    """Return simple defensive warnings for a sample passphrase."""

    warnings: list[str] = []
    lowered = passphrase.lower()
    common_fragments = ["password", "admin", "qwerty", "welcome", "letmein", "internet", "wifi"]

    if len(passphrase) < 12:
        warnings.append("Use at least 12 characters; 16 or more is better for WiFi.")
    if len(passphrase) < 16:
        warnings.append("Consider a longer phrase made of several unrelated words.")
    if any(fragment in lowered for fragment in common_fragments):
        warnings.append("Avoid common words such as password, admin, qwerty, welcome, or wifi.")
    if re.search(r"(.)\1\1", passphrase):
        warnings.append("Avoid repeated characters or obvious patterns.")
    if re.search(r"(1234|abcd|qwer|202[0-9])", lowered):
        warnings.append("Avoid sequences, years, and keyboard patterns.")
    return warnings


def passphrase_rating(entropy_bits: float) -> tuple[str, str]:
    """Return a readable rating from estimated entropy."""

    if entropy_bits >= 90:
        return "STRONG", "green"
    if entropy_bits >= 70:
        return "GOOD", "cyan"
    if entropy_bits >= 50:
        return "FAIR", "yellow"
    return "WEAK", "red"


def run_passphrase_check(args: argparse.Namespace) -> int:
    """Estimate defensive strength of a sample WiFi passphrase."""

    require_authorization(args.confirm_authorized)
    console.print(
        Panel.fit(
            "For privacy, test a similar pattern instead of typing your real "
            "production WiFi password. The value is not saved to reports.",
            title="Passphrase Safety",
            border_style="yellow",
        )
    )

    passphrase = args.sample_passphrase
    if passphrase is None:
        passphrase = getpass.getpass("Sample passphrase to evaluate: ")

    pool = passphrase_pool_size(passphrase)
    entropy_bits = len(passphrase) * math.log2(pool)
    rating, style = passphrase_rating(entropy_bits)
    warnings = passphrase_warnings(passphrase)

    table = Table(title="WiFi Passphrase Strength Estimate", show_lines=True)
    table.add_column("Metric")
    table.add_column("Value")
    table.add_row("Length", str(len(passphrase)))
    table.add_row("Estimated character pool", str(pool))
    table.add_row("Estimated entropy", f"{entropy_bits:.1f} bits")
    table.add_row("Rating", Text(rating, style=style))
    console.print(table)

    if warnings:
        console.print("[yellow]Recommendations:[/yellow]")
        for warning in warnings:
            console.print(f"- {warning}")
    else:
        console.print("[green]No obvious passphrase pattern issues found.[/green]")
    return 0


def simulated_lab_data() -> tuple[list[WirelessInterface], list[VisibleNetwork], list[SavedProfile], list[RiskFinding]]:
    """Return fake data for a safe educational WiFi lab."""

    interfaces = [
        WirelessInterface(
            name="Wi-Fi",
            state="connected",
            ssid="HomeLab",
            authentication="WPA2-Personal",
            cipher="CCMP",
            channel="6",
            signal="92%",
        )
    ]
    networks = [
        VisibleNetwork(
            ssid="HomeLab",
            authentication="WPA2-Personal",
            encryption="CCMP",
            signal="92%",
            channel="6",
            bssids=["00:11:22:33:44:55"],
        ),
        VisibleNetwork(
            ssid="HomeLab-Guest",
            authentication="Open",
            encryption="None",
            signal="78%",
            channel="11",
            bssids=["00:11:22:33:44:66"],
        ),
        VisibleNetwork(
            ssid="<hidden>",
            authentication="WPA2-Personal",
            encryption="CCMP",
            signal="64%",
            channel="1",
            bssids=["00:11:22:33:44:77"],
        ),
    ]
    profiles = [
        SavedProfile(
            name="HomeLab-Guest",
            authentication="Open",
            cipher="None",
            connection_mode="Connect automatically",
        ),
        SavedProfile(
            name="HomeLab",
            authentication="WPA2-Personal",
            cipher="CCMP",
            connection_mode="Connect automatically",
        ),
    ]
    findings = analyze_visible_networks(networks)
    findings.extend(analyze_saved_profiles(profiles))
    return interfaces, networks, profiles, findings


def run_lab(args: argparse.Namespace) -> int:
    """Run a simulated educational lab with fake WiFi data."""

    require_authorization(args.confirm_authorized)
    assume_yes = bool(args.yes)
    section(
        "Simulated Lab",
        "This lab uses fake WiFi data. It teaches safe audit decisions without "
        "touching a real network or performing any attack activity.",
    )

    interfaces, networks, profiles, findings = simulated_lab_data()
    if ask_yes_no("Lab step 1: review fake wireless interface state?", assume_yes=assume_yes):
        render_interfaces(interfaces)
    if ask_yes_no("Lab step 2: review fake visible networks?", assume_yes=assume_yes):
        render_networks(networks)
    if ask_yes_no("Lab step 3: review fake saved profiles?", assume_yes=assume_yes):
        render_profiles(profiles)
    if ask_yes_no("Lab step 4: identify defensive findings?", assume_yes=assume_yes):
        render_findings(findings)

    console.print(
        Panel.fit(
            "Expected priorities:\n"
            "1. Remove or secure the open guest network.\n"
            "2. Disable auto-join for open profiles.\n"
            "3. Treat hidden SSIDs as privacy-only, not security.\n"
            "4. Keep WPA2-AES or move to WPA3 where supported.",
            title="Lab Answer Key",
            border_style="green",
        )
    )
    return 0


def run_audit(args: argparse.Namespace, wizard: bool = False) -> int:
    """Run a guided or non-interactive audit."""

    require_authorization(args.confirm_authorized)
    assume_yes = bool(args.yes or not wizard)

    interfaces: list[WirelessInterface] = []
    networks: list[VisibleNetwork] = []
    profiles: list[SavedProfile] = []
    findings: list[RiskFinding] = []

    section(
        "Step 1 - Environment",
        f"Platform: {platform.system()} {platform.release()}\n"
        "The assistant will use safe operating-system WiFi inventory commands.",
    )

    if ask_yes_no("Step 2: show wireless interfaces?", assume_yes=assume_yes):
        interfaces = collect_interfaces()
        render_interfaces(interfaces)

    if ask_yes_no("Step 3: scan visible WiFi networks?", assume_yes=assume_yes):
        networks = collect_visible_networks()
        findings.extend(analyze_visible_networks(networks))
        render_networks(networks)

    if args.include_profiles or ask_yes_no(
        "Step 4: review saved WiFi profile security settings without showing passwords?",
        assume_yes=assume_yes,
        default=False,
    ):
        profiles = collect_saved_profiles()
        findings.extend(analyze_saved_profiles(profiles))
        render_profiles(profiles)

    render_findings(findings)

    report = build_report(interfaces, networks, profiles, findings)
    if args.json_out:
        write_json_report(args.json_out.resolve(), report)
        console.print(f"[green]JSON report saved to {args.json_out.resolve()}[/green]")
    if args.csv_out:
        write_csv_findings(args.csv_out.resolve(), findings)
        console.print(f"[green]CSV findings saved to {args.csv_out.resolve()}[/green]")

    if wizard and not args.json_out and ask_yes_no("Step 5: save a JSON report now?", default=True):
        output = Path("reports") / f"wifi_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        write_json_report(output.resolve(), report)
        console.print(f"[green]JSON report saved to {output.resolve()}[/green]")

    console.print(
        "[dim]Reminder: this assistant does not perform WiFi attacks or password recovery. "
        "Use findings for hardening and authorized remediation only.[/dim]"
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build CLI parser."""

    parser = argparse.ArgumentParser(
        description="Step-by-step defensive WiFi security audit assistant."
    )
    subparsers = parser.add_subparsers(dest="command")

    def add_common(command: argparse.ArgumentParser) -> None:
        command.add_argument("--confirm-authorized", action="store_true", help="Confirm authorized defensive use.")
        command.add_argument("--include-profiles", action="store_true", help="Review saved profile security settings without showing passwords.")
        command.add_argument("--json-out", type=Path, help="Save full JSON report.")
        command.add_argument("--csv-out", type=Path, help="Save findings CSV report.")
        command.add_argument("--yes", action="store_true", help="Assume yes for wizard prompts.")

    wizard = subparsers.add_parser("wizard", help="Run the interactive step-by-step audit.")
    add_common(wizard)
    wizard.set_defaults(func=lambda args: run_audit(args, wizard=True))

    scan = subparsers.add_parser("scan", help="Run all safe audit steps non-interactively.")
    add_common(scan)
    scan.set_defaults(func=lambda args: run_audit(args, wizard=False))

    learn = subparsers.add_parser("learn", help="Show a safe defensive WiFi learning path.")
    learn.add_argument("--confirm-authorized", action="store_true", help="Confirm authorized defensive use.")
    learn.set_defaults(func=run_learn)

    lab = subparsers.add_parser("lab", help="Run a simulated step-by-step WiFi audit lab.")
    lab.add_argument("--confirm-authorized", action="store_true", help="Confirm authorized defensive use.")
    lab.add_argument("--yes", action="store_true", help="Assume yes for lab prompts.")
    lab.set_defaults(func=run_lab)

    passphrase = subparsers.add_parser("passphrase-check", help="Estimate the strength of a sample WiFi passphrase.")
    passphrase.add_argument("--confirm-authorized", action="store_true", help="Confirm authorized defensive use.")
    passphrase.add_argument("--sample-passphrase", help="Sample passphrase to evaluate. Prefer a similar pattern, not your real password.")
    passphrase.set_defaults(func=run_passphrase_check)

    interfaces = subparsers.add_parser("interfaces", help="Show wireless interfaces.")
    interfaces.add_argument("--confirm-authorized", action="store_true", help="Confirm authorized defensive use.")
    interfaces.set_defaults(func=lambda args: (require_authorization(args.confirm_authorized), render_interfaces(collect_interfaces()), 0)[2])

    return parser


def main() -> int:
    """CLI entry point."""

    parser = build_parser()
    args = parser.parse_args()
    if not args.command:
        args = parser.parse_args(["wizard"])
    return int(args.func(args))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]Audit cancelled by user.[/yellow]")
        raise SystemExit(130)
