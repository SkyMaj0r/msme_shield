"""
MSME Shield Edge Agent — sensor.py v3.0
-----------------------------------------
Windows-native telemetry collector.

Collects local system telemetry and POSTs it to the MSME Shield backend
as an AgentPayload (POST /api/agent/submit).

WHAT THIS FILE DOES:
    1. Software inventory   — Windows: HKLM + WOW6432Node Uninstall registry keys
                              Mac: /Applications/*.app Info.plist (sys.platform guard)
    2. Port scanning        — psutil net_connections (LISTEN, port < 49152 only)
                              nmap (Mac/Linux only; skipped on Windows)
    3. OS info              — platform + systeminfo (Windows) for last patch date
    4. Running services     — psutil.win_service_iter() (Windows only; logged)
    5. Antivirus status     — WMI SecurityCenter2 (Windows only; logged)
    6. Startup entries      — Registry HKCU/HKLM Run keys (Windows only; logged)
    7. Chrome extensions    — %LOCALAPPDATA% manifest.json (Windows only; logged)
    8. Backend submission   — POST /api/agent/submit, 120s timeout

ENVIRONMENT (.env in edge_agent/ directory):
    BACKEND_URL    — default: http://localhost:8000
    ORG_NAME       — default: "Test MSME"
    IT_MATURITY    — default: "basic"  (basic|intermediate|advanced)
    AGENT_DOMAIN   — default: ""  (empty → backend skips SSL check)

STRICT CONSTRAINTS:
    - Zero FastAPI, SQLAlchemy, or Pydantic imports.
    - winreg, wmi, and other Windows-only imports are always function-local.
    - Every collection function fails gracefully — one failure never stops others.
    - Payload field names match AgentPayload schema exactly.
    - Ephemeral ports (>= 49152) are filtered before POST.
    - Extra Windows telemetry is logged only; it is NOT included in the POST
      payload because AgentPayload schema has no fields for it.
"""

from __future__ import annotations

import json
import logging
import os
import platform
import subprocess
import sys

# ---------------------------------------------------------------------------
# Logging — must be configured before any other module-level code
# ---------------------------------------------------------------------------
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sensor.log")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("msme_shield.sensor")

# ---------------------------------------------------------------------------
# Load .env from edge_agent/ directory
# ---------------------------------------------------------------------------
try:
    from dotenv import load_dotenv

    _env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    load_dotenv(dotenv_path=_env_path)
    log.info("Loaded environment from: %s", _env_path)
except ImportError:
    log.warning(
        "python-dotenv not installed — .env file will not be loaded. "
        "Install with: pip install python-dotenv"
    )

# ---------------------------------------------------------------------------
# Guarded imports — fail loudly, never silently hide missing stdlib deps
# ---------------------------------------------------------------------------
try:
    import requests
except ImportError:
    log.error("[FATAL] requests is not installed. Run: pip install requests")
    sys.exit(1)

try:
    import psutil
except ImportError:
    log.error("[FATAL] psutil is not installed. Run: pip install psutil")
    sys.exit(1)

# Ephemeral port threshold — ports >= this value are excluded from the payload
EPHEMERAL_THRESHOLD = 49152


# ===========================================================================
# SOFTWARE COLLECTION
# ===========================================================================

def collect_software_windows() -> list[dict]:
    """
    Reads both 64-bit and 32-bit (WOW6432Node) Windows registry Uninstall keys
    to enumerate installed software.

    Extracts DisplayName, DisplayVersion, and Publisher for each subkey.
    Entries with no DisplayName are skipped.
    Deduplicates by DisplayName (first occurrence wins).

    winreg is imported inside this function — it is Windows-only stdlib and
    would crash on Mac/Linux if imported at module level.

    Returns:
        List of {"name": str, "version": str} dicts matching SoftwareItem schema.
        Publisher is collected for logging but not included (schema has no field).
    """
    try:
        import winreg  # type: ignore[import]
    except ImportError:
        log.error("winreg not available — this function requires Windows.")
        return []

    UNINSTALL_KEYS = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    ]

    results: list[dict] = []
    seen_names: set[str] = set()

    for reg_path in UNINSTALL_KEYS:
        try:
            hive = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path)
        except OSError as exc:
            log.warning("Cannot open registry key %s: %s", reg_path, exc)
            continue

        subkey_count = 0
        try:
            subkey_count = winreg.QueryInfoKey(hive)[0]
        except OSError as exc:
            log.warning("Cannot query key info for %s: %s", reg_path, exc)
            winreg.CloseKey(hive)
            continue

        for i in range(subkey_count):
            try:
                subkey_name = winreg.EnumKey(hive, i)
                subkey = winreg.OpenKey(hive, subkey_name)
            except OSError:
                continue

            display_name = ""
            display_version = ""
            publisher = ""
            try:
                display_name, _ = winreg.QueryValueEx(subkey, "DisplayName")
            except (OSError, PermissionError):
                pass
            try:
                display_version, _ = winreg.QueryValueEx(subkey, "DisplayVersion")
            except (OSError, PermissionError):
                pass
            try:
                publisher, _ = winreg.QueryValueEx(subkey, "Publisher")
            except (OSError, PermissionError):
                pass

            try:
                winreg.CloseKey(subkey)
            except Exception:  # noqa: BLE001
                pass

            if not display_name:
                continue

            # Deduplicate by name
            if display_name in seen_names:
                continue
            seen_names.add(display_name)

            log.debug(
                "Software found: %s %s (Publisher: %s)",
                display_name,
                display_version or "unknown",
                publisher or "unknown",
            )
            results.append(
                {
                    "name": display_name.strip(),
                    "version": str(display_version).strip() if display_version else "",
                }
            )

        winreg.CloseKey(hive)

    log.info("Windows software scan complete: %d apps found.", len(results))
    return results


def collect_software_mac() -> list[dict]:
    """
    Scans /Applications/ for installed macOS applications.

    Only called on Darwin (sys.platform == 'darwin'). Reads each .app bundle's
    Contents/Info.plist via plistlib to get CFBundleName + CFBundleShortVersionString.
    Skips entries with an empty name or version.

    Returns:
        List of {"name": str, "version": str} dicts.
    """
    import plistlib  # stdlib — always available on Mac

    apps_dir = "/Applications"
    results: list[dict] = []

    try:
        entries = os.listdir(apps_dir)
    except PermissionError as exc:
        log.error("Cannot list %s: %s", apps_dir, exc)
        return results
    except Exception as exc:  # noqa: BLE001
        log.error("Unexpected error listing %s: %s", apps_dir, exc)
        return results

    for entry in entries:
        if not entry.endswith(".app"):
            continue

        plist_path = os.path.join(apps_dir, entry, "Contents", "Info.plist")
        try:
            with open(plist_path, "rb") as fh:
                plist = plistlib.load(fh)
        except FileNotFoundError:
            continue
        except PermissionError:
            continue
        except Exception as exc:  # noqa: BLE001
            log.warning("Could not read plist for %s: %s", entry, exc)
            continue

        name: str = plist.get("CFBundleName") or plist.get("CFBundleDisplayName", "")
        version: str = plist.get("CFBundleShortVersionString", "")

        if not name or not version:
            continue

        results.append({"name": name.strip(), "version": version.strip()})

    log.info("Mac software scan complete: %d apps found.", len(results))
    return results


def collect_software() -> list[dict]:
    """
    Platform dispatcher for software inventory collection.

    Routes to Windows registry reader on Windows, plistlib reader on Mac.
    Returns empty list with a warning for unsupported platforms.

    Returns:
        List of {"name": str, "version": str} dicts.
    """
    system = platform.system()

    if system == "Windows":
        return collect_software_windows()
    elif system == "Darwin":
        return collect_software_mac()
    else:
        log.warning(
            "Unsupported platform: %s. Software collection skipped. "
            "Threat-intel pipeline will run with an empty software list.",
            system,
        )
        return []


# ===========================================================================
# OS INFO — Windows systeminfo enrichment
# ===========================================================================

def collect_os_info_windows() -> dict:
    """
    Runs 'systeminfo' to extract OS name, OS version, and last hotfix date.

    Only called on Windows. Parses the 'OS Name', 'OS Version', and
    'Hotfix(s)' sections from systeminfo text output. The most recent
    hotfix install date is returned as last_patch_date.

    Falls back to platform module values if systeminfo fails.

    Returns:
        Dict with keys: os_name, os_version, last_patch_date (str or None).
        Logged to sensor.log — not included in AgentPayload (no schema field).
    """
    result = {
        "os_name": f"{platform.system()} {platform.release()}",
        "os_version": platform.version(),
        "last_patch_date": None,
    }

    try:
        proc = subprocess.run(
            ["systeminfo"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        output = proc.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        log.warning("systeminfo failed: %s — using platform module fallback.", exc)
        return result

    for line in output.splitlines():
        if line.startswith("OS Name:"):
            result["os_name"] = line.split(":", 1)[1].strip()
        elif line.startswith("OS Version:"):
            result["os_version"] = line.split(":", 1)[1].strip()

    # Parse hotfix section — lines like "               [01]: KB5034441  1/15/2024"
    in_hotfix_section = False
    hotfix_dates: list[str] = []
    for line in output.splitlines():
        if line.startswith("Hotfix(s):"):
            in_hotfix_section = True
            continue
        if in_hotfix_section:
            stripped = line.strip()
            if not stripped or (not stripped.startswith("[") and ":" not in stripped):
                break
            # Each hotfix line may end with a date like "1/15/2024"
            parts = stripped.split()
            if parts:
                last_part = parts[-1]
                # Simple date heuristic: contains "/" and has digits
                if "/" in last_part and any(c.isdigit() for c in last_part):
                    hotfix_dates.append(last_part)

    if hotfix_dates:
        # Keep the last (most recent) date in the output
        result["last_patch_date"] = hotfix_dates[-1]

    log.info(
        "Windows OS info — Name: %s | Version: %s | Last patch: %s",
        result["os_name"],
        result["os_version"],
        result["last_patch_date"] or "not detected",
    )
    return result


# ===========================================================================
# PORT COLLECTION
# ===========================================================================

def collect_ports_psutil() -> list[dict]:
    """
    Enumerates TCP ports in LISTEN state using psutil.

    Filters ephemeral ports (>= 49152) — these are transient OS-assigned
    ports that generate false positives in the exposure scoring model.

    Deduplicates by port number (first occurrence wins).

    Returns:
        List of {"port": int, "state": "open", "service": "unknown",
                 "risk_weight": 0.0} dicts. All ports < 49152.
    """
    results: list[dict] = []

    try:
        connections = psutil.net_connections(kind="inet")
    except psutil.AccessDenied as exc:
        log.error(
            "AccessDenied calling psutil.net_connections: %s. "
            "Try running the agent with elevated privileges (sudo on Mac).",
            exc,
        )
        return results
    except Exception as exc:  # noqa: BLE001
        log.error("Unexpected error during psutil port scan: %s", exc)
        return results

    seen_ports: set[int] = set()

    for conn in connections:
        try:
            if conn.status != psutil.CONN_LISTEN:
                continue
            laddr = conn.laddr
            if laddr is None:
                continue
            port: int = laddr.port

            # Filter ephemeral ports — only report well-known / registered ports
            if port >= EPHEMERAL_THRESHOLD:
                continue

            if port in seen_ports:
                continue
            seen_ports.add(port)

            results.append(
                {
                    "port": port,
                    "state": "open",
                    "service": "unknown",
                    "risk_weight": 0.0,
                }
            )
            log.debug("psutil: listening port %d discovered.", port)
        except (AttributeError, PermissionError) as exc:
            log.warning("Skipping connection entry: %s", exc)
            continue

    log.info("psutil port scan: %d listening ports found (< 49152).", len(results))
    return results


def collect_ports_nmap() -> list[dict]:
    """
    Runs a fast local nmap scan on 127.0.0.1. Mac/Linux only.

    WINDOWS: Skipped entirely. nmap binary and packet-capture driver
    (WinPcap/Npcap) trigger Windows Defender false positives on client
    machines. psutil provides equivalent coverage on Windows.

    Returns:
        List of port dicts on Mac/Linux, empty list on Windows.
    """
    if platform.system() == "Windows":
        log.info(
            "nmap scan skipped on Windows — psutil provides equivalent "
            "coverage without AV compatibility risk."
        )
        return []

    try:
        import nmap  # type: ignore[import]  # python-nmap optional
    except ImportError:
        log.warning(
            "python-nmap not installed — nmap layer skipped. "
            "Install with: pip install python-nmap  "
            "Also ensure nmap binary is present: brew install nmap"
        )
        return []

    results: list[dict] = []

    try:
        nm = nmap.PortScanner()
        nm.scan("127.0.0.1", arguments="-F")

        if "127.0.0.1" not in nm.all_hosts():
            log.info("nmap scan: no results for 127.0.0.1.")
            return results

        tcp_data = nm["127.0.0.1"].get("tcp", {})
        for port, port_info in tcp_data.items():
            port_int = int(port)
            if port_info.get("state") == "open" and port_int < EPHEMERAL_THRESHOLD:
                service = port_info.get("name", "unknown") or "unknown"
                results.append(
                    {
                        "port": port_int,
                        "state": "open",
                        "service": service,
                        "risk_weight": 0.0,
                    }
                )
                log.debug("nmap: open port %d (%s) discovered.", port_int, service)

    except nmap.PortScannerError as exc:
        log.warning("nmap binary not on PATH: %s. Install with: brew install nmap", exc)
        return []
    except Exception as exc:  # noqa: BLE001
        log.warning("nmap scan failed: %s", exc)
        return []

    log.info("nmap port scan: %d open ports found.", len(results))
    return results


def collect_all_ports() -> list[dict]:
    """
    Merges psutil and nmap port layers into a deduplicated list.

    On Windows: psutil only (nmap is skipped).
    On Mac/Linux: nmap > psutil (nmap wins on collision for richer service data).

    Returns:
        List of unique port dicts, all with port < 49152.
    """
    psutil_ports = collect_ports_psutil()
    nmap_ports = collect_ports_nmap()

    merged: dict[int, dict] = {}
    for p in psutil_ports:
        merged[p["port"]] = p
    for p in nmap_ports:
        merged[p["port"]] = p

    result = list(merged.values())

    log.info(
        "Port merge complete — psutil:%d nmap:%d merged unique:%d",
        len(psutil_ports),
        len(nmap_ports),
        len(result),
    )
    return result


# ===========================================================================
# WINDOWS-ONLY TELEMETRY (logged; not included in AgentPayload)
# ===========================================================================

def collect_services_windows() -> list[dict]:
    """
    Enumerates all running Windows services using psutil.win_service_iter().

    Collects: name, display_name, status for each service with status='running'.
    Logged to sensor.log; not included in AgentPayload (no schema field).

    Returns:
        List of {"name": str, "display_name": str, "status": str} dicts.
    """
    results: list[dict] = []

    if platform.system() != "Windows":
        return results

    try:
        for svc in psutil.win_service_iter():
            try:
                info = svc.as_dict()
                if info.get("status") == "running":
                    results.append(
                        {
                            "name": info.get("name", ""),
                            "display_name": info.get("display_name", ""),
                            "status": info.get("status", ""),
                        }
                    )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception:  # noqa: BLE001
                continue
    except AttributeError:
        log.warning(
            "psutil.win_service_iter() not available — "
            "requires psutil >= 3.0 on Windows."
        )
        return results
    except Exception as exc:  # noqa: BLE001
        log.warning("Service enumeration failed: %s", exc)
        return results

    log.info("Windows services: %d running services found.", len(results))
    return results


def collect_antivirus_windows() -> list[dict]:
    """
    Queries the WMI SecurityCenter2 namespace for installed antivirus products.

    Collects: displayName, productState for each AntiVirusProduct entry.
    Logged to sensor.log; not included in AgentPayload (no schema field).

    WMI may be unavailable on Server SKUs or stripped Windows installations
    — this function always returns gracefully in that case.

    Returns:
        List of {"display_name": str, "product_state": str} dicts.
    """
    results: list[dict] = []

    if platform.system() != "Windows":
        return results

    try:
        import wmi  # type: ignore[import]  # Windows only; pip install wmi

        c = wmi.WMI(namespace="root/SecurityCenter2")
        for av in c.AntiVirusProduct():
            results.append(
                {
                    "display_name": getattr(av, "displayName", ""),
                    "product_state": str(getattr(av, "productState", "")),
                }
            )
        log.info("Antivirus: %d product(s) detected via WMI.", len(results))
    except ImportError:
        log.warning(
            "wmi library not installed — antivirus check skipped. "
            "Install with: pip install wmi"
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("WMI antivirus query failed: %s", exc)

    return results


def collect_startup_windows() -> list[dict]:
    """
    Reads Windows autorun (startup) entries from HKCU and HKLM Run registry keys.

    Checks:
        HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
        HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run

    Collects: name, path for each entry.
    Logged to sensor.log; not included in AgentPayload (no schema field).

    Returns:
        List of {"name": str, "path": str} dicts.
    """
    results: list[dict] = []

    if platform.system() != "Windows":
        return results

    try:
        import winreg  # type: ignore[import]
    except ImportError:
        log.error("winreg not available — startup collection requires Windows.")
        return results

    RUN_KEYS = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    ]

    for hive_root, reg_path in RUN_KEYS:
        try:
            key = winreg.OpenKey(hive_root, reg_path)
        except OSError as exc:
            log.warning("Cannot open startup key %s: %s", reg_path, exc)
            continue

        try:
            count = winreg.QueryInfoKey(key)[1]  # number of values
            for i in range(count):
                try:
                    name, data, _ = winreg.EnumValue(key, i)
                    results.append({"name": str(name), "path": str(data)})
                except OSError:
                    continue
        except OSError as exc:
            log.warning("Cannot enumerate startup key %s: %s", reg_path, exc)
        finally:
            try:
                winreg.CloseKey(key)
            except Exception:  # noqa: BLE001
                pass

    log.info("Startup entries: %d autorun items found.", len(results))
    return results


def collect_chrome_extensions_windows() -> list[dict]:
    """
    Best-effort enumeration of installed Chrome extensions on Windows.

    Walks %LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Extensions,
    reading manifest.json from each extension subdirectory to get name
    and version.

    Entire function is wrapped in try/except — Chrome may not be installed.
    Logged to sensor.log; not included in AgentPayload (no schema field).

    Returns:
        List of {"name": str, "version": str} dicts.
    """
    results: list[dict] = []

    if platform.system() != "Windows":
        return results

    try:
        base = os.path.expandvars(
            r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Extensions"
        )

        if not os.path.isdir(base):
            log.info("Chrome extensions directory not found — Chrome may not be installed.")
            return results

        for ext_id in os.listdir(base):
            ext_dir = os.path.join(base, ext_id)
            if not os.path.isdir(ext_dir):
                continue
            # Each extension has one or more version subdirectories
            for version_dir in os.listdir(ext_dir):
                manifest_path = os.path.join(ext_dir, version_dir, "manifest.json")
                if not os.path.isfile(manifest_path):
                    continue
                try:
                    with open(manifest_path, encoding="utf-8", errors="replace") as fh:
                        manifest = json.load(fh)
                    name = manifest.get("name", "").strip()
                    version = manifest.get("version", "").strip()
                    if name and not name.startswith("__MSG_"):
                        results.append({"name": name, "version": version})
                except (json.JSONDecodeError, OSError):
                    continue
                break  # only read the first version subdirectory per extension

    except Exception as exc:  # noqa: BLE001
        log.warning("Chrome extension scan failed: %s", exc)

    log.info("Chrome extensions: %d found.", len(results))
    return results


# ===========================================================================
# HELPER FUNCTIONS
# ===========================================================================

def _safe_getfqdn() -> str:
    """
    Safely retrieves the fully qualified domain name of this machine.

    Used as fallback when AGENT_DOMAIN is not set in the environment.
    Returns "" on any failure. Never raises.
    """
    try:
        import socket
        return socket.getfqdn()
    except Exception:  # noqa: BLE001
        return ""


# ===========================================================================
# PAYLOAD CONSTRUCTION
# ===========================================================================

def build_payload(
    software_list: list[dict],
    open_ports: list[dict],
    os_name: str,
    os_version: str,
    domain_name: str,
    it_maturity: str,
) -> dict:
    """
    Constructs the exact dict matching the AgentPayload Pydantic schema
    in backend/schemas.py.

    Fields (must match AgentPayload exactly):
        organization_name  — ORG_NAME env var
        software_list      — list of {name, version} dicts
        open_ports         — list of {port, state, service, risk_weight} dicts
        os_name            — OS name string
        os_version         — OS version string
        domain_name        — AGENT_DOMAIN env var or FQDN fallback
        it_maturity        — IT_MATURITY env var

    Extra Windows telemetry (services, AV, startup, Chrome) is NOT included
    here — AgentPayload has no schema fields for it.

    Returns:
        Dict conforming to AgentPayload schema.
    """
    return {
        "organization_name": "SAV Industries Limited",
        "software_list": software_list,
        "open_ports": open_ports,
        "os_name": os_name,
        "os_version": os_version,
        "domain_name": domain_name,
        "it_maturity": it_maturity,
    }


# ===========================================================================
# BACKEND SUBMISSION
# ===========================================================================

def post_payload(payload: dict) -> dict | None:
    """
    POSTs the assembled AgentPayload to POST /api/agent/submit.

    Reads BACKEND_URL from the environment and appends the endpoint path.
    Uses a 120-second timeout to accommodate the NVD → EPSS → endoflife.date
    enrichment pipeline. With NVD API v2.0 rate limiting (0.2s between calls),
    34 apps × ~0.2s can approach 46s before network latency.

    Returns:
        Parsed response dict on HTTP 200, None on any failure.
    """
    backend_url = "http://192.168.1.10:8000"
    api_endpoint = f"{backend_url}/api/agent/submit"

    log.info("Posting payload to: %s", api_endpoint)
    log.info(
        "Payload summary — org: %r | software: %d | ports: %d | maturity: %r",
        payload.get("organization_name"),
        len(payload.get("software_list", [])),
        len(payload.get("open_ports", [])),
        payload.get("it_maturity"),
    )

    try:
        response = requests.post(
            api_endpoint,
            json=payload,
            timeout=120,
            headers={"Content-Type": "application/json"},
        )
        response.raise_for_status()

        result: dict = response.json()
        log.info(
            "Backend accepted payload. HTTP %d | scan_id=%s | tech_score=%s | "
            "risk_band_preview=%s | software_count=%s | cve_count=%s | "
            "any_eol=%s | ssl_days=%s | message=%r",
            response.status_code,
            result.get("scan_id"),
            result.get("tech_score"),
            result.get("risk_band_preview"),
            result.get("software_count"),
            result.get("cve_count"),
            result.get("any_eol"),
            result.get("ssl_days"),
            result.get("message"),
        )
        return result

    except requests.exceptions.ConnectionError:
        log.error(
            "Cannot connect to backend at %s. "
            "Ensure uvicorn is running: "
            "cd backend && uvicorn api:app --reload --port 8000",
            api_endpoint,
        )
    except requests.exceptions.Timeout:
        log.error(
            "Request timed out after 120s. "
            "Backend is processing a large software inventory — "
            "NVD API enrichment can exceed 60s for 34+ apps. "
            "Check backend logs for pipeline progress."
        )
    except requests.exceptions.HTTPError as exc:
        log.error(
            "Backend returned HTTP error: %s | Body: %s",
            exc,
            response.text[:500],
        )
    except Exception as exc:  # noqa: BLE001
        log.error("Unexpected error during payload submission: %s", exc)

    return None


# ===========================================================================
# ENTRY POINT
# ===========================================================================

def main() -> None:
    """
    MSME Shield scan pipeline — Step 1 (Agent side).

    Orchestrates all collection phases, assembles the AgentPayload-compliant
    dict, and submits to the backend. Extra Windows telemetry (services, AV,
    startup entries, Chrome extensions) is collected and logged but not sent
    in the POST payload because AgentPayload has no schema fields for them.

    The backend returns a scan_id and partial scores. The MSME owner then
    opens the dashboard to complete Step 2 (governance checklist).
    """
    log.info("=" * 60)
    log.info("MSME Shield Edge Agent v3.0 — Starting")
    log.info("Platform: %s", platform.system())
    log.info("=" * 60)

    # ── Phase 1: Software inventory ─────────────────────────────────────────
    log.info("Phase 1: Collecting software inventory...")
    software: list[dict] = collect_software()
    log.info("Phase 1 complete: %d software items found.", len(software))

    # ── Phase 2: Port scanning ───────────────────────────────────────────────
    log.info("Phase 2: Scanning open ports (psutil; nmap on Mac/Linux)...")
    ports: list[dict] = collect_all_ports()
    log.info("Phase 2 complete: %d unique port(s) found (all < 49152).", len(ports))

    # ── Phase 3: System information ──────────────────────────────────────────
    log.info("Phase 3: Reading system information...")
    if platform.system() == "Windows":
        os_info = collect_os_info_windows()
        os_name: str = os_info["os_name"]
        os_version: str = os_info["os_version"]
        log.info("Last patch date: %s", os_info["last_patch_date"] or "not detected")
    else:
        os_name = f"{platform.system()} {platform.release()}"
        os_version = platform.version()

    domain: str = os.getenv("AGENT_DOMAIN", "").strip() or _safe_getfqdn()
    it_maturity: str = os.getenv("IT_MATURITY", "basic")

    log.info("OS: %s | Version: %s", os_name, os_version)
    log.info("Domain: %s", domain or "(none — SSL check will be skipped)")
    log.info("IT Maturity: %s", it_maturity)
    log.info("Organisation: %s", os.getenv("ORG_NAME", "Test MSME"))

    # ── Phase 4: Windows-only extended telemetry (logged, not POSTed) ────────
    if platform.system() == "Windows":
        log.info("Phase 4: Collecting Windows-only extended telemetry (logged only)...")

        services = collect_services_windows()
        log.info(
            "Running services (%d): %s",
            len(services),
            [s["name"] for s in services[:10]],
        )

        av_products = collect_antivirus_windows()
        log.info(
            "Antivirus products (%d): %s",
            len(av_products),
            [a["display_name"] for a in av_products],
        )

        startup_entries = collect_startup_windows()
        log.info(
            "Startup entries (%d): %s",
            len(startup_entries),
            [e["name"] for e in startup_entries],
        )

        chrome_extensions = collect_chrome_extensions_windows()
        log.info(
            "Chrome extensions (%d): %s",
            len(chrome_extensions),
            [e["name"] for e in chrome_extensions[:10]],
        )
    else:
        log.info("Phase 4: Skipped (Windows-only extended telemetry).")

    # ── Phase 5: Build payload and submit ────────────────────────────────────
    log.info("Phase 5: Submitting to MSME Shield backend...")
    payload: dict = build_payload(
        software_list=software,
        open_ports=ports,
        os_name=os_name,
        os_version=os_version,
        domain_name=domain,
        it_maturity=it_maturity,
    )

    result: dict | None = post_payload(payload)

    # ── Result display ───────────────────────────────────────────────────────
    if result:
        log.info("=" * 60)
        log.info("SCAN SUBMITTED SUCCESSFULLY")
        log.info("  Scan ID:        %s", result.get("scan_id"))
        log.info("  Tech Score:     %s", result.get("tech_score"))
        log.info("  Risk Preview:   %s", result.get("risk_band_preview"))
        log.info("  Software Found: %s", result.get("software_count"))
        log.info("  CVEs Found:     %s", result.get("cve_count"))
        log.info("  EOL Software:   %s", result.get("any_eol"))
        log.info("  SSL Days Left:  %s", result.get("ssl_days"))
        log.info("-" * 60)
        log.info("  %s", result.get("message", ""))
        log.info("  Open your MSME Shield dashboard to complete")
        log.info("  the governance assessment.")
        log.info("=" * 60)
    else:
        log.error("=" * 60)
        log.error("SUBMISSION FAILED")
        log.error("  Check sensor.log for details.")
        log.error("  Ensure the MSME Shield backend is running:")
        log.error("  cd backend && uvicorn api:app --reload --port 8000")
        log.error("=" * 60)


if __name__ == "__main__":
    main()
