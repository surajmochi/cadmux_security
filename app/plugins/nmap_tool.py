from __future__ import annotations

import ipaddress
import shlex
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from app.core.models import ScanRequest, ScanResult
from app.core.plugin_manager import BaseTool


class NmapTool(BaseTool):
    name = "nmap"

    SCAN_TYPES: dict[str, list[str]] = {
        "quick": ["-T4", "-F"],
        "intense": ["-T4", "-A", "-v"],
        "ports": ["-sV"],
        "ping": ["-sn"],
        "stealth_syn": ["-sS", "-T4", "--open"],
        "udp_top_ports": ["-sU", "--top-ports", "100", "-T4"],
        "os_service": ["-O", "-sV", "--osscan-guess", "-T4"],
        "nse_discovery": ["-sV", "--script", "discovery", "-T4"],
        "nse_auth": ["-sV", "--script", "auth", "-T4"],
        "nse_vuln": ["-sV", "--script", "vuln", "-T4"],
        "aggressive_t5": ["-sS", "-sV", "-O", "-T5", "--open"],
        "firewall_evasion_fragment": ["-sS", "-Pn", "-f", "--mtu", "24", "-T3"],
        "decoy_scan": ["-sS", "-D", "RND:10", "-T4"],
        "full_tcp_output": ["-sS", "-p-", "-T4", "-oA", "nmap_full_tcp"],
    }

    def scan(self, request: ScanRequest) -> ScanResult:
        started_at = datetime.now(timezone.utc)
        target = request.target.strip()
        self._validate_target(target)

        args = self.SCAN_TYPES.get(request.scan_type, self.SCAN_TYPES["quick"])
        command = ["nmap", *args, *request.extra_args, "-oX", "-", target]

        result = ScanResult(
            tool=self.name,
            target=target,
            command=shlex.join(command),
            started_at=started_at,
        )

        try:
            proc = subprocess.run(
                command,
                text=True,
                capture_output=True,
                check=False,
                timeout=600,
            )
            if proc.returncode != 0:
                result.status = "error"
                result.error = proc.stderr.strip() or "nmap returned a non-zero exit code"
                return result

            parsed = parse_nmap_xml(proc.stdout)
            result.output = parsed
            return result
        except subprocess.TimeoutExpired:
            result.status = "error"
            result.error = "nmap scan timed out after 600 seconds"
            return result
        except FileNotFoundError:
            result.status = "error"
            result.error = "nmap binary was not found in PATH"
            return result
        except Exception as exc:  # defensive reliability catch
            result.status = "error"
            result.error = f"unexpected scan error: {exc}"
            return result
        finally:
            result.finished_at = datetime.now(timezone.utc)

    @staticmethod
    def _validate_target(target: str) -> None:
        if not target:
            raise ValueError("Target cannot be empty")

        # Accept IPs/CIDRs/hostnames while avoiding shell metacharacters.
        forbidden = set(";&|`$<>")
        if any(ch in forbidden for ch in target):
            raise ValueError("Target contains forbidden shell characters")

        try:
            ipaddress.ip_network(target, strict=False)
        except ValueError:
            # allow common hostname tokens
            if not all(ch.isalnum() or ch in ".-" for ch in target):
                raise ValueError("Target must be a valid IP, CIDR, or hostname")


def parse_nmap_xml(xml_output: str) -> dict:
    root = ET.fromstring(xml_output)
    hosts: list[dict] = []

    for host in root.findall("host"):
        addr = host.find("address")
        status_el = host.find("status")
        ports_el = host.find("ports")
        hostnames_el = host.find("hostnames")
        os_el = host.find("os")
        hostscript_el = host.find("hostscript")

        ports = []
        if ports_el is not None:
            for port in ports_el.findall("port"):
                state_el = port.find("state")
                svc_el = port.find("service")
                script_results = []
                for script_el in port.findall("script"):
                    script_results.append(
                        {
                            "id": script_el.get("id", "unknown"),
                            "output": script_el.get("output", ""),
                        }
                    )
                ports.append(
                    {
                        "port": int(port.get("portid", "0")),
                        "protocol": port.get("protocol", "unknown"),
                        "state": state_el.get("state", "unknown") if state_el is not None else "unknown",
                        "service": svc_el.get("name", "unknown") if svc_el is not None else "unknown",
                        "product": svc_el.get("product", "") if svc_el is not None else "",
                        "version": svc_el.get("version", "") if svc_el is not None else "",
                        "extra_info": svc_el.get("extrainfo", "") if svc_el is not None else "",
                        "scripts": script_results,
                    }
                )

        hostnames = []
        if hostnames_el is not None:
            for hostname in hostnames_el.findall("hostname"):
                hostnames.append(hostname.get("name", "unknown"))

        os_matches = []
        if os_el is not None:
            for osmatch in os_el.findall("osmatch"):
                os_matches.append(
                    {
                        "name": osmatch.get("name", "unknown"),
                        "accuracy": osmatch.get("accuracy", "0"),
                    }
                )

        host_scripts = []
        if hostscript_el is not None:
            for script_el in hostscript_el.findall("script"):
                host_scripts.append(
                    {
                        "id": script_el.get("id", "unknown"),
                        "output": script_el.get("output", ""),
                    }
                )

        hosts.append(
            {
                "address": addr.get("addr", "unknown") if addr is not None else "unknown",
                "status": status_el.get("state", "unknown") if status_el is not None else "unknown",
                "hostnames": hostnames,
                "os_matches": os_matches,
                "host_scripts": host_scripts,
                "ports": ports,
            }
        )

    return {"hosts": hosts, "host_count": len(hosts)}
