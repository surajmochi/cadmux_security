from app.plugins.nmap_tool import NmapTool


def test_advanced_scan_profiles_are_available() -> None:
    expected_profiles = {
        "stealth_syn",
        "udp_top_ports",
        "os_service",
        "nse_discovery",
        "nse_auth",
        "nse_vuln",
        "aggressive_t5",
        "firewall_evasion_fragment",
        "decoy_scan",
        "full_tcp_output",
    }
    assert expected_profiles.issubset(set(NmapTool.SCAN_TYPES))
