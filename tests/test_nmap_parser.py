from app.plugins.nmap_tool import parse_nmap_xml


def test_parse_nmap_xml_extracts_hosts_and_ports() -> None:
    xml = """
    <nmaprun>
      <host>
        <status state=\"up\" />
        <address addr=\"10.0.0.1\" />
        <hostnames>
          <hostname name=\"gateway.local\" />
        </hostnames>
        <os>
          <osmatch name=\"Linux 5.x\" accuracy=\"98\" />
        </os>
        <ports>
          <port protocol=\"tcp\" portid=\"22\">
            <state state=\"open\" />
            <service name=\"ssh\" product=\"OpenSSH\" version=\"9.0\" extrainfo=\"protocol 2.0\" />
            <script id=\"ssh2-enum-algos\" output=\"rsa-sha2-256\" />
          </port>
        </ports>
        <hostscript>
          <script id=\"uptime\" output=\"System uptime: 1 day\" />
        </hostscript>
      </host>
    </nmaprun>
    """

    result = parse_nmap_xml(xml)
    assert result["host_count"] == 1
    assert result["hosts"][0]["address"] == "10.0.0.1"
    assert result["hosts"][0]["ports"][0]["service"] == "ssh"
    assert result["hosts"][0]["ports"][0]["product"] == "OpenSSH"
    assert result["hosts"][0]["ports"][0]["version"] == "9.0"
    assert result["hosts"][0]["ports"][0]["scripts"][0]["id"] == "ssh2-enum-algos"
    assert result["hosts"][0]["hostnames"] == ["gateway.local"]
    assert result["hosts"][0]["os_matches"][0]["name"] == "Linux 5.x"
    assert result["hosts"][0]["host_scripts"][0]["id"] == "uptime"
