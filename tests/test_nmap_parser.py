from app.plugins.nmap_tool import parse_nmap_xml


def test_parse_nmap_xml_extracts_hosts_and_ports() -> None:
    xml = """
    <nmaprun>
      <host>
        <status state=\"up\" />
        <address addr=\"10.0.0.1\" />
        <ports>
          <port protocol=\"tcp\" portid=\"22\">
            <state state=\"open\" />
            <service name=\"ssh\" />
          </port>
        </ports>
      </host>
    </nmaprun>
    """

    result = parse_nmap_xml(xml)
    assert result["host_count"] == 1
    assert result["hosts"][0]["address"] == "10.0.0.1"
    assert result["hosts"][0]["ports"][0]["service"] == "ssh"
