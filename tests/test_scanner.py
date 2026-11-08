from modules.scanner import parse_nmap_xml

SAMPLE='''<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/><hostnames><hostname name="localhost" type="PTR"/></hostnames><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.0"/></port><port protocol="tcp" portid="80"><state state="closed"/><service name="http"/></port></ports></host></nmaprun>'''

def test_parses_open_ports_and_service_versions():
    hosts=parse_nmap_xml(SAMPLE)
    assert len(hosts)==1
    assert hosts[0]["addresses"]==["127.0.0.1"]
    assert len(hosts[0]["ports"])==1
    assert hosts[0]["ports"][0]["product"]=="OpenSSH"
    assert hosts[0]["ports"][0]["version"]=="9.0"

def test_empty_xml_hosts():
    assert parse_nmap_xml("<nmaprun></nmaprun>")==[]

def test_invalid_xml_raises():
    import pytest
    with pytest.raises(Exception): parse_nmap_xml("<not-closed>")
