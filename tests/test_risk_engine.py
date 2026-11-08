from modules.risk_engine import score_exposure

def test_risky_port_adds_explained_finding():
    result=score_exposure([{"ports":[{"port":23,"service":"telnet"}]}])
    assert result["score"]==20
    assert result["label"]=="Low"
    assert "Telnet" in result["why"][0]

def test_score_caps_at_100():
    hosts=[{"ports":[{"port":23},{"port":445},{"port":3389},{"port":27017}]}]
    fp={"http":{"security_headers":{x:False for x in ("a","b","c","d")},"https":False}}
    cves=[{"id":str(i),"severity":"CRITICAL"} for i in range(5)]
    assert score_exposure(hosts,fp,cves)["score"]==100

def test_header_and_https_findings_are_remediable():
    result=score_exposure([],{"http":{"security_headers":{"content-security-policy":False},"https":False}})
    assert result["score"]==12
    assert all(f["remediation"] for f in result["findings"])

def test_cve_match_flags_version_for_applicability_review():
    result=score_exposure([{"ports":[{"port":80,"product":"Apache httpd","version":"2.4.7"}]}],cves=[{"id":"CVE-2021-41773","severity":"HIGH","matched_product":"Apache httpd 2.4.7"}])
    assert any(f["type"]=="outdated_version" for f in result["findings"])
    assert "confirm" in next(f for f in result["findings"] if f["type"]=="outdated_version")["detail"]
