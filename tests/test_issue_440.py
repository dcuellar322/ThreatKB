from app.models.yara_rule import Yara_rule, Yara_rule_history


def test_import_preserves_condition_and_commits_history(authenticated):
    source = """rule SUSP_certificate_payload {
    meta:
      author = "Didier Stevens, Florian Roth"
    strings:
      $re1 = "-----BEGIN CERTIFICATE-----"
      $fp1 = "replace it with the PEM-encoded root certificate"
    condition:
      uint32(0) == 0x2D2D2D2D and $re1 at 0
      /* not M after the certificate header */
      and not uint8(29) == 0x4D and not uint8(28) == 0x4D
      and not 1 of ($fp*)
    }
    rule brace_literal { strings: $a = "{x}" condition: $a }
    """
    response = authenticated.post(
        "/ThreatKB/import",
        json={
            "import_text": source,
            "autocommit": True,
            "extract_ip": False,
            "extract_dns": False,
        },
    )
    assert response.status_code == 200
    result = response.json["artifacts"]
    assert result["errors"] == []
    assert len(result["committed"]) == 2
    assert Yara_rule.query.count() == 2
    assert Yara_rule_history.query.count() == 2
    assert "uint8(29)" in Yara_rule.query.first().condition
