import yara
from importlib.metadata import version
from packaging.version import Version


def test_current_yara_supports_negated_hex_bytes():
    assert Version(version("yara-python")) >= Version("4.5.4")
    compiled = yara.compile(
        source="rule modern_hex { strings: $a = { ~00 11 } condition: $a }"
    )
    assert compiled.match(data=b"\x42\x11")
    assert not compiled.match(data=b"\x00\x11")
