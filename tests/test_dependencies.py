from importlib.metadata import version
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_runtime_dependency_ranges_are_bounded():
    requirements = {
        line.strip()
        for line in (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    }

    assert requirements == {
        "impacket>=0.13.1,<0.14",
        "pyasn1>=0.6,<0.7",
        "six>=1.17,<2",
        "pytest>=8,<9",
    }


def test_supported_runtime_imports():
    from impacket.examples.utils import ldap_login, parse_identity
    from impacket.krb5.asn1 import AS_REP, TGS_REP
    from impacket.krb5.kerberosv5 import KerberosError

    assert callable(ldap_login)
    assert callable(parse_identity)
    assert AS_REP is not None
    assert TGS_REP is not None
    assert issubclass(KerberosError, Exception)
    assert version("impacket").startswith("0.13.")
