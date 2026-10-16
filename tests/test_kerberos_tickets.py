import pytest

import orpheus_kerberos


def test_nt_hash_tgt_selection_is_independent_from_requested_tgs_type(monkeypatch):
    observed = {}

    def fake_tgt(client, password, domain, lmhash, nthash, aes_key, **kwargs):
        observed.update(password=password, lmhash=lmhash, nthash=nthash, aes_key=aes_key)
        return b"tgt", object(), object(), object()

    monkeypatch.setattr(orpheus_kerberos._upstream, "getKerberosTGT", fake_tgt)
    result = orpheus_kerberos.get_tgt_for_credentials(
        "user", "", "LAB.LOCAL", nthash="11" * 16, kdc_host="192.0.2.1"
    )

    assert result[0] == b"tgt"
    assert observed["nthash"] == bytes.fromhex("11" * 16)
    assert observed["aes_key"] == b""


@pytest.mark.parametrize("length", [2, 30, 34, 62, 66])
def test_aes_key_rejects_lengths_other_than_128_or_256_bits(length):
    with pytest.raises(ValueError, match="AES key"):
        orpheus_kerberos.get_tgt_for_credentials(
            "user", "", "LAB.LOCAL", aes_key="a" * length
        )


def test_kdc_option_string_maps_exactly_to_bit_indexes():
    assert orpheus_kerberos.kdc_option_values("0x80000001") == [0, 31]
    assert orpheus_kerberos.kdc_option_values("0x00000000") == []


@pytest.mark.parametrize(
    "hashes",
    [
        ":" + "11" * 16,
        "22" * 16 + ":" + "11" * 16,
    ],
)
def test_validate_key_material_accepts_nt_hash_pairs(hashes):
    assert orpheus_kerberos.validate_key_material(hashes, None) is None


@pytest.mark.parametrize(
    "hashes",
    [
        "11" * 16,
        ":",
        ":aa",
        ":" + "11" * 15,
        ":" + "11" * 17,
        "zz:" + "11" * 16,
        "11:22:33",
    ],
)
def test_validate_key_material_rejects_invalid_hash_pairs(hashes):
    with pytest.raises(ValueError):
        orpheus_kerberos.validate_key_material(hashes, None)


@pytest.mark.parametrize("length", [32, 64])
def test_validate_key_material_accepts_aes_keys(length):
    assert orpheus_kerberos.validate_key_material(None, "aa" * (length // 2)) is None
