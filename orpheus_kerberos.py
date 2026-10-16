"""Small Kerberos extensions required by Orpheus."""

# Contains Kerberos routines adapted from Impacket, by Alberto Solino (@agsolino).
# Upstream portions: Copyright 2019 SecureAuth Corporation. All rights reserved.
# Current upstream: Copyright Fortra, LLC and its affiliated companies.
# See LICENSE for the preserved Impacket license texts.

import datetime
import random
import socket
import struct
from binascii import unhexlify

from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue

from impacket import LOG
from impacket.krb5 import constants
from impacket.krb5.asn1 import (
    AP_REQ, AS_REP, Authenticator, EncTGSRepPart, KRB_ERROR, TGS_REP,
    TGS_REQ, seq_set, seq_set_iter,
)
from impacket.krb5.crypto import Key, _enctype_table
from impacket.krb5.kerberosv5 import KerberosError
from impacket.krb5 import kerberosv5 as _upstream
from impacket.krb5.types import KerberosTime, Principal, Ticket
from orpheus_runtime import normalize_kdc_options


_rand = random.SystemRandom()


def _hex_bytes(value, field, lengths=None):
    if value in ('', b'', None):
        return b''
    if isinstance(value, bytes):
        raw = value
    else:
        try:
            raw = unhexlify(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f'{field} must be hexadecimal') from exc
    if lengths and len(raw) not in lengths:
        raise ValueError(f'{field} must be {" or ".join(str(n * 8) for n in lengths)} bits')
    return raw


def validate_key_material(hashes: str | None, aes_key: str | bytes | None) -> None:
    """Validate CLI hash/key material without performing authentication."""
    if hashes is not None:
        parts = hashes.split(':')
        if len(parts) != 2:
            raise ValueError('hashes must use LMHASH:NTHASH format')
        lmhash, nthash = parts
        if not nthash:
            raise ValueError('NT hash must be 128 bits')
        if lmhash:
            _hex_bytes(lmhash, 'LM hash', (16,))
        _hex_bytes(nthash, 'NT hash', (16,))
    if aes_key is not None:
        _hex_bytes(aes_key, 'AES key', (16, 32))


def kdc_option_values(value: str) -> list[int]:
    return normalize_kdc_options(value)[1]


def get_tgt_for_credentials(client_name, password, domain, lmhash=b'', nthash=b'',
                            aes_key=b'', kdc_host=None, request_pac=True,
                            timeout=10.0):
    lmhash = _hex_bytes(lmhash, 'LM hash', (16,))
    nthash = _hex_bytes(nthash, 'NT hash', (16,))
    aes_key = _hex_bytes(aes_key, 'AES key', (16, 32))
    # Impacket exposes no TGT transport parameter; restore its global hook on exit.
    original_transport = _upstream.sendReceive
    _upstream.sendReceive = lambda data, host, kdcHost: send_receive(
        data, host, kdcHost, timeout=timeout
    )
    try:
        return _upstream.getKerberosTGT(
            client_name, password, domain, lmhash, nthash, aes_key,
            kdcHost=kdc_host, requestPAC=request_pac,
        )
    finally:
        _upstream.sendReceive = original_transport


def recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = []
    received = 0
    while received < size:
        chunk = sock.recv(size - received)
        if not chunk:
            raise ConnectionError(f'expected {size} bytes, received {received} before EOF')
        chunks.append(chunk)
        received += len(chunk)
    return b''.join(chunks)


def send_receive(data: bytes, host: str, kdc_host: str | None = None,
                 port: int = 88, timeout: float = 10.0) -> bytes:
    target = kdc_host or host
    LOG.debug('Trying to connect to KDC at %s:%d', target, port)
    try:
        with socket.create_connection((target, port), timeout=timeout) as connection:
            connection.sendall(struct.pack('!I', len(data)) + data)
            try:
                response_size = struct.unpack('!I', recv_exact(connection, 4))[0]
                response = recv_exact(connection, response_size)
            except ConnectionError as exc:
                raise ConnectionError(f'{target}:{port}: {exc}') from exc
    except OSError as exc:
        raise ConnectionError(f'connection error ({target}:{port}): {exc}') from exc

    if not response:
        return response
    try:
        error = KerberosError(packet=decoder.decode(response, asn1Spec=KRB_ERROR())[0])
    except Exception:
        return response
    if error.getErrorCode() != constants.ErrorCodes.KDC_ERR_PREAUTH_REQUIRED.value:
        raise error
    return response


def get_tgs(server_name, domain, kdc_host, tgt, cipher, session_key,
            kdc_options: str, request_etype: int, timeout: float = 10.0):
    try:
        decoded_tgt = decoder.decode(tgt, asn1Spec=AS_REP())[0]
    except Exception:
        decoded_tgt = decoder.decode(tgt, asn1Spec=TGS_REP())[0]

    domain = domain.upper()
    ticket = Ticket()
    ticket.from_asn1(decoded_tgt['ticket'])

    ap_req = AP_REQ()
    ap_req['pvno'] = 5
    ap_req['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)
    ap_req['ap-options'] = constants.encodeFlags([])
    seq_set(ap_req, 'ticket', ticket.to_asn1)

    authenticator = Authenticator()
    authenticator['authenticator-vno'] = 5
    authenticator['crealm'] = decoded_tgt['crealm'].asOctets()
    client_name = Principal()
    client_name.from_asn1(decoded_tgt, 'crealm', 'cname')
    seq_set(authenticator, 'cname', client_name.components_to_asn1)
    now = datetime.datetime.now(datetime.timezone.utc)
    authenticator['cusec'] = now.microsecond
    authenticator['ctime'] = KerberosTime.to_asn1(now)
    encrypted = cipher.encrypt(session_key, 7, encoder.encode(authenticator), None)
    ap_req['authenticator'] = noValue
    ap_req['authenticator']['etype'] = cipher.enctype
    ap_req['authenticator']['cipher'] = encrypted

    request = TGS_REQ()
    request['pvno'] = 5
    request['msg-type'] = int(constants.ApplicationTagNumbers.TGS_REQ.value)
    request['padata'] = noValue
    request['padata'][0] = noValue
    request['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_TGS_REQ.value)
    request['padata'][0]['padata-value'] = encoder.encode(ap_req)
    body = seq_set(request, 'req-body')
    body['kdc-options'] = constants.encodeFlags(kdc_option_values(kdc_options))
    seq_set(body, 'sname', server_name.components_to_asn1)
    body['realm'] = domain
    tomorrow = now + datetime.timedelta(days=1)
    body['till'] = KerberosTime.to_asn1(tomorrow)
    body['nonce'] = _rand.getrandbits(31)
    seq_set_iter(body, 'etype', (int(request_etype),))

    response = send_receive(encoder.encode(request), domain, kdc_host, timeout=timeout)
    tgs = decoder.decode(response, asn1Spec=TGS_REP())[0]
    plain = cipher.decrypt(session_key, 8, tgs['enc-part']['cipher'])
    reply = decoder.decode(plain, asn1Spec=EncTGSRepPart())[0]
    new_session_key = Key(reply['key']['keytype'], reply['key']['keyvalue'].asOctets())
    new_cipher = _enctype_table[reply['key']['keytype']]

    received_spn = Principal()
    received_spn.from_asn1(tgs['ticket'], 'realm', 'sname')
    if received_spn.components[0] == server_name.components[0]:
        return response, new_cipher, session_key, new_session_key
    referral_domain = received_spn.components[1]
    return get_tgs(
        server_name, referral_domain, kdc_host, response, new_cipher,
        new_session_key, kdc_options, request_etype, timeout,
    )
