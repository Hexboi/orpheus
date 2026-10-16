# Orpheus

Orpheus is a CLI and interactive wrapper for Kerberoasting and AS-REP Roasting,
built on Impacket. It lets you choose KDC options and the requested encryption
type (AES256 or RC4), independently of the credentials used to obtain the TGT.
Use it only in authorized environments.

## Changes from upstream

This version is derived from [TrustedSec/Orpheus](https://github.com/trustedsec/orpheus)
and preserves its original attribution. The main changes are:

- **Features:** AS-REP Roasting, a non-interactive CLI with `--dry-run` and
  proxychains options, alongside the original REPL.
- **Compatibility:** Impacket 0.13.x integration and replacement of the full
  `kerberosv5.py` fork with a local module containing the required extensions.
- **Fixes:** separate TGT credentials and requested TGS encryption type,
  input validation, consistent decimal/hex KDC options, and request pacing
  after failed attempts.
- **Reliability:** Kerberos TCP transport with timeouts and complete reads,
  atomic output, overwrite protection, and explicit exit codes.
- **Tests and documentation:** regression tests, opt-in laboratory tests,
  CI workflows, and updated documentation.

## Installation

Requires Python 3.10+. A single requirements file includes runtime and test
dependencies. Install in a virtual environment where possible:

```text
python -m pip install .
```

With the environment active, the `orpheus` command is available from any directory:

```text
orpheus --help
```

To work on the source without reinstalling after each change:
`python -m pip install -e .`.


## Quick start

The following examples use placeholder values. Kerberoasting with AES256 TGS:

```text
orpheus --cred 'lab.local/user:password' --dcip 10.1.1.1 --file spns.txt --enc 18
```

Unauthenticated AS-REP Roasting using a username list:

```text
orpheus --cred 'lab.local/' --dcip 10.1.1.1 --mode asrep --usersfile users.txt --file asrep.txt --enc 23
```

A username list contains one name per line. The scripts ignore blank lines and
duplicates, preserving the order of the first occurrence.

## Wrapper CLI

```text
orpheus --help
```

| Flag | Purpose and default |
| --- | --- |
| `--cred` | Required: `domain/user[:password]`; use `domain/` for an unauthenticated AS-REP username list. |
| `--dcip` | Required: domain controller address. |
| `--mode` | `kerb` (default) or `asrep`. |
| `--file` | Hash output file; defaults to `spns.txt`, including in AS-REP mode. |
| `--usersfile` | Username list for `asrep`; adds `-no-pass` to the child command. |
| `--options` | Unsigned 32-bit mask; defaults to `0x40810000`. |
| `--enc` | Requested encryption type: `18` AES256 (default) or `23` RC4. |
| `--sleep` | Seconds between consecutive attempts; defaults to `0`. |
| `--jitter` | Random integer variation of `±N` seconds; defaults to `0`. |
| `--overwrite` | Allow replacement of existing output. |
| `--proxychains` | Prefix execution with `proxychains` on Linux; ignored on Windows. |
| `--pcconf` | Configuration passed to `proxychains -f`. |
| `-n`, `--dry-run` | Show the command without executing it. |

## Interactive mode

Start without arguments:

```text
orpheus
```

| REPL command | Effect |
| --- | --- |
| `cred <value>`, `dcip <value>`, `file <path>` | Set credentials, DC, and output. |
| `0` … `31` | Toggle the specified KDC bit, numbered from the left. |
| `hex <value>` | Set the KDC mask; also accepts a decimal integer. |
| `enc` | Toggle AES256 and RC4. |
| `mode` | Toggle Kerberoasting and AS-REP Roasting. |
| `usersfile <path>` | Set the AS-REP username list. |
| `sleep <seconds>`, `jitter <seconds>` | Set request pacing. |
| `overwrite` | Toggle replacement of existing output. |
| `proxychains`, `pcconf <path>` | Toggle the Linux prefix and set its configuration. |
| `command` | Show the constructed command, including credentials. |
| `run` | Execute the current command. |
| `clear`, `help`, `exit` | Redraw the screen, show commands, or exit. |


## Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | All requested targets succeeded, or enumeration completed, including with no matches. |
| `1` | At least one result and at least one failed or skipped target. |
| `2` | Invalid input, local file, or option combination. |
| `3` | Kerberos/LDAP authentication or authorization error before the target loop. |
| `4` | Network, protocol, or runtime error before the target loop. |
| `5` | No successful request results, including when all targets failed or were skipped. |

## Development and testing

```text
python -m pytest -m "not lab" -q
python -m pip check
```

The `lab` tests are optional. Set `ORPHEUS_LAB_DC`, `ORPHEUS_LAB_DOMAIN`,
`ORPHEUS_LAB_USERNAME`, and `ORPHEUS_LAB_PASSWORD`; specific scenarios also use
`ORPHEUS_LAB_ASREP_USER` and `ORPHEUS_LAB_SPN_USER`. Run them with
`python -m pytest -m lab -q`. Do not store credentials or results in the project.

| File | Responsibility |
| --- | --- |
| `pyproject.toml` | Installation, the `orpheus` command, and test configuration. |
| `orpheus.py` | CLI, REPL, and child script execution. |
| `GetUserSPNs.py` | LDAP SPN enumeration, TGT acquisition, and TGS requests. |
| `GetNPUsers.py` | Enumeration of accounts without preauthentication and AS-REP requests. |
| `orpheus_kerberos.py` | Kerberos extensions and local TCP transport with a 10-second timeout. |
| `orpheus_runtime.py` | Validation, counters, exit codes, and atomic output. |
| `tests/` | Offline tests and laboratory integration. |

## License

The Orpheus GPLv3 and Impacket license texts are preserved in [LICENSE](LICENSE).
Original attribution remains in the source files.

This product includes software developed by SecureAuth Corporation (https://www.secureauth.com/) and Fortra (https://www.fortra.com).
