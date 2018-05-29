#!/usr/bin/env python

from __future__ import print_function

__version__ = '0.1'
__author__  = 'Trevor Hartman'

import sys
import OpenSSL
import ssl
import socket
import json
import datetime
import dateparser

# Imports necessary for parsing ASN.1 Extension strings
from ndg.httpsclient.subj_alt_name import SubjectAltName
from pyasn1.codec.der import decoder as der_decoder


class Cert(object):
    """A SSL certificate object."""

    __isbinary = False
    cert_data = None
    altname   = None
    subject   = None
    issuer    = None
    issued_to = None
    issued_by = None
    exp_date  = None

    def __init__(self, cert_data, binary=False):
        if binary:
            self.__isbinary = binary
            self.cert_data = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_data)  # Is an x509 object.
        else:
            self.cert_data = cert_data

    def getExpDate(self):
        if not self.exp_date:
            if self.__isbinary:
                #print(self.cert_data.get_notAfter())
                self.exp_date = dateparser.parse(self.cert_data.get_notAfter(), date_formats=['%Y%m%d%H%M%SZ']).strftime('%s')
            else:
                #print(self.cert_data.viewkeys())
                #print(self.cert_data['notAfter'])
                # There is a bug in python SSL here where it gets the timezone ast GMT not GMT+1 which is UTC.  It should be GMT+1, but who cares for my purposes.
                self.exp_date = dateparser.parse(self.cert_data['notAfter']).strftime('%s')
        return self.exp_date

    def getIssuedBy(self):
        if not self.issued_by:
            if self.__isbinary:
                self.issued_by = self.getIssuer()['CN']
            else:
                self.issued_by = self.getIssuer()['commonName']
        return self.issued_by

    def getIssuer(self):
        if not self.issuer:
            if self.__isbinary:
                self.issuer = dict([ x[0], x[1] ] for x in self.cert_data.get_issuer().get_components())
            else:
                self.issuer = dict(x[0] for x in self.cert_data['issuer'])
        return self.issuer

    def getIssuedTo(self):
        if not self.issued_to:
            if self.__isbinary:
                self.issued_to = self.getSubject()['CN']
            else:
                self.issued_to = self.getSubject()['commonName']
        return self.issued_to

    def getAllIssuedNames(self):
        to = self.getIssuedTo()
        alt = self.getSubjectAltNames()
        alt[to] = 'IssuedTo'
        return alt

    def getSubject(self):
        if not self.subject:
            if self.__isbinary:
                self.subject = dict([ x[0], x[1] ] for x in self.cert_data.get_subject().get_components())
            else:
                self.subject = dict(x[0] for x in self.cert_data['subject'])
        return self.subject

    def getSubjectAltNames(self):
        if not self.altname:
            if self.__isbinary:
                alt_names = {}
                general_names = SubjectAltName()
                ext_data = self.getExtension('subjectAltName').get_data()
                dec_data = der_decoder.decode(ext_data, asn1Spec=general_names)
                for name in dec_data:
                    if isinstance(name, SubjectAltName):
                        for entry in range(len(name)):
                            component = name.getComponentByPosition(entry)
                            alt_names[str(component.getComponent())] = component.getName()
                self.altname = alt_names
            else:
                self.altname = dict([ x[1], x[0] ] for x in self.cert_data['subjectAltName'])
        return self.altname

    # Short Name: basicConstraints, extendedKeyUsage, keyUsage, crlDistributionPoints, certificatePolicies,
    #             authorityInfoAccess, authorityKeyIdentifier, subjectAltName, subjectKeyIdentifier, UNDEF
    def getExtension(self, ext_short_name):
        if not self.__isbinary:
            return None
        
        for i in range(self.cert_data.get_extension_count()):
            if self.cert_data.get_extension(i).get_short_name() == ext_short_name:
                return self.cert_data.get_extension(i)

    def __str__(self):
        if self.__isbinary:
            return "Issuer: %s, Subject: %s" % (json.dumps(self.getIssuer(), indent=4, sort_keys=True), json.dumps(self.getSubject(), indent=4, sort_keys=True))
        return json.dumps(self.cert_data, indent=4, sort_keys=True)


class CertReader(object):
    """Reading SSL certificates from sites."""
    ctx = None

    def __init__(self):
        #ssl._create_default_https_context = ssl._create_unverified_context
        # Monkey patch ssl to allow hostname matches.
        ssl.match_hostname = lambda cert, hostname: True
        self.ctx = ssl.create_default_context()

    def readCert(self, hostname, port=443, timeout=2):
        s = self.ctx.wrap_socket(socket.socket(), server_hostname=hostname)
        s.settimeout(timeout)
        s.connect((hostname, port))
        return Cert(s.getpeercert())

    def readBinaryCert(self, hostname, port=443):
        s = self.ctx.wrap_socket(socket.socket(), server_hostname=hostname)
        s.connect((hostname, port))
        return Cert(s.getpeercert(True), True)  # BINARY DER FORMAT, load with OpenSSL.crypto.FILETYPE_ASN1 in Cert class


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def ips(start, end):
    import socket, struct
    start = struct.unpack('>I', socket.inet_aton(start))[0]
    end = struct.unpack('>I', socket.inet_aton(end))[0]
    return [socket.inet_ntoa(struct.pack('>I', i)) for i in range(start, end)]

if __name__ == "__main__":
    cr = CertReader()

    for ip in ips('23.253.0.0', '23.253.255.255'):
        eprint("---- ", ip, "----")
        try:
            cert1 = cr.readCert(ip, 443)       # Normal type, uses python ssl
            cert2 = cr.readBinaryCert(ip, 443) # Binary Type, uses OpenSSL
            #print(cert1.__str__())
            #print(cert2.__str__())
            print(ip, "\t", json.dumps(cert1.getSubject()))
            print(ip, "\t", json.dumps(cert2.getSubject()))
            print(ip, "\t", json.dumps(cert1.getIssuedBy()))
            print(ip, "\t", json.dumps(cert2.getIssuedBy()))
            print(ip, "\t", json.dumps(cert1.getAllIssuedNames()))
            print(ip, "\t", json.dumps(cert2.getAllIssuedNames()))
            print(ip, "\t", json.dumps(cert1.getExpDate()))
            print(ip, "\t", json.dumps(cert2.getExpDate()))
        except Exception as ex:
            print("Exception!")
            print(ex.message)
            pass

    sys.exit(1)

