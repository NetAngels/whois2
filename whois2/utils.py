# -*- coding: utf-8 -*-
import os
import gettext
import subprocess

gettext.textdomain('whois2')
locale_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'locale')
_ = gettext.translation('whois2', locale_path, fallback=True).ugettext


RU_SUBDOMAINS = ['com.ru', 'net.ru', 'org.ru', 'pp.ru', 'spb.ru', 'msk.ru']

class WhoisDomainBase(object):
    invalid = False


class WhoisDomain(WhoisDomainBase):
    """
    whois2.check(..) result
    """
    def __init__(self, domain, whois_data):
        self.domain = domain
        self.whois_data = whois_data


class WhoisDomainInvalid(WhoisDomainBase):
    """
    whois2.check(..) result in case when domain name is invalid
    """
    invalid = True
    def __init__(self, domain, validation_errors):
        self.domain = domain
        self.validation_errors = validation_errors


def get_whois(domain, whois_server=None):
    """
    Get whois information from remote domain in plain text format

    :param domain: domain name which can be a valid string, IDN-encoded if necessary.

    :returns: the string with the whois information about the domain
    :raises: RuntimeError (if "whois" command line utility returns with non-zero and non-one status)
    """
    cmd = ['whois', '-H', domain]
    if whois_server:
        cmd += ['-h', whois_server]
    pipe = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = pipe.communicate()
    if pipe.returncode in (0, 1):
        return out
    error_text = ['cmd > {}'.format(' '.join(cmd)), ]
    if out:
        error_text += ['out > {}'.format(line) for line in out.splitlines()]
    if err:
        error_text += ['err > {}'.format(line) for line in err.splitlines()]
    raise RuntimeError('\n'.join(error_text))


def normalize_domain_name(domain_name):
    """
    Normalized domain name
    """
    return domain_name.strip().lower().encode('idna')


def is_idna(domain_name):
    """
    IDNA check

    Return true is domain (either unicode or its idna representation is in fact
    contains prohibited symbols which have to be IDNA encoded
    """
    domain_name = domain_name.strip().lower()
    idna_domain = domain_name.encode('idna')
    return idna_domain.decode('idna') != idna_domain


def unicodify(domain_name):
    """
    Convert any domain name (IDNA or unicode representation) to unicode
    """
    return domain_name.encode('idna').decode('idna')
