# -*- coding: utf-8 -*-
import os
import re
import gettext
import subprocess

from .data import zones

gettext.textdomain('whois2')
locale_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'locale')
_ = gettext.translation('whois2', locale_path, fallback=True).gettext

DEFAULT_CACHE_TIMEOUT = 600

RU_SUBDOMAINS = filter(lambda zone: re.match(r'^(\w+\.(ru$|su$)|ru.net$)', zone), zones)


class WhoisDomainBase(object):
    invalid = False

    def ascii_domain(self):
        """
        Return domain name in ASCII (xn notation)
        """
        return normalize_domain_name(self.domain)

    def unicode_domain(self):
        """
        Return domain name in unicode format
        """
        return self.ascii_domain().decode('idna')

    def is_idna(self):
        """
        Return True if domain name contains non-latin symbols
        """
        return is_idna(self.ascii_domain())


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


def get_whois(domain, whois_server=None, cache=None, cache_timeout=None):
    """
    Get whois information from remote domain in plain text format

    :param domain: domain name which can be a valid string, IDN-encoded if necessary.
    :param cache: a cache object having two methods: set(key, value, timeout)
                  and get(key), can be None, if you don't intend to use caching mechanism
    :param cache_timeout: cache timeout (in seconds)

    :returns: the string with the whois information about the domain
    :raises: RuntimeError (if "whois" command line utility returns with non-zero and non-one status)
    """
    cmd = ['whois', '-H', domain]
    if whois_server:
        cmd += ['-h', whois_server]
    cache_key = ':'.join((domain, whois_server or ''))

    out = None
    if cache:
        out = cache.get(cache_key)
    if out is None:
        pipe = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = pipe.communicate()
        if pipe.returncode in (0, 1):
            if cache:
                cache.set(cache_key, out, cache_timeout or DEFAULT_CACHE_TIMEOUT)
            return out
        error_text = ['cmd > {0}'.format(' '.join(cmd)), ]
        if out:
            error_text += ['out > {0}'.format(line) for line in out.splitlines()]
        if err:
            error_text += ['err > {0}'.format(line) for line in err.splitlines()]
        raise RuntimeError('\n'.join(error_text))
    else:
        return out


def normalize_domain_name(domain_name):
    """
    Normalized domain name
    """
    return domain_name.strip().lower().encode('idna')


def is_idna(domain_name):
    """
    IDNA check

    Return true is domain (either unicode or its idna representation) is in fact
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
