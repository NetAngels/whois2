# -*- coding: utf-8 -*-
from .utils import get_whois, normalize_domain_name, WhoisDomain, WhoisDomainInvalid, _
from .validators import tld_validator
from .parsers import tld_parser

SUPPORTED_TLD = ['aero', 'ag', 'biz', 'bz', 'cc', 'com', 'com.ru', 'co.uk',
'hn', 'info', 'lc', 'me', 'mn', 'mobi', 'msk.ru', 'name', 'net', 'net.ru',
'org', 'org.ru', 'pp.ru', 'pro', 'ru', 'sc', 'spb.ru', 'su', 'tel', 'travel', 'tv',
'vc', 'xn--p1ai', 'xxx',]

WHOIS_SERVERS = {
    'com.ru': 'whois.nic.ru',
    'net.ru': 'whois.nic.ru',
    'org.ru': 'whois.nic.ru',
    'pp.ru': 'whois.nic.ru',
    'spb.ru': 'whois.nic.ru',
    'msk.ru': 'whois.nic.ru',
}


def check(domain):
    domain = normalize_domain_name(domain)
    validation_errors = get_validation_errors(domain)
    if validation_errors:
        return WhoisDomainInvalid(domain, validation_errors)
    name, tld = extract_tld(domain, SUPPORTED_TLD)
    whois_data = get_whois(domain, whois_server=WHOIS_SERVERS.get(tld))
    whois_result = parse_whois_data(domain, whois_data)
    return whois_result


def get_validation_errors(domain):
    # basic validation
    if not '.' in domain:
        return [_('invalid domain name')]
    name, tld = extract_tld(domain, SUPPORTED_TLD)
    if tld is None:
        prefix, suffix = domain.rsplit('.', 1)
        return [_('there are no rules to handle .{} domains').format(suffix)]
    # custom domain validation
    errors = []
    for validator in tld_validator.get(tld):
        error = validator(name, tld)
        if error:
            errors.append(error)
    return errors


def parse_whois_data(domain, whois_data):
    name, tld = extract_tld(domain, SUPPORTED_TLD)
    whois = WhoisDomain(domain, whois_data)
    for parser in tld_parser.get(tld):
        parser(whois, name, tld)
    return whois


def extract_tld(domain, tld_list):
    """
    extract tld, based on the list of registry suffixes, starting from the
    longest one.

    For example, if registry contains suffixes for 'org.ru' and 'ru',
    then the domain 'linux.org.ru' will be split as ['linux', 'org.ru']

    If there is no such suffix, appropriate for the domain, then function
    returns ['full_domain.tld', None]
    """
    suffixes = sorted(tld_list, key=len, reverse=True)
    for suffix in suffixes:
        if domain.endswith('.{}'.format(suffix)):
            return domain[:-len(suffix)-1], domain[-len(suffix):]
    return domain, None
