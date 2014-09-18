# -*- coding: utf-8 -*-
from .utils import get_whois, normalize_domain_name, WhoisDomain, WhoisDomainInvalid, _
from .validators import tld_validator
from .parsers import tld_parser
from .data import zones

SUPPORTED_TLD = zones

def check(domain, cache=None, cache_timeout=None):
    domain = normalize_domain_name(domain)
    validation_errors = get_validation_errors(domain)
    if validation_errors:
        return WhoisDomainInvalid(domain, validation_errors)
    name, tld = extract_tld(domain)
    whois_data = get_whois(domain, cache=cache, cache_timeout=cache_timeout)
    whois_result = parse_whois_data(domain, whois_data)
    return whois_result


def get_validation_errors(domain):
    # basic validation
    if not '.' in domain:
        return [_('invalid domain name')]
    name, tld = extract_tld(domain)
    if tld is None:
        prefix, suffix = domain.rsplit('.', 1)
        return [_('there are no rules to handle .{0} domains').format(suffix)]
    # custom domain validation
    errors = []
    for validator in tld_validator.get(tld):
        error = validator(name, tld)
        if error:
            errors.append(error)
    return errors


def parse_whois_data(domain, whois_data):
    name, tld = extract_tld(domain)
    whois = WhoisDomain(domain, whois_data)
    for parser in tld_parser.get(tld):
        parser(whois, name, tld)
    # while we have only one parser to check is domain not registered
    # that if registered is None, it means this parser found nothing
    whois.registered = getattr(whois, 'registered', True)
    return whois


def extract_tld(domain):
    """
    extract tld, based on the list of registry suffixes, starting from the
    longest one.

    For example, if registry contains suffixes for 'org.ru' and 'ru',
    then the domain 'linux.org.ru' will be split as ['linux', 'org.ru']

    If there is no such suffix, appropriate for the domain, then function
    returns ['full_domain.tld', None]
    """
    suffixes = sorted(SUPPORTED_TLD, key=len, reverse=True)
    for suffix in suffixes:
        if domain.endswith('.{0}'.format(suffix)):
            return domain[:-len(suffix)-1], domain[-len(suffix):]
    return domain, None
