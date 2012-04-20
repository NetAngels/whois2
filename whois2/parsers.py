# -*- coding: utf-8 -*-
from .decorators import Registrar
tld_parser = Registrar()


@tld_parser('__all__')
def not_found(whois, name, tld):
    """
    Define whether a domain is found or not
    """
    templates = set([
        'NOT FOUND',
        'Not found: %s' % whois.domain,
        'No match for "%s".' % whois.domain,
        'No match for "%s".' % whois.domain.upper(),
        'No entries found for the selected source(s).',
        'No match',
        'No match.',
    ])
    registered = True
    for line in whois.whois_data.splitlines():
        if line.strip() in templates:
            registered = False
            break
    whois.registered = registered
