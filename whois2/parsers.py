# -*- coding: utf-8 -*-
import re
from .decorators import Registrar
from .utils import RU_SUBDOMAINS
from .parser_utils import register, clean_nameserver, clean_datetime, RegexpMatcher
tld_parser = Registrar()


#------------------------------------------------------------------------------
# getting 'registered' attribute
#------------------------------------------------------------------------------

@tld_parser('__all__')
def not_found(whois, name, tld):
    """
    Define whether a domain is found or not
    """
    templates = set([
        'not found',
        'not found: %s' % whois.domain,
        'no match for "%s".' % whois.domain,
        'no entries found for the selected source(s).',
        'no match',
        'no match.',
        'not registered',
        'domain not found',
        'nothing found for this query',
        'status: free',
        'status: available',
        'no matching record',
        'no entries found',
        'no matching objects found',
        'no data found',
        'nothing found for this query',
        'available for registration',
        'do not have an entry in our database'
    ])
    registered = getattr(whois, 'registered', None)
    if registered is None:
        for line in whois.whois_data.splitlines():
            if any(template in re.sub(r'\s+', ' ', line.lower().strip()) for template in templates):
                whois.registered = False
                break

@tld_parser('com', 'net', 'org', 'ru')
def expiration_date(whois, name, tld):
    """
    Define whether a domain has expiration date or no
    """
    templates = set([
        'Expiration Date: ',
        'paid-till: ',
        'Record expires: ',
    ])

    for template in templates:
        if template in whois.whois_data:
            whois.registered = True
            break

#------------------------------------------------------------------------------
# getting 'nameservers' attribute
#------------------------------------------------------------------------------

register(
    tld_parser(
        'sc', 'ag', 'hn', 'mobi', 'tel', 'lc', 'org', 'cc', 'net',
        'aero', 'com', 'bz', 'tv', 'xxx', 'pro', 'travel', 'biz', 'mn', 'vc',
        'info'
    ),
    RegexpMatcher('nameservers', re.compile(r'^\s*Name Server:\s*(?P<nameservers>\S+)'), multi_value=True, clean=clean_nameserver)
)
register(
    tld_parser('me'),
    RegexpMatcher('nameservers', re.compile(r'^\s*Nameservers:\s*(?P<nameservers>\S+)'), multi_value=True, clean=clean_nameserver)
)
register(
    tld_parser('ru', 'su', *RU_SUBDOMAINS),
    RegexpMatcher('nameservers', re.compile(r'^\s*nserver:\s*(?P<nameservers>\S+)'), multi_value=True, clean=clean_nameserver)
)


@tld_parser('co.uk')
def co_uk_nameservers(whois, name, tld):
    in_nameservers = False
    whois.nameservers = []
    for line in whois.whois_data.splitlines():
        line = line.strip()
        if not in_nameservers:
            if line == 'Name servers:':
                in_nameservers = True
                continue
        else:
            if line == '':
                break
            else:
                whois.nameservers.append(clean_nameserver(line))

#------------------------------------------------------------------------------
# getting 'paid_till' and 'created' attribute
#------------------------------------------------------------------------------
register(
    tld_parser('ru', 'su', *RU_SUBDOMAINS),
    RegexpMatcher('paid_till', re.compile(r'^paid-till:\s*(?P<paid_till>\d{4}\.\d{2}.\d{2})'), clean=clean_datetime)
)
register(
    tld_parser('ru', 'su', *RU_SUBDOMAINS),
    RegexpMatcher('created', re.compile(r'^created:\s*(?P<created>\d{4}\.\d{2}.\d{2})'), clean=clean_datetime)
)
