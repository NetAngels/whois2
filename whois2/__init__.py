# -*- coding: utf-8 -*-
from .utils import get_whois, normalize_domain_name, WhoisDomain, WhoisDomainInvalid, _
from .validators import tld_validator
from .parsers import tld_parser

SUPPORTED_TLD = """ac ad ae aero af ag al am aq as asia at aw ax az
ba bb be bg bh bi biz bj bm bo bs bt bz
ca cat cc cd cf cg ch ci cl cm cn coop cr cu cv cx cz
co co.ao co.bw co.ck co.fk co.id co.il co.in co.ke co.ls co.mz co.no co.nz co.th co.tz co.uk co.uz co.za co.zm co.zw
com com.ai com.ar com.au com.bd com.bn com.br com.cn com.cy com.eg com.et com.fj com.gh com.gn com.gt com.gu com.hk com.jm com.kh com.kw com.lb com.lr com.mt com.mv com.ng com.ni com.np com.nr com.om com.pa com.pl com.py com.qa com.ru com.sa com.sb com.sg com.sv com.sy com.tr com.tw com.ua com.uy com.ve com.vi com.vn com.ye
de de.com dj dk dm do dz
ec edu ee es eu eu.com
fi fm fo fr
ga gd ge gf gg gi gl gm gp gr gs gy
hk hm hn hr ht hu
ie im in info in.ua io ir is it
je jo jobs jp
kg ki kiev.ua kn kr ky
la lc li lk lt lu lv ly
ma mc md me me.uk mg mk mn mo mobi mp ms msk.ru mu museum mw mx my
na name nc ne net net.cn net.ru nf nl no nu
org org.cn org.ru org.uk
pe ph pk pl pn pr pro ps pt pw
re ro rs ru ru.com rw
sc sd se sg sh si sk sl sm sn so spb.ru sr st su sz
tel tc td tg tj tk tl tm tn to travel tt tv tw
ua ug us uz
vc vg vn vu
ws
xn--p1ai xxx
""".split()

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
