# -*- coding: utf-8 -*-
"""
Validation rules for domain.

Every domain name is normalized, thus idna-ficated and in lower case
"""
import re
from .decorators import Registrar
from .utils import is_idna, unicodify, RU_SUBDOMAINS, _
tld_validator = Registrar()


@tld_validator('__all__')
def base_validation(name, tld):
    if '.' in name:
        return _('pick 2nd level domain. domain.tld, not www.domain.tld')
    valid_domain_symbols = re.compile(r'^[a-z0-9\-]+$')
    if not valid_domain_symbols.match(name):
        return _('domains must contain letters, numbers and a "-" sign only')
    if name.startswith('-') or name.endswith('-'):
        return _('domain cannot starts or ends with "-" sign')



@tld_validator('ru', 'pro', 'info', 'biz', 'travel', 'aero', 'mobi', 'xxx',
               'me', 'bz', 'ag', 'hn', 'lc', 'mn', 'sc', 'vc', *RU_SUBDOMAINS)
def idna_forbidden(name, tld):
    if is_idna(name):
        return _('IDNA domains are forbidden in .{} domain').format(tld)



@tld_validator('su', 'com', 'net', 'org', 'tel', 'name', 'tv', 'cc')
def idna_allowed(name, tld):
    pass


@tld_validator('info', 'pro', 'name', 'travel', 'xxx', 'bz', 'mn', 'sc')
def three_letters_domain(name, tld):
    if len(name) < 3:
        return _('domain names shorter than 3 letter are forbidden in .{}').format(tld)



@tld_validator('ru', 'su', 'tel', 'name', 'aero', 'bz', 'mn', 'sc', 'vc', *RU_SUBDOMAINS)
def two_letters_domain(name, tld):
    if len(name) < 2:
        return _('domain names shorter than 2 letter are forbidden in .{}').format(tld)



@tld_validator('xn--p1ai')
def rf_validator(name, tld):
    # according to http://www.xn--j1ay.xn--p1ai/ru/docs/rules.php
    u_name = unicodify(name)
    if len(u_name) < 2:
        return _('RF domain must contain at least 2 symbols')
    if len(name + '.xn--p1ai') > 63:
        return _('IDNA representation of the domain contains more than 63 symbols')
    regexp = re.compile(ur'^[абвгдеёжзийклмнопрстуфхцчшщъыьэюя0123456789\-]+$')
    if not regexp.match(u_name):
        return _('RF domain must contain only russian letters, numbers and a "-" sign')
    if u_name.startswith('-') or u_name.endswith('-'):
        return _('domain cannot starts or ends with "-" sign')
