# -*- coding: utf-8 -*-
from nose.tools import eq_
from mock import patch
from whois2 import check, extract_tld, get_validation_errors, normalize_domain_name, SUPPORTED_TLD
from whois2.utils import is_idna


def test_extract_tld():
    domains = {
        'linux.org.ru': ('linux', 'org.ru'),
        'linux.ru': ('linux', 'ru'),
        'linux.nonexistent': ('linux.nonexistent', None),
    }
    for domain, parts in domains.iteritems():
        eq_(extract_tld(domain, SUPPORTED_TLD), parts)


def test_is_idna():
    domains = {
        'xn--e1aybc.xn--p1ai': True,
        u'привет.рф': True,
        u'EXAMPLE.COM': False,
    }
    for domain, result in domains.iteritems():
        eq_(is_idna(domain), result, u'Wrong idna identification of %s' % domain)


def test_get_validation_errors():
    domains = {
        'linux.ru': False,
        'linux': True,
        'linux.nonexistent': True,
        'www.linux.ru': True,
    }
    for domain, has_validation_errors in domains.iteritems():
        errors = get_validation_errors(domain)
        eq_(errors != [], has_validation_errors, 'Unexpected error status for %s: %s' % (domain, errors))

def test_rf_domains():
    long_domain = (u'пушкин-' * 6) + u'пушкин.рф'
    domains = {
        u'пушкин-66.рф': True,
        u'а.рф': False,
        u'google.рф': False,
        u'-пушкин.рф': False,
        u'пушкин-.рф': False,
        long_domain: False,
    }
    for domain, valid in domains.iteritems():
        errors = get_validation_errors(normalize_domain_name(domain))
        eq_(errors == [], valid, 'Unexpected error status for %s: %s' % (domain, errors))


def mock_get_whois(domain, whois_server=None, cache=None):
    with open('tests/whois_data/%s' % domain.lower()) as fd:
        return fd.read()

def test_not_found():
    tld_list = SUPPORTED_TLD[::]
    tld_list.remove('xn--p1ai')
    for tld in tld_list:
        domain1 = 'google.%s' % tld
        domain2 = 'sahchoo5theevaa8peel.%s' % tld
        with patch('whois2.get_whois', mock_get_whois):
            result1 = check(domain1)
            result2 = check(domain2)
        eq_(result1.registered, True, 'Domain %s is identified as unregistered while it is' % domain1)
        eq_(result2.registered, False, 'Domain %s is identified as registered while it is not' % domain2)
