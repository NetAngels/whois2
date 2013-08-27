# -*- coding: utf-8 -*-
from dateutil import parser

def register(registry, parser):
    """
    Register class-based parser to the registry

    Quite simple wrapper, basically a "sintactic sugar".
    """
    registry(parser)


def clean_nameserver(nserver):
    """
    Cleanup function for nameserver name
    """
    if nserver.endswith('.'):
        nserver = nserver[:-1]
    nserver = nserver.lower()
    return nserver


def clean_datetime(value):
    return parser.parse(value)


class RegexpMatcher(object):

    def __init__(self, attribute_name, regexp, multi_value=False, clean=None):
        """
        Check every whois line against regular expression

        :param attribute_name: attribute names the matcher search in
                                whois data and adds to whois object
        :param regexp: regular expession to extract from whois and add as attribute
        :param multi_value: boolean flag defining whether an attribute can have
                            more than one value
        :param clean: optional callable object accepting value extracted from whois text
                      and cleaning it up before passing as a whois object
        """
        self.attribute_name = attribute_name
        self.regexp = regexp
        self.multi_value = multi_value
        self.clean = clean

    def __call__(self, whois, name, tld):
        self.prepare_whois(whois)
        for line in  whois.whois_data.splitlines():
            match = self.regexp.match(line)
            if match:
                value = match.group(self.attribute_name)
                self.add_to_whois(whois, value)

    def prepare_whois(self, whois):
        if self.multi_value:
            if not hasattr(whois, self.attribute_name):
                setattr(whois, self.attribute_name, [])
        else:
            if not hasattr(whois, self.attribute_name):
                setattr(whois, self.attribute_name, None)

    def add_to_whois(self, whois, value):
        if value is None:
            return None
        if self.clean:
            value = self.clean(value)
        if value is None:
            return None
        if self.multi_value:
            getattr(whois, self.attribute_name).append(value)
        else:
            setattr(whois, self.attribute_name, value)
