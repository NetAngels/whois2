#!/usr/bin/env python
#coding: utf-8
from distutils.core import setup

setup(
    name='whois2',
    version='0.8.4',
    author='NetAngels',
    author_email='info@netangels.ru',
    packages=['whois2', ],
    scripts=['scripts/whois2', ],
    url='',
    download_url = '',
    license = 'BSD',
    description = 'whois wrapper library and whois2 command line utility',
    install_requires=[
        'blessings==1.5.1',
        'python-dateutil==1.5',
    ],
    classifiers=(
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries :: Python Modules',
    )
)
