# -*- coding: utf8 -*-

from setuptools import setup, find_packages

setup(name='pywerview',
    version='1.0-dev',
    description='A Python port of PowerSploit\'s PowerView',
    dependency_links = ['https://github.com/CoreSecurity/impacket/tarball/master#egg=impacket-0.9.16dev']
    classifiers=[
        'Programming Language :: Python :: 2.7',
    ],
    keywords='python powersploit pentesting',
    url='https://github.com/the-useless-one/pywerview',
    author='Yannick Méheut',
    author_email='yannick@meheut.org',
    license='GNU',
    packages=find_packages(include=[
        "pywerview", "pywerview.*"
    ]),
    install_requires=[
        'impacket>=0.9.16dev',
        'pyasn1',
        'pycrypto',
        'pyopenssl',
        'bs4'
    ],
    entry_points = {
        'console_scripts': ['pywerview=pywerview.cli.main:main'],
    },
    zip_safe=False)

