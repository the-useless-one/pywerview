# -*- coding: utf8 -*-

from setuptools import setup, find_packages

try:
    import pypandoc
    long_description = pypandoc.convert('README.md', 'rst')
except(IOError, ImportError):
    long_description = open('README.md').read()

setup(name='pywerview',
    version='0.2.0',
    description='A Python port of PowerSploit\'s PowerView',
    long_description=long_description,
    dependency_links = ['https://github.com/CoreSecurity/impacket/tarball/master#egg=impacket-0.9.16dev'],
    classifiers=[
        'Environment :: Console',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
        'Programming Language :: Python :: 2.7',
        'Topic :: Security',
    ],
    keywords='python powersploit pentesting recon active directory windows',
    url='https://github.com/the-useless-one/pywerview',
    author='Yannick Méheut',
    author_email='yannick@meheut.org',
    license='GNU GPLv3',
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

