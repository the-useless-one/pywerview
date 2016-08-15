# -*- coding: utf8 -*-

from setuptools import setup, find_packages

setup(name='pywerview',
    version='0.0.1',
    description='A Python port of PowerSploit\'s PowerView',
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
        'impacket>=0.9.15',
        'pyasn1',
        'pycrypto',
        'pyopenssl',
        'bs4'
    ],
    entry_points = {
        'console_scripts': ['pywerview=pywerview.main:main'],
    },
    zip_safe=False)