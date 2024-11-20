#!/usr/bin/env python3

from setuptools import setup, find_packages

long_description = open('README.md').read()

setup(name='pywerview',
    version='0.7.1',
    description='A Python port of PowerSploit\'s PowerView',
    long_description=long_description,
    long_description_content_type='text/markdown',
    classifiers=[
        'Environment :: Console',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
        'Programming Language :: Python :: 3.6',
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
    entry_points = {
        'console_scripts': ['pywerview=pywerview.cli.main:main'],
    },
    zip_safe=False)

