#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os

from setuptools import find_packages, setup

exec(open(os.path.join(os.path.dirname(__file__),
                       'whois_similarity_distance/_version.py')).read())  # defines __version__

with open('requirements.txt') as handle:
    REQUIRES = handle.read().splitlines()
    REQUIRES = [req[:req.find('=')] for req in REQUIRES]
    print(REQUIRES)
        

with open('README.md') as handle:
    README = handle.read()


setup(
    name='whois_similarity_distance',
    version=__version__,
    maintainer='Raúl B. Netto',
    maintainer_email='raulbeni@gmail.com',
    install_requires=REQUIRES,
    packages=find_packages(),
    url='https://github.com/stratosphereips/whois-similarity-distance',
    download_url='https://github.com/stratosphereips/whois-similarity-distance/archive/v0.2.0a.tar.gz',
    license='MIT',
    description=' This python scripts can calculate the WHOIS Similarity Distance between two given domains.',
    long_description=README,
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Telecommunications Industry',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
        'Topic :: Security',
    ],
    keywords='whois similarity',
    entry_points={
        'console_scripts': [
            'wsd_domains = whois_similarity_distance.wsd_domains:main',
        ],
    },
)
