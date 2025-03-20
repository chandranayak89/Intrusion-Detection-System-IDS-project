#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Setup script for the SIEM & Incident Response Integration module.
"""

import os
import sys
from setuptools import setup, find_packages

# Get the directory of the current file
here = os.path.abspath(os.path.dirname(__file__))

# Get the long description from the README file
with open(os.path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

# Get the requirements
with open(os.path.join(here, 'requirements.txt'), encoding='utf-8') as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]

# Define optional dependencies
extras_require = {
    'thehive': ['thehive4py>=1.8.1'],
    'splunk': ['splunk-sdk>=1.6.18'],
    'slack': ['slackclient>=2.9.4'],
    'pagerduty': ['pdpyras>=4.5.0'],
    'geoip': ['maxminddb>=2.2.0', 'geoip2>=4.6.0'],
    'all': [
        'thehive4py>=1.8.1',
        'splunk-sdk>=1.6.18',
        'slackclient>=2.9.4',
        'pdpyras>=4.5.0',
        'maxminddb>=2.2.0',
        'geoip2>=4.6.0'
    ],
    'dev': [
        'pytest>=7.2.0',
        'pytest-cov>=4.0.0',
        'responses>=0.22.0',
        'freezegun>=1.2.2'
    ]
}

setup(
    name='ids-siem-integration',
    version='0.1.0',
    description='SIEM & Incident Response Integration for IDS',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/yourusername/ids-project',
    author='Security Team',
    author_email='security@example.com',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Information Technology',
        'Topic :: Security',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
    ],
    keywords='security ids siem soar incident-response',
    packages=find_packages(where='.'),
    python_requires='>=3.7, <4',
    install_requires=requirements,
    extras_require=extras_require,
    package_data={
        'siem': ['config/*.yaml'],
    },
    entry_points={
        'console_scripts': [
            'ids-siem-example=siem.examples.siem_integration_example:main',
        ],
    },
    project_urls={
        'Bug Reports': 'https://github.com/yourusername/ids-project/issues',
        'Documentation': 'https://github.com/yourusername/ids-project#readme',
    },
) 