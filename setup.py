#!/usr/bin/env python
# -*- coding: utf-8 -*-


try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

import imp
from email.utils import parseaddr
info = imp.load_source('info', 'flask_oauthlib/info.py')
author, author_email = parseaddr(info.AUTHOR)

setup(
    name=info.NAME,
    version=info.VERSION,
    author=author,
    author_email=author_email,
    url=info.REPOSITORY,
    packages=["flask_oauthlib", "flask_oauthlib.provider"],
    description="OAuthlib for Flask",
    zip_safe=False,
    include_package_data=True,
    platforms='any',
    long_description=open('README.rst').read(),
    license=open('LICENSE').read(),
    install_requires=[
        'Flask',
        'oauthlib',
    ],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved',
        'License :: OSI Approved :: BSD License',
        'Operating System :: MacOS',
        'Operating System :: POSIX',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: Implementation',
        'Programming Language :: Python :: Implementation :: CPython',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ]
)
