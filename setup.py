#!/usr/bin/env python
# -*- coding: utf-8 -*-


try:
    import multiprocessing
except ImportError:
    pass

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

import imp
from email.utils import parseaddr
info = imp.load_source('info', 'flask_oauthlib/info.py')
author, author_email = parseaddr(info.AUTHOR)


def fread(filename):
    with open(filename) as f:
        return f.read()


setup(
    name=info.NAME,
    version=info.VERSION,
    author=author,
    author_email=author_email,
    url=info.REPOSITORY,
    packages=[
        "flask_oauthlib",
        "flask_oauthlib.provider",
        "flask_oauthlib.contrib",
    ],
    description="OAuthlib for Flask",
    zip_safe=False,
    include_package_data=True,
    platforms='any',
    long_description=fread('README.rst'),
    license='BSD',
    install_requires=[
        'Flask',
        'oauthlib>=0.5',
    ],
    tests_require=['nose', 'Flask-SQLAlchemy'],
    test_suite='nose.collector',
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
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: Implementation',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ]
)
