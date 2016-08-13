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

from email.utils import parseaddr
import flask_oauthlib

author, author_email = parseaddr(flask_oauthlib.__author__)


def fread(filename):
    with open(filename) as f:
        return f.read()


setup(
    name='Flask-OAuthlib',
    version=flask_oauthlib.__version__,
    author=author,
    author_email=author_email,
    url=flask_oauthlib.__homepage__,
    packages=[
        "flask_oauthlib",
        "flask_oauthlib.provider",
        "flask_oauthlib.contrib",
        "flask_oauthlib.contrib.client",
    ],
    description="OAuthlib for Flask",
    zip_safe=False,
    include_package_data=True,
    platforms='any',
    long_description=fread('README.rst'),
    license='BSD',
    install_requires=[
        'Flask',
        'oauthlib>=1.1.2',
        'requests-oauthlib>=0.6.2',
    ],
    tests_require=['nose', 'Flask-SQLAlchemy', 'mock'],
    test_suite='nose.collector',
    classifiers=[
        'Development Status :: 4 - Beta',
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
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: Implementation',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ]
)
