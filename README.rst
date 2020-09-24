Flask-OAuthlib
==============

.. image:: https://img.shields.io/badge/donate-lepture-green.svg
   :target: https://lepture.com/donate
   :alt: Donate lepture
.. image:: https://img.shields.io/pypi/wheel/flask-oauthlib.svg
   :target: https://pypi.python.org/pypi/flask-OAuthlib/
   :alt: Wheel Status
.. image:: https://img.shields.io/pypi/v/flask-oauthlib.svg
   :target: https://pypi.python.org/pypi/flask-oauthlib/
   :alt: Latest Version
.. image:: https://travis-ci.org/lepture/flask-oauthlib.svg?branch=master
   :target: https://travis-ci.org/lepture/flask-oauthlib
   :alt: Travis CI Status
.. image:: https://coveralls.io/repos/lepture/flask-oauthlib/badge.svg?branch=master
   :target: https://coveralls.io/r/lepture/flask-oauthlib
   :alt: Coverage Status


Notice
------

**You SHOULD use https://github.com/lepture/authlib instead**.

Flask-OAuthlib is an extension to Flask that allows you to interact with
remote OAuth enabled applications. On the client site, it is a replacement
for Flask-OAuth. But it does more than that, it also helps you to create
OAuth providers.

Flask-OAuthlib relies on oauthlib_.

.. _oauthlib: https://github.com/idan/oauthlib


Sponsored by
------------

If you want to quickly add secure authentication to Flask, feel free to
check out Auth0's Python API SDK and free plan at `auth0.com/developers`_
|auth0 image|

.. _`auth0.com/developers`: https://auth0.com/developers?utm_source=GHsponsor&utm_medium=GHsponsor&utm_campaign=flask-oauthlib&utm_content=auth

.. |auth0 image| image:: https://user-images.githubusercontent.com/290496/31718461-031a6710-b44b-11e7-80f8-7c5920c73b8f.png
   :target: https://auth0.com/developers?utm_source=GHsponsor&utm_medium=GHsponsor&utm_campaign=flask-oauthlib&utm_content=auth
   :alt: Coverage Status
   :width: 18px
   :height: 18px


Features
--------

- Support for OAuth 1.0a, 1.0, 1.1, OAuth2 client
- Friendly API (same as Flask-OAuth)
- Direct integration with Flask
- Basic support for remote method invocation of RESTful APIs
- Support OAuth1 provider with HMAC and RSA signature
- Support OAuth2 provider with Bearer token


Security Reporting
------------------

If you found security bugs which can not be public, send me email at `me@lepture.com`.
Attachment with patch is welcome.


Installation
------------

Installing flask-oauthlib is simple with pip::

    $ pip install Flask-OAuthlib

There is also a `development version <https://github.com/lepture/flask-oauthlib/archive/master.zip#egg=Flask-OAuthlib-dev>`_ on GitHub.


Links
-----

- Documentation: https://flask-oauthlib.readthedocs.io
- PyPI: https://pypi.org/project/Flask-OAuthlib/
- Client Examples: https://github.com/lepture/flask-oauthlib/tree/master/example
