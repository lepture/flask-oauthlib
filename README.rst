Flask-OAuthlib
==============

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
.. image:: https://img.shields.io/badge/donate-lepture-green.svg
   :target: https://lepture.herokuapp.com/?amount=1000&reason=lepture%2Fflask-oauthlib
   :alt: Donate leptjure


Flask-OAuthlib is an extension to Flask that allows you to interact with
remote OAuth enabled applications. On the client site, it is a replacement
for Flask-OAuth. But it does more than that, it also helps you to create
OAuth providers.

Flask-OAuthlib relies on oauthlib_.

.. _oauthlib: https://github.com/idan/oauthlib

Features
--------

- Support for OAuth 1.0a, 1.0, 1.1, OAuth2 client
- Friendly API (same as Flask-OAuth)
- Direct integration with Flask
- Basic support for remote method invocation of RESTful APIs
- Support OAuth1 provider with HMAC and RSA signature
- Support OAuth2 provider with Bearer token

And request more features at `github issues`_.

.. _`github issues`: https://github.com/lepture/flask-oauthlib/issues


Security Reporting
------------------

If you found security bugs which can not be public, send me email at `me@lepture.com`.
Attachment with patch is welcome.


Installation
------------

Installing flask-oauthlib is simple with pip_::

    $ pip install Flask-OAuthlib

If you don't have pip installed, try with easy_install::

    $ easy_install Flask-OAuthlib

.. _pip: http://www.pip-installer.org/


Additional Notes
----------------

We keep documentation at `flask-oauthlib@readthedocs`_.

.. _`flask-oauthlib@readthedocs`: https://flask-oauthlib.readthedocs.io

If you are only interested in the client part, you can find some examples
in the ``example`` directory.

There is also a `development version <https://github.com/lepture/flask-oauthlib/archive/master.zip#egg=Flask-OAuthlib-dev>`_ on GitHub.
