Flask-OAuthlib
==============

.. image:: https://badge.fury.io/py/Flask-OAuthlib.png
   :target: http://badge.fury.io/py/Flask-OAuthlib
.. image:: https://travis-ci.org/lepture/flask-oauthlib.png?branch=master
   :target: https://travis-ci.org/lepture/flask-oauthlib
.. image:: https://coveralls.io/repos/lepture/flask-oauthlib/badge.png?branch=master
   :target: https://coveralls.io/r/lepture/flask-oauthlib

Flask-OAuthlib is an extension to Flask that allows you to interact with
remote OAuth enabled applications. On the client site, it is a replacement
for Flask-OAuth. But it does more than that, it also helps you to create
oauth providers.

Flask-OAuthlib relies on oauthlib_.

.. _oauthlib: https://github.com/idan/oauthlib

Features
--------

- Support for OAuth 1.0a, 1.0, 1.1, OAuth2 client
- Friendly API (same with Flask-OAuth)
- Direct integration with Flask
- Basic support for remote method invocation of RESTful APIs
- Support OAuth1 provider with HMAC and RSA signature
- Support OAuth2 provider with Bearer token

And request more features at `github issues`_.

.. _`github issues`: https://github.com/lepture/flask-oauthlib/issues


Installation
------------

Install flask-oauthlib is simple with pip_::

    $ pip install Flask-OAuthlib

If you don't have pip installed, try with easy_install::

    $ easy_install Flask-OAuthlib

.. _pip: http://www.pip-installer.org/


Additional Notes
----------------

We keep a documentation at `flask-oauthlib@readthedocs`_.

.. _`flask-oauthlib@readthedocs`: https://flask-oauthlib.readthedocs.org

If you are only interested in client part, you can find some examples
in the ``example`` directory.

There is also a `development version <https://github.com/lepture/flask-oauthlib/archive/master.zip#egg=Flask-OAuthlib-dev>`_ on GitHub.
