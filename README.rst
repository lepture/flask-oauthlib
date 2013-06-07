Flask-OAuthlib
==============

.. image:: https://travis-ci.org/lepture/flask-oauthlib.png?branch=master
        :target: https://travis-ci.org/lepture/flask-oauthlib
.. image:: https://coveralls.io/repos/lepture/flask-oauthlib/badge.png?branch=master
        :target: https://coveralls.io/r/lepture/flask-oauthlib

Flask-OAuthlib is an extension to Flask that allows you to interact with
remote OAuth enabled applications. It is a replacement for Flask-OAuth.

Features
--------

* The client part is compatible with Flask-OAuth
* Compatible with non-standard but OAuth-Like services like weibo

Installation
------------

Install flask-oauthlib is simple with pip_::

    $ pip install Flask-OAuthlib

If you don't have pip installed, try with easy_install::

    $ easy_install Flask-OAuthlib

.. _pip: http://www.pip-installer.org/


Usage
-----

You can find some examples in this repo. This includes:

1. OAuth1 with twitter
2. OAuth2 with facebook
3. Non-standard OAuth-like service weibo
4. Another Chinese Social service douban
