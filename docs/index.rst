.. Flask-OAuthlib documentation master file, created by
   sphinx-quickstart on Fri May 17 21:54:48 2013.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Flask-OAuthlib
==============

Flask-OAuthlib is desinged as a replacement for Flask-OAuth. It depends
on the oauthlib module.

The client part of Flask-OAuthlib shares the same API as Flask-OAuth,
which is pretty and simple.


Features
--------

- Support for OAuth 1.0a, 1.0, 1.1, OAuth2 client
- Friendly API (same with Flask-OAuth)
- Direct integration with Flask
- Basic support for remote method invocation of RESTful APIs
- Support OAuth1 provider with HMAC and RSA signature
- Support OAuth2 provider with Bearer token


User's Guide
------------

This part of the documentation, which is mostly prose, begins with some
background information about Flask-OAuthlib, then focuese on step-by-step
instructions for getting the most out of Flask-OAuthlib

.. toctree::
   :maxdepth: 2

   intro
   install
   client
   oauth1
   oauth2
   additional


API Documentation
-----------------

If you are looking for information on a specific function, class or method,
this part of the documentation is for you.

.. toctree::
   :maxdepth: 2

   api


Additional Notes
----------------

Contribution guide, legal information and changelog are here.

.. toctree::
   :maxdepth: 2

   contrib
   changelog
   authors
