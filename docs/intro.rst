.. _introduction:

Introduction
============

Flask-OAuthlib is designed to be a replacement for Flask-OAuth. It depends on
oauthlib_.

Why
---

The original `Flask-OAuth`_ suffers from lack of maintenance, and oauthlib_ is a
promising replacement for `python-oauth2`_.

.. _`Flask-OAuth`: http://pythonhosted.org/Flask-OAuth/
.. _oauthlib: https://github.com/idan/oauthlib
.. _`python-oauth2`: https://pypi.python.org/pypi/oauth2/

There are lots of non-standard services that claim they are oauth providers, but
their APIs are always broken. While rewriteing an oauth extension for Flask, I
took them into consideration. Flask-OAuthlib does support these non-standard
services.

Flask-OAuthlib also provides the solution for creating an oauth service. It
supports both oauth1 and oauth2 (with Bearer Token).

import this
-----------

Flask-OAuthlib was developed with a few :pep:`20` idioms in mind::

    >>> import this


#. Beautiful is better than ugly.
#. Explicit is better than implicit.
#. Simple is better than complex.
#. Complex is better than complicated.
#. Readability counts.

All contributions to Flask-OAuthlib should keep these important rules in mind.


License
-------

A large number of open source projects in Python are `BSD Licensed`_, and
Flask-OAuthlib is released under `BSD License`_ too.

.. _`BSD License`: http://opensource.org/licenses/BSD-3-Clause
.. _`BSD Licensed`: http://opensource.org/licenses/BSD-3-Clause

.. include:: ../LICENSE
