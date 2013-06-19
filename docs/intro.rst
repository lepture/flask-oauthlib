.. _introduction:

Introduction
============

Flask-OAuthlib is designed as a replacement for Flask-OAuth. It depends on
the oauthlib module.


Why
---

The original `Flask-OAuth`_ is lack of maintenance, and oauthlib_ is a
promising replacement for oauth2.

.. _`Flask-OAuth`: http://pythonhosted.org/Flask-OAuth/
.. _oauthlib: https://github.com/idan/oauthlib

There are lots of non-standard services that claim themself as oauth providers,
but the API are always broken. When rewrite a oauth extension for flask,
I do take them into consideration, Flask-OAuthlib does support those
non-standard services.

Flask-OAuthlib also provide the solution for creating an oauth service.
It is now focusing on the oauth2 part, and will take the oauth1 into
consideration.

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
