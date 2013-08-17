.. _changelog:

Changelog
=========

Here you can see the full list of changes between each Flask-OAuthlib release.

Version 0.3.1
-------------

Release date to be decided.

- Add contrib module via `#15`_. We are still working on it,
  take your own risk.
- Add example of linkedin via `#35`_.
- Compatible with new proposals of oauthlib.
- Bugfix for client part.
- Backward compatible for lower version of Flask via `#37`_.

.. _`#15`: https://github.com/lepture/flask-oauthlib/issues/15
.. _`#35`: https://github.com/lepture/flask-oauthlib/issues/35
.. _`#37`: https://github.com/lepture/flask-oauthlib/issues/37

Version 0.3.0
-------------

Release on July 10, 2013.

- OAuth1 Provider available. Documentation at :doc:`oauth1`. :)
- Add ``before_request`` and ``after_request`` via `#22`_.
- Lazy load configuration for client via `#23`_. Documentation at :ref:`lazy-configuration`.
- Python 3 compatible now.

.. _`#22`: https://github.com/lepture/flask-oauthlib/issues/22
.. _`#23`: https://github.com/lepture/flask-oauthlib/issues/23

Version 0.2.0
-------------

Release on June 19, 2013.

- OAuth2 Provider available. Documentation at :doc:`oauth2`. :)
- Make client part testable.
- Change extension name of client from ``oauth-client`` to ``oauthlib.client``.

Version 0.1.1
-------------

Released on May 23, 2013.

- Fix setup.py

Version 0.1.0
-------------

First public preview release on May 18, 2013.
