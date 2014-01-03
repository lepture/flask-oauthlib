.. _changelog:

Changelog
=========

Here you can see the full list of changes between each Flask-OAuthlib release.

Version 0.4.2
-------------

Released on Jan 3, 2014

Happy New Year!

- Add param ``state`` in authorize method via `#63`_.
- Bugfix for encoding error in Python 3 via `#65`_.

.. _`#63`: https://github.com/lepture/flask-oauthlib/issues/63
.. _`#65`: https://github.com/lepture/flask-oauthlib/issues/65

Version 0.4.1
-------------

Released on Nov 25, 2013

- Add access_token on request object via `#53`_.
- Bugfix for lazy loading configuration via `#55`_.

.. _`#53`: https://github.com/lepture/flask-oauthlib/issues/53
.. _`#55`: https://github.com/lepture/flask-oauthlib/issues/55


Version 0.4.0
-------------

Released on Nov 12, 2013

- Redesign contrib library.
- A new way for lazy loading configuration via `#51`_.
- Some bugfixes.

.. _`#51`: https://github.com/lepture/flask-oauthlib/issues/51


Version 0.3.4
-------------

Released on Oct 31, 2013

- Bugfix for client missing a string placeholder via `#49`_.
- Bugfix for client property getter via `#48`_.

.. _`#49`: https://github.com/lepture/flask-oauthlib/issues/49
.. _`#48`: https://github.com/lepture/flask-oauthlib/issues/48

Version 0.3.3
-------------

Released on Oct 4, 2013

- Support for token generator in OAuth2 Provider via `#42`_.
- Improve client part, improve test cases.
- Fix scope via `#44`_.

.. _`#42`: https://github.com/lepture/flask-oauthlib/issues/42
.. _`#44`: https://github.com/lepture/flask-oauthlib/issues/44

Version 0.3.2
-------------

Released on Sep 13, 2013

- Upgrade oauthlib to 0.6
- A quick bugfix for request token params via `#40`_.

.. _`#40`: https://github.com/lepture/flask-oauthlib/issues/40

Version 0.3.1
-------------

Released on Aug 22, 2013

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

Released on July 10, 2013.

- OAuth1 Provider available. Documentation at :doc:`oauth1`. :)
- Add ``before_request`` and ``after_request`` via `#22`_.
- Lazy load configuration for client via `#23`_. Documentation at :ref:`lazy-configuration`.
- Python 3 compatible now.

.. _`#22`: https://github.com/lepture/flask-oauthlib/issues/22
.. _`#23`: https://github.com/lepture/flask-oauthlib/issues/23

Version 0.2.0
-------------

Released on June 19, 2013.

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
