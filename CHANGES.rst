Changelog
=========

Here you can see the full list of changes between each Flask-OAuthlib release.

Version 0.9.3
-------------

Released on Jun 2, 2016

- Revert the wrong implement of non credential oauth2 require auth
- Catch all exceptions in OAuth2 providers
- Bugfix for examples, docs and other things


Version 0.9.2
-------------

Released on Nov 3, 2015

- Bugfix in client parse_response when body is none.
- Update contrib client by @tonyseek
- Typo fix for OAuth1 provider
- Fix OAuth2 provider on non credential clients by @Fleurer


Version 0.9.1
-------------

Released on Mar 9, 2015

- Improve on security.
- Fix on contrib client.

Version 0.9.0
-------------

Released on Feb 3, 2015

- New feature for contrib client, which will become the official client in
  the future via `#136`_ and `#176`_.
- Add appropriate headers when making POST request for access toke via `#169`_.
- Use a local copy of instance 'request_token_params' attribute to avoid side
  effects via `#177`_.
- Some minor fixes of contrib by Hsiaoming Yang.

.. _`#177`: https://github.com/lepture/flask-oauthlib/pull/177
.. _`#169`: https://github.com/lepture/flask-oauthlib/pull/169
.. _`#136`: https://github.com/lepture/flask-oauthlib/pull/136
.. _`#176`: https://github.com/lepture/flask-oauthlib/pull/176


Version 0.8.0
-------------

Released on Dec 3, 2014

.. module:: flask_oauthlib.provider.oauth2

- New feature for generating refresh tokens
- Add new function :meth:`OAuth2Provider.verify_request` for non vanilla Flask projects
- Some small bugfixes


Version 0.7.0
-------------

Released on Aug 20, 2014

.. module:: flask_oauthlib.client

- Deprecated :meth:`OAuthRemoteApp.authorized_handler` in favor of
  :meth:`OAuthRemoteApp.authorized_response`.
- Add revocation endpoint via `#131`_.
- Handle unknown exceptions in providers.
- Add PATCH method for client via `#134`_.

.. _`#131`: https://github.com/lepture/flask-oauthlib/pull/131
.. _`#134`: https://github.com/lepture/flask-oauthlib/pull/134


Version 0.6.0
-------------

Released on Jul 29, 2014

- Compatible with OAuthLib 0.6.2 and 0.6.3
- Add invalid_response decorator to handle invalid request
- Add error_message for OAuthLib Request.

Version 0.5.0
-------------

Released on May 13, 2014

- Add ``contrib.apps`` module, thanks for tonyseek via `#94`_.
- Status code changed to 401 for invalid access token via `#93`_.
- **Security bug** for access token via `#92`_.
- Fix for client part, request token params for OAuth1 via `#91`_.
- **API change** for ``oauth.require_oauth`` via `#89`_.
- Fix for OAuth2 provider, support client authentication for authorization-code grant type via `#86`_.
- Fix client_credentials logic in validate_grant_type via `#85`_.
- Fix for client part, pass access token method via `#83`_.
- Fix for OAuth2 provider related to confidential client via `#82`_.

Upgrade From 0.4.x to 0.5.0
~~~~~~~~~~~~~~~~~~~~~~~~~~~

API for OAuth providers ``oauth.require_oauth`` has changed.

Before the change, you would write code like::

    @app.route('/api/user')
    @oauth.require_oauth('email')
    def user(req):
        return jsonify(req.user)

After the change, you would write code like::

    from flask import request

    @app.route('/api/user')
    @oauth.require_oauth('email')
    def user():
        return jsonify(request.oauth.user)

.. _`#94`: https://github.com/lepture/flask-oauthlib/pull/94
.. _`#93`: https://github.com/lepture/flask-oauthlib/issues/93
.. _`#92`: https://github.com/lepture/flask-oauthlib/issues/92
.. _`#91`: https://github.com/lepture/flask-oauthlib/issues/91
.. _`#89`: https://github.com/lepture/flask-oauthlib/issues/89
.. _`#86`: https://github.com/lepture/flask-oauthlib/pull/86
.. _`#85`: https://github.com/lepture/flask-oauthlib/pull/85
.. _`#83`: https://github.com/lepture/flask-oauthlib/pull/83
.. _`#82`: https://github.com/lepture/flask-oauthlib/issues/82

Thanks Stian Prestholdt and Jiangge Zhang.

Version 0.4.3
-------------

Released on Feb 18, 2014

- OAuthlib released 0.6.1, which caused a bug in oauth2 provider.
- Validation for scopes on oauth2 right via `#72`_.
- Handle empty response for application/json via `#69`_.

.. _`#69`: https://github.com/lepture/flask-oauthlib/issues/69
.. _`#72`: https://github.com/lepture/flask-oauthlib/issues/72

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
