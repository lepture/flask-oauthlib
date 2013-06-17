.. _provider:

Provider
========

This part of documentation covers the tutorial of setting up an OAuth
provider. Currently, only OAuth2 is implemented.

If you need OAuth1 provider, vote for `OAuth1 Provider`_.

.. _`OAuth1 Provider`: https://github.com/lepture/flask-oauthlib/issues/13


OAuth2 Server
-------------

An OAuth2 server concerns how to grant the auothorization and how to protect
the resource.

To implementing the oauthorization flow, we need to understand the data model.

User (Resource Owner)
~~~~~~~~~~~~~~~~~~~~~

A user, or resource owner, is usally the registered user on your site. You
design your own user model, there is not much to say.

Client (Application)
~~~~~~~~~~~~~~~~~~~~

A client is the app which want to use the resource of a user. It is suggested
that the client is registered by a user on your site, but it is not required.

The client should contain at least these information:

- client_id: A random string
- client_secret: A random string
- client_type: A string represents if it is `confidential`
- redirect_uris: A list of redirect uris
- default_redirect_uri: One of the redirect uris
- default_scopes: Default scopes of the client

But it could be better, if you implemented:

- allowed_grant_types: A list of grant types
- allowed_response_types: A list of response types

An example of the data model in SQLAlchemy (SQLAlchemy is not required)::

    class Client(db.Model):
        # human readable name, not required
        name = db.Column(db.Unicode(40))

        # human readable description, not required
        description = db.Column(db.Unicode(400))

        # creator of the client, not required
        user_id = db.Column(db.ForeignKey('user.id'))
        # required if you need to support password credential
        user = relationship('User')

        client_id = db.Column(db.Unicode(40), primary_key=True)
        client_secret = db.Column(db.Unicode(55), unique=True, index=True,
                                  nullable=False)

        # public or confidential
        client_type = db.Column(db.Unicode(20), default=u'public')

        _redirect_uris = db.Column(db.UnicodeText)
        _default_scopes = db.Column(db.UnicodeText)

        @property
        def redirect_uris(self):
            if self._redirect_uris:
                return self._redirect_uris.split()
            return []

        @property
        def default_redirect_uri(self):
            return self.redirect_uris[0]

        @property
        def default_scopes(self):
            if self._default_scopes:
                return self._default_scopes.split()
            return []


Grant Token
~~~~~~~~~~~

A grant token is created in the authorization flow, and will be destroyed
when the authorization finished. In this case, it would be better to store
the data in a cache, which would benefit a better performance.

A grant token should contain at least these information:

- client_id: A random string of client_id
- code: A random string
- user: The authorization user
- scopes: A list of scope
- expires: A datetime.datetime in UTC
- redirect_uri: A URI string
- delete: A function to delete itself

Also in SQLAlchemy model (would be better if it is in a cache)::

    class Grant(db.Model):
        id = db.Column(db.Integer, primary_key=True)

        user_id = db.Column(
            db.Integer, db.ForeignKey('user.id', ondelete='CASCADE')
        )
        user = relationship('User')

        client_id = db.Column(
            db.Unicode(40), db.ForeignKey('client.client_id'),
            nullable=False,
        )
        client = relationship('Client')

        code = db.Column(db.Unicode(255), index=True, nullable=False)

        redirect_uri = db.Column(db.Unicode(255))
        expires = db.Column(db.DateTime)

        _scopes = db.Column(db.UnicodeText)

        def delete(self):
            db.session.delete(self)
            db.session.commit()
            return self

        @property
        def scopes(self):
            if self._scopes:
                return self._scopes.split()
            return []

Bearer Token
~~~~~~~~~~~~

A bearer token is the final token that could be use by the client. There
are other token types, but bearer token is widely used. Flask-OAuthlib only
comes with bearer token.

A bearer token requires at least these information:

- access_token: A string token
- refresh_token: A string token
- client_id: ID of the client
- scopes: A list of scopes
- expires: A `datetime.datetime` object
- user: The user object

An example of the data model in SQLAlchemy::

    from datetime import datetime, timedelta

    class Token(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        client_id = db.Column(
            db.Unicode(40), db.ForeignKey('client.client_id'),
            nullable=False,
        )
        client = relationship('Client')

        user_id = db.Column(
            db.Integer, db.ForeignKey('user.id')
        )
        user = relationship('User')

        # currently only bearer is supported
        token_type = db.Column(db.Unicode(40))

        access_token = db.Column(db.Unicode(255))
        refresh_token = db.Column(db.Unicode(255))
        expires = db.Column(db.DateTime)
        _scopes = db.Column(db.UnicodeText)

        @property
        def scopes(self):
            if self._scopes:
                return self._scopes.split()
            return []


Configuration
~~~~~~~~~~~~~
