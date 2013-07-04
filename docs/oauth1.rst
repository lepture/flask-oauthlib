OAuth1 Server
=============

This part of documentation covers the tutorial of setting up an OAuth1
provider. An OAuth2 server concerns how to grant the auothorization and
how to protect the resource. Register an **OAuth** provider::

    from flask_oauthlib.provider import OAuth1Provider

    app = Flask(__name__)
    oauth = OAuth1Provider(app)

Like any other Flask extensions, we can pass the application later::

    oauth = OAuth1Provider()

    def create_app():
        app = Flask(__name__)
        oauth.init_app(app)
        return app

To implemente the oauthorization flow, we need to understand the data model.


User (Resource Owner)
---------------------

A user, or resource owner, is usally the registered user on your site. You
design your own user model, there is not much to say.


Client (Application)
---------------------

A client is the app which want to use the resource of a user. It is suggested
that the client is registered by a user on your site, but it is not required.

The client should contain at least these information:

- client_key: A random string
- client_secret: A random string
- redirect_uris: A list of redirect uris
- default_redirect_uri: One of the redirect uris
- default_realms: Default realms/scopes of the client

But it could be better, if you implemented:

- validate_realms: A function to validate realms

An example of the data model in SQLAlchemy (SQLAlchemy is not required)::

    class Client(db.Model):
        # human readable name, not required
        name = db.Column(db.Unicode(40))

        # human readable description, not required
        description = db.Column(db.Unicode(400))

        # creator of the client, not required
        user_id = db.Column(db.ForeignKey('user.id'))
        # required if you need to support client credential
        user = relationship('User')

        client_key = db.Column(db.Unicode(40), primary_key=True)
        client_secret = db.Column(db.Unicode(55), unique=True, index=True,
                                  nullable=False)

        _realms = db.Column(db.UnicodeText)
        _redirect_uris = db.Column(db.UnicodeText)

        @property
        def redirect_uris(self):
            if self._redirect_uris:
                return self._redirect_uris.split()
            return []

        @property
        def default_redirect_uri(self):
            return self.redirect_uris[0]

        @property
        def default_realms(self):
            if self._realms:
                return self._realms.split()
            return []


Request Token and Verifier
--------------------------

Request token is designed for exchanging access token. Verifier token is
designed to verify the current user. It is always suggested that you combine
request token and verifier together.


Access Token
------------

An access token is the final token that could be use by the client. Client
will send access token everytime when it need to access resource.


Configuration
-------------

The oauth provider has some built-in defaults, you can change them with Flask
config:

==================================== ==========================================
`OAUTH1_PROVIDER_ERROR_URI`          The error page when there is an error,
                                     default value is ``'/oauth/errors'``.
`OAUTH1_PROVIDER_ERROR_ENDPOINT`     You can also configure the error page uri
                                     with an endpoint name.
`OAUTH1_PROVIDER_REALMS`             A list of allowed realms, default is [].
`OAUTH1_PROVIDER_KEY_LENGTH`         A range allowed for key length, default
                                     value is (20, 30).
`OAUTH1_PROVIDER_ENFORCE_SSL`        If the server should be enforced through
                                     SSL. Default value is True.
`OAUTH1_PROVIDER_SIGNATURE_METHODS`  Allowed signature methods, default value
                                     is (SIGNATURE_HMAC, SIGNATURE_RSA).
==================================== ==========================================

.. warning::

    RSA signature is not ready at this moment, you should use HMAC.


Implements
----------

Protect Resource
----------------
