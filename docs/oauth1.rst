OAuth1 Server
=============

This part of documentation covers the tutorial of setting up an OAuth1
provider. An OAuth1 server concerns how to grant the authorization and
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
        name = db.Column(db.String(40))

        # human readable description, not required
        description = db.Column(db.String(400))

        # creator of the client, not required
        user_id = db.Column(db.ForeignKey('user.id'))
        # required if you need to support client credential
        user = relationship('User')

        client_key = db.Column(db.String(40), primary_key=True)
        client_secret = db.Column(db.String(55), unique=True, index=True,
                                  nullable=False)

        _realms = db.Column(db.Text)
        _redirect_uris = db.Column(db.Text)

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

The request token should contain:

- client: Client associated with this token
- token: Access token
- secret: Access token secret
- realms: Realms with this access token
- redirect_uri: A URI for redirecting

The verifier should contain:

- verifier: A random string for verifier
- user: The current user

And the all in one token example::

    class RequestToken(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(
            db.Integer, db.ForeignKey('user.id', ondelete='CASCADE')
        )
        user = relationship('User')

        client_key = db.Column(
            db.String(40), db.ForeignKey('client.client_key'),
            nullable=False,
        )
        client = relationship('Client')

        token = db.Column(db.String(255), index=True, unique=True)
        secret = db.Column(db.String(255), nullable=False)

        verifier = db.Column(db.String(255))

        redirect_uri = db.Column(db.Text)
        _realms = db.Column(db.Text)

        @property
        def realms(self):
            if self._realms:
                return self._realms.split()
            return []

Since the request token and verifier is a one-time token, it would be better
to put them in a cache.


Timestamp and Nonce
-------------------

Timestamp and nonce is a token for preventing repeating requests, it can store
these information:

- client_key: The client/consure key
- timestamp: The ``oauth_timestamp`` parameter
- nonce: The ``oauth_nonce`` parameter
- request_token: Request token string, if any
- access_token: Access token string, if any

The timelife of a timestamp and nonce is 60 senconds, put it in a cache please.
Here is an example in SQLAlchemy::

    class Nonce(db.Model):
        id = db.Column(db.Integer, primary_key=True)

        timestamp = db.Column(db.Integer)
        nonce = db.Column(db.String(40))
        client_key = db.Column(
            db.String(40), db.ForeignKey('client.client_key'),
            nullable=False,
        )
        client = relationship('Client')
        request_token = db.Column(db.String(50))
        access_token = db.Column(db.String(50))


Access Token
------------

An access token is the final token that could be use by the client. Client
will send access token everytime when it need to access resource.

A access token requires at least these information:

- client: Client associated with this token
- user: User associated with this token
- token: Access token
- secret: Access token secret
- realms: Realms with this access token

The implementation in SQLAlchemy::

    class AccessToken(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        client_key = db.Column(
            db.String(40), db.ForeignKey('client.client_key'),
            nullable=False,
        )
        client = relationship('Client')

        user_id = db.Column(
            db.Integer, db.ForeignKey('user.id'),
        )
        user = relationship('User')

        token = db.Column(db.String(255))
        secret = db.Column(db.String(255))

        _realms = db.Column(db.Text)

        @property
        def realms(self):
            if self._realms:
                return self._realms.split()
            return []


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

The implementings of authorization flow needs three handlers, one is request
token handler, one is authorize handler for user to confirm the grant, the
other is token handler for client to exchange access token.

Before the implementing of authorize and request/access token handler, we need
to set up some getters and setter to communicate with the database.


Client getter
`````````````

A client getter is required. It tells which client is sending the requests,
creating the getter with decorator::

    @oauth.clientgetter
    def load_client(client_key):
        return Client.query.filter_by(client_key=client_key).first()


Request token & verifier getters and setters
````````````````````````````````````````````

Request token & verifier getters and setters are required. They are used in the
authorization flow, implemented with decorators::

    @oauth.grantgetter
    def load_request_token(token):
        grant = RequestToken.query.filter_by(token=token).first()
        return grant

    @oauth.grantsetter
    def save_request_token(token, request):
        if oauth.realms:
            realms = ' '.join(request.realms)
        else:
            realms = None
        grant = RequestToken(
            token=token['oauth_token'],
            secret=token['oauth_token_secret'],
            client=request.client,
            redirect_uri=request.redirect_uri,
            _realms=realms,
        )
        db.session.add(grant)
        db.session.commit()
        return grant

    @oauth.verifiergetter
    def load_verifier(verifier, token):
        return RequestToken.query.filter_by(verifier=verifier, token=token).first()

    @oauth.verifiersetter
    def save_verifier(token, verifier, *args, **kwargs):
        tok = RequestToken.query.filter_by(token=token).first()
        tok.verifier = verifier['oauth_verifier']
        tok.user = get_current_user()
        db.session.add(tok)
        db.session.commit()
        return tok


In the sample code, there is a ``get_current_user`` method, that will return
the current user object, you should implement it yourself.

The ``token`` for ``grantsetter`` is a dict, that contains::

    {
        u'oauth_token': u'arandomstringoftoken',
        u'oauth_token_secret': u'arandomstringofsecret',
        u'oauth_authorized_realms': u'email address'
    }

And the ``verifier`` for ``verifiersetter`` is a dict too, it contains::

    {
        u'oauth_verifier': u'Gqm3id67MdkrASOCQIAlb3XODaPlun',
        u'oauth_token': u'eTYP46AJbhp8u4LE5QMjXeItRGGoAI',
        u'resource_owner_key': u'eTYP46AJbhp8u4LE5QMjXeItRGGoAI'
    }

Token getter and setter
```````````````````````

Token getter and setters are required. They are used in the authorization flow
and accessing resource flow. Implemented with decorators::

    @oauth.tokengetter
    def load_access_token(client_key, token, *args, **kwargs):
        t = AccessToken.query.filter_by(
                client_key=client_key, token=token).first()
        return t

    @oauth.tokensetter
    def save_access_token(token, request):
        tok = AccessToken(
            client=request.client,
            user=request.user,
            token=token['oauth_token'],
            secret=token['oauth_token_secret'],
            _realms=token['oauth_authorized_realms'],
        )
        db.session.add(tok)
        db.session.commit()

The setter receives ``token`` and ``request`` parameters. The ``token`` is a
dict, which contains::

    {
        u'oauth_token_secret': u'H1xGH4X1ZkRAulHHdLfdFm7NR350tr',
        u'oauth_token': u'aXNlKcjkVImnTfTKj8CgFpc1XRZr6P',
        u'oauth_authorized_realms': u'email'
    }

The ``request`` is an object, it contains at least a `user` and `client`
objects for current flow.


Timestamp and Nonce getter and setter
`````````````````````````````````````

Timestamp and Nonce getter and setter is required. They are used everywhere::

    @oauth.noncegetter
    def load_nonce(client_key, timestamp, nonce, request_token, access_token):
        return Nonce.query.filter_by(
            client_key=client_key, timestamp=timestamp, nonce=nonce,
            request_token=request_token, access_token=access_token,
        ).first()

    @oauth.noncesetter
    def save_nonce(client_key, timestamp, nonce, request_token, access_token):
        nonce = Nonce(
            client_key=client_key,
            timestamp=timestamp,
            nonce=nonce,
            request_token=request_token,
            access_token=access_token,
        )
        db.session.add(nonce)
        db.session.commit()
        return nonce

Request token handler
`````````````````````

Request token handler is a decorator for generating request token. You don't
need to do much::

    @app.route('/oauth/request_token')
    @oauth.request_token_handler
    def request_token():
        return {}

You can add more data on token response::

    @app.route('/oauth/request_token')
    @oauth.request_token_handler
    def request_token():
        return {'version': '0.1.0'}

Authorize handler
`````````````````

Authorize handler is a decorator for authorize endpoint. It is suggested
that you implemented it this way::

    @app.route('/oauth/authorize', methods=['GET', 'POST'])
    @require_login
    @oauth.authorize_handler
    def authorize(*args, **kwargs):
        if request.method == 'GET':
            client_key = kwargs.get('resource_owner_key')
            client = Client.query.filter_by(client_key=client_key).first()
            kwargs['client'] = client
            return render_template('authorize.html', **kwargs)
        confirm = request.form.get('confirm', 'no')
        return confirm == 'yes'

The GET request will render a page for user to confirm the grant, parameters
in kwargs are:

- resource_owner_key: same as client_key
- realms: realms that this client requests

The POST request needs to return a bool value that tells whether user grantted
the access or not.

Access token handler
````````````````````

Access token handler is a decorator for exchange access token. Client will
request an access token with a request token. You don't need to do much::

    @app.route('/oauth/access_token')
    @oauth.access_token_handler
    def access_token():
        return {}

Just like request token handler, you can add more data in access token.

Protect Resource
----------------

Protect the resource of a user with ``require_oauth`` decorator now::

    @app.route('/api/me')
    @oauth.require_oauth('email')
    def me():
        user = request.oauth.user
        return jsonify(email=user.email, username=user.username)

    @app.route('/api/user/<username>')
    @oauth.require_oauth('email')
    def user(username):
        user = User.query.filter_by(username=username).first()
        return jsonify(email=user.email, username=user.username)

The decorator accepts a list of realms, only the clients with the given realms
can access the defined resources.

.. versionchanged:: 0.5.0

The ``request`` has an additional property ``oauth``, it contains at least:

- client: client model object
- realms: a list of scopes
- user: user model object
- headers: headers of the request
- body: body content of the request


Example for OAuth 1
-------------------

Here is an example of OAuth 1 server: https://github.com/lepture/example-oauth1-server

Also read this article http://lepture.com/en/2013/create-oauth-server.
