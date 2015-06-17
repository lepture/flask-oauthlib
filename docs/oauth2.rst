.. _oauth2:

OAuth2 Server
=============

An OAuth2 server concerns how to grant the authorization and how to protect
the resource. Register an **OAuth** provider::

    from flask_oauthlib.provider import OAuth2Provider

    app = Flask(__name__)
    oauth = OAuth2Provider(app)

Like any other Flask extensions, we can pass the application later::

    oauth = OAuth2Provider()

    def create_app():
        app = Flask(__name__)
        oauth.init_app(app)
        return app

To implement the authorization flow, we need to understand the data model.

User (Resource Owner)
---------------------

A user, or resource owner, is usually the registered user on your site. You
design your own user model, there is not much to say.

Client (Application)
---------------------

A client is the app which want to use the resource of a user. It is suggested
that the client is registered by a user on your site, but it is not required.

The client should contain at least these properties:

- client_id: A random string
- client_secret: A random string
- client_type: A string represents if it is `confidential`
- redirect_uris: A list of redirect uris
- default_redirect_uri: One of the redirect uris
- default_scopes: Default scopes of the client

But it could be better, if you implemented:

- allowed_grant_types: A list of grant types
- allowed_response_types: A list of response types
- validate_scopes: A function to validate scopes

.. note::

    The value of the scope parameter is expressed as a list of space-
    delimited, case-sensitive strings.

    via: http://tools.ietf.org/html/rfc6749#section-3.3

An example of the data model in SQLAlchemy (SQLAlchemy is not required)::

    class Client(db.Model):
        # human readable name, not required
        name = db.Column(db.String(40))

        # human readable description, not required
        description = db.Column(db.String(400))

        # creator of the client, not required
        user_id = db.Column(db.ForeignKey('user.id'))
        # required if you need to support client credential
        user = db.relationship('User')

        client_id = db.Column(db.String(40), primary_key=True)
        client_secret = db.Column(db.String(55), unique=True, index=True,
                                  nullable=False)

        # public or confidential
        is_confidential = db.Column(db.Boolean)

        _redirect_uris = db.Column(db.Text)
        _default_scopes = db.Column(db.Text)

        @property
        def client_type(self):
            if self.is_confidential:
                return 'confidential'
            return 'public'

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
-----------

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
        user = db.relationship('User')

        client_id = db.Column(
            db.String(40), db.ForeignKey('client.client_id'),
            nullable=False,
        )
        client = db.relationship('Client')

        code = db.Column(db.String(255), index=True, nullable=False)

        redirect_uri = db.Column(db.String(255))
        expires = db.Column(db.DateTime)

        _scopes = db.Column(db.Text)

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
------------

A bearer token is the final token that could be used by the client. There
are other token types, but bearer token is widely used. Flask-OAuthlib only
comes with bearer token.

A bearer token requires at least these information:

- access_token: A string token
- refresh_token: A string token
- client_id: ID of the client
- scopes: A list of scopes
- expires: A `datetime.datetime` object
- user: The user object
- delete: A function to delete itself

An example of the data model in SQLAlchemy::

    class Token(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        client_id = db.Column(
            db.String(40), db.ForeignKey('client.client_id'),
            nullable=False,
        )
        client = db.relationship('Client')

        user_id = db.Column(
            db.Integer, db.ForeignKey('user.id')
        )
        user = db.relationship('User')

        # currently only bearer is supported
        token_type = db.Column(db.String(40))

        access_token = db.Column(db.String(255), unique=True)
        refresh_token = db.Column(db.String(255), unique=True)
        expires = db.Column(db.DateTime)
        _scopes = db.Column(db.Text)

        def delete(self):
            db.session.delete(self)
            db.session.commit()
            return self

        @property
        def scopes(self):
            if self._scopes:
                return self._scopes.split()
            return []


Configuration
-------------

The oauth provider has some built-in defaults, you can change them with Flask
config:

================================== ==========================================
`OAUTH2_PROVIDER_ERROR_URI`        The error page when there is an error,
                                   default value is ``'/oauth/errors'``.
`OAUTH2_PROVIDER_ERROR_ENDPOINT`   You can also configure the error page uri
                                   with an endpoint name.
`OAUTH2_PROVIDER_TOKEN_EXPIRES_IN` Default Bearer token expires time, default
                                   is ``3600``.
================================== ==========================================


Implementation
--------------

The implementation of authorization flow needs two handlers, one is the authorization
handler for the user to confirm the grant, the other is the token handler for the client
to exchange/refresh access tokens.

Before the implementing of authorize and token handler, we need to set up some
getters and setters to communicate with the database.

Client getter
`````````````

A client getter is required. It tells which client is sending the requests,
creating the getter with decorator::

    @oauth.clientgetter
    def load_client(client_id):
        return Client.query.filter_by(client_id=client_id).first()


Grant getter and setter
```````````````````````

Grant getter and setter are required. They are used in the authorization flow,
implemented with decorators::

    from datetime import datetime, timedelta

    @oauth.grantgetter
    def load_grant(client_id, code):
        return Grant.query.filter_by(client_id=client_id, code=code).first()

    @oauth.grantsetter
    def save_grant(client_id, code, request, *args, **kwargs):
        # decide the expires time yourself
        expires = datetime.utcnow() + timedelta(seconds=100)
        grant = Grant(
            client_id=client_id,
            code=code['code'],
            redirect_uri=request.redirect_uri,
            _scopes=' '.join(request.scopes),
            user=get_current_user(),
            expires=expires
        )
        db.session.add(grant)
        db.session.commit()
        return grant


In the sample code, there is a ``get_current_user`` method, that will return
the current user object, you should implement it yourself.

The ``request`` object is defined by ``OAuthlib``, you can get at least this much
information:

- client: client model object
- scopes: a list of scopes
- user: user model object
- redirect_uri: redirect_uri parameter
- headers: headers of the request
- body: body content of the request
- state: state parameter
- response_type: response_type paramter

Token getter and setter
```````````````````````

Token getter and setter are required. They are used in the authorization flow
and accessing resource flow. They are implemented with decorators as follows::

    @oauth.tokengetter
    def load_token(access_token=None, refresh_token=None):
        if access_token:
            return Token.query.filter_by(access_token=access_token).first()
        elif refresh_token:
            return Token.query.filter_by(refresh_token=refresh_token).first()

    from datetime import datetime, timedelta

    @oauth.tokensetter
    def save_token(token, request, *args, **kwargs):
        toks = Token.query.filter_by(client_id=request.client.client_id,
                                     user_id=request.user.id)
        # make sure that every client has only one token connected to a user
        for t in toks:
            db.session.delete(t)

        expires_in = token.get('expires_in')
        expires = datetime.utcnow() + timedelta(seconds=expires_in)

        tok = Token(
            access_token=token['access_token'],
            refresh_token=token['refresh_token'],
            token_type=token['token_type'],
            _scopes=token['scope'],
            expires=expires,
            client_id=request.client.client_id,
            user_id=request.user.id,
        )
        db.session.add(tok)
        db.session.commit()
        return tok

The getter will receive two parameters, if you don't need to support refresh
token, you can just load token by access token.

The setter receives ``token`` and ``request`` parameters. The ``token`` is a
dict, which contains::

    {
        u'access_token': u'6JwgO77PApxsFCU8Quz0pnL9s23016',
        u'refresh_token': u'7cYSMmBg4T7F4kwoWfUQA99J8yqjp0',
        u'token_type': u'Bearer',
        u'expires_in': 3600,
        u'scope': u'email address'
    }

The ``request`` is an object like the one in grant setter.


User getter
```````````

User getter is optional. It is only required if you need password credential
authorization::

    @oauth.usergetter
    def get_user(username, password, *args, **kwargs):
        user = User.query.filter_by(username=username).first()
        if user.check_password(password):
            return user
        return None

Authorize handler
`````````````````

Authorize handler is a decorator for the authorize endpoint. It is suggested
that you implemented it this way::

        @app.route('/oauth/authorize', methods=['GET', 'POST'])
        @require_login
        @oauth.authorize_handler
        def authorize(*args, **kwargs):
            if request.method == 'GET':
                client_id = kwargs.get('client_id')
                client = Client.query.filter_by(client_id=client_id).first()
                kwargs['client'] = client
                return render_template('oauthorize.html', **kwargs)

            confirm = request.form.get('confirm', 'no')
            return confirm == 'yes'

The GET request will render a page for user to confirm the grant, parameters in
kwargs are:

- client_id: id of the client
- scopes: a list of scope
- state: state parameter
- redirect_uri: redirect_uri parameter
- response_type: response_type parameter

The POST request needs to return a bool value that tells whether user granted
access or not.

There is a ``@require_login`` decorator in the sample code, you should
implement it yourself.


Token handler
`````````````

Token handler is a decorator for exchanging/refreshing access token. You don't need
to do much::

    @app.route('/oauth/token')
    @oauth.token_handler
    def access_token():
        return None

You can add more data on the token response::

    @app.route('/oauth/token')
    @oauth.token_handler
    def access_token():
        return {'version': '0.1.0'}

Limit the HTTP method with Flask routes, for example, only POST is allowed for
exchange tokens::

    @app.route('/oauth/token', methods=['POST'])
    @oauth.token_handler
    def access_token():
        return None

The authorization flow is finished, everything should be working now.


.. admonition:: Note:

    This token endpoint is for access token and refresh token both. But please
    remember that refresh token is only available for confidential client,
    and only available in password credential.


Revoke handler
``````````````
In some cases a user may wish to revoke access given to an application and the
revoke handler makes it possible for an application to programmaticaly revoke
the access given to it. Also here you don't need to do much, allowing POST only
is recommended::

    @app.route('/oauth/revoke', methods=['POST'])
    @oauth.revoke_handler
    def revoke_token(): pass


Subclass way
````````````

If you are not satisfied with the decorator way of getters and setters, you can
implement them in the subclass way::

    class MyProvider(OAuth2Provider):
        def _clientgetter(self, client_id):
            return Client.query.filter_by(client_id=client_id).first()

        #: more getters and setters

Every getter and setter is started with ``_``.


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

The decorator accepts a list of scopes and only the clients with the given scopes
can access the defined resources.

.. versionchanged:: 0.5.0

The ``request`` has an additional property ``oauth``, it contains at least:

- client: client model object
- scopes: a list of scopes
- user: user model object
- redirect_uri: redirect_uri parameter
- headers: headers of the request
- body: body content of the request
- state: state parameter
- response_type: response_type paramter

Example for OAuth 2
-------------------

Here is an example of OAuth 2 server: https://github.com/lepture/example-oauth2-server

Also read this article http://lepture.com/en/2013/create-oauth-server.
