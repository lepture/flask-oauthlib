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

To implemente the oauthorization flow, we need to understand the data model.

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
- validate_scopes: A function to validate scopes

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

        client_id = db.Column(db.Unicode(40), primary_key=True)
        client_secret = db.Column(db.Unicode(55), unique=True, index=True,
                                  nullable=False)

        # public or confidential
        is_confidential = db.Column(db.Boolean)

        _redirect_uris = db.Column(db.UnicodeText)
        _default_scopes = db.Column(db.UnicodeText)

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

        access_token = db.Column(db.Unicode(255), unique=True)
        refresh_token = db.Column(db.Unicode(255), unique=True)
        expires = db.Column(db.DateTime)
        _scopes = db.Column(db.UnicodeText)

        @property
        def scopes(self):
            if self._scopes:
                return self._scopes.split()
            return []


Configuration
~~~~~~~~~~~~~

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


Implements
~~~~~~~~~~

The implementings of authorization flow needs two handlers, one is authorize
handler for user to confirm the grant, the other is token handler for client
to exchange/refresh access token.

Before the implementing of authorize and token handler, we need to set up some
getters and setter to communicate with the database.

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

The ``request`` object is defined by ``OAuthlib``, you can get at least these
information:

- client: client model object
- scopes: a list of scopes
- user: user model object
- redirect_uri: rediret_uri parameter
- headers: headers of the request
- body: body content of the request
- state: state parameter
- response_type: response_type paramter

Token getter and setter
```````````````````````

Token getter and setters are required. They are used in the authorization flow
and accessing resource flow. Implemented with decorators::

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
        db.session.delete(toks)

        expires_in = token.pop('expires_in')
        expires = datetime.utcnow() + timedelta(seconds=expires_in)

        tok = Token(**token)
        tok.expires = expires
        tok.client_id = request.client.client_id
        tok.user_id = request.user.id
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

The POST request needs to return a bool value that tells whether user grantted
the access or not.

There is a ``@require_login`` decorator in the sample code, you should
implement it yourself.


Token handler
`````````````

Token handler is a decorator for exchange/refresh access token. You don't need
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


Subclass way
````````````

If you are not satisfied with the decorator way of getters and setters, you can
implements them in the subclass way::

    class MyProvider(OAuth2Provider):
        def _clientgetter(self, client_id):
            return Client.query.filter_by(client_id=client_id).first()

        #: more getters and setters

Every getter and setter is started with ``_``.


Protect Resource
~~~~~~~~~~~~~~~~

Protect the resource of a user with ``require_oauth`` decorator now::

    @app.route('/api/me')
    @oauth.require_oauth('email')
    def me(request):
        user = request.user
        return jsonify(email=user.email, username=user.username)

    @app.route('/api/user/<username>')
    @oauth.require_oauth('email')
    def user(request, username):
        user = User.query.filter_by(username=username).first()
        return jsonify(email=user.email, username=user.username)

The decorator accepts a list of scopes, only the clients with the given scopes
can access the defined resources.

The handlers accepts an extended parameter ``request``, as we have explained
above, it contains at least:

- client: client model object
- scopes: a list of scopes
- user: user model object
- redirect_uri: rediret_uri parameter
- headers: headers of the request
- body: body content of the request
- state: state parameter
- response_type: response_type paramter

You may find the name confused, since Flask has a ``request`` model, you can
rename it to other names, for exmaple::

    @app.route('/api/me')
    @oauth.require_oauth('email', 'username')
    def me(data):
        user = data.user
        return jsonify(email=user.email, username=user.username)
