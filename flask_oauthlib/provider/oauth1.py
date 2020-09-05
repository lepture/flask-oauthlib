# coding: utf-8
"""
    flask_oauthlib.provider.oauth1
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Implemnts OAuth1 provider support for Flask.

    :copyright: (c) 2013 - 2014 by Hsiaoming Yang.
"""

import logging
from functools import wraps
from werkzeug.utils import cached_property
from flask import request, redirect, url_for
from flask import make_response, abort
from oauthlib.oauth1 import RequestValidator
from oauthlib.oauth1 import WebApplicationServer as Server
from oauthlib.oauth1 import SIGNATURE_HMAC, SIGNATURE_RSA
from oauthlib.common import to_unicode, add_params_to_uri, urlencode
from oauthlib.oauth1.rfc5849 import errors
from ..utils import extract_params, create_response

SIGNATURE_METHODS = (SIGNATURE_HMAC, SIGNATURE_RSA)

__all__ = ('OAuth1Provider', 'OAuth1RequestValidator')

log = logging.getLogger('flask_oauthlib')


class OAuth1Provider(object):
    """Provide secure services using OAuth1.

    Like many other Flask extensions, there are two usage modes. One is
    binding the Flask app instance::

        app = Flask(__name__)
        oauth = OAuth1Provider(app)

    The second possibility is to bind the Flask app later::

        oauth = OAuth1Provider()

        def create_app():
            app = Flask(__name__)
            oauth.init_app(app)
            return app

    And now you can protect the resource with realms::

        @app.route('/api/user')
        @oauth.require_oauth('email', 'username')
        def user():
            return jsonify(request.oauth.user)
    """

    def __init__(self, app=None):
        self._before_request_funcs = []
        self._after_request_funcs = []
        if app:
            self.init_app(app)

    def init_app(self, app):
        """
        This callback can be used to initialize an application for the
        oauth provider instance.
        """
        self.app = app
        app.extensions = getattr(app, 'extensions', {})
        app.extensions['oauthlib.provider.oauth1'] = self

    @cached_property
    def error_uri(self):
        """The error page URI.

        When something turns error, it will redirect to this error page.
        You can configure the error page URI with Flask config::

            OAUTH1_PROVIDER_ERROR_URI = '/error'

        You can also define the error page by a named endpoint::

            OAUTH1_PROVIDER_ERROR_ENDPOINT = 'oauth.error'
        """
        error_uri = self.app.config.get('OAUTH1_PROVIDER_ERROR_URI')
        if error_uri:
            return error_uri
        error_endpoint = self.app.config.get('OAUTH1_PROVIDER_ERROR_ENDPOINT')
        if error_endpoint:
            return url_for(error_endpoint)
        return '/oauth/errors'

    @cached_property
    def server(self):
        """
        All in one endpoints. This property is created automaticly
        if you have implemented all the getters and setters.
        """
        if hasattr(self, '_validator'):
            return Server(self._validator)

        if hasattr(self, '_clientgetter') and \
           hasattr(self, '_tokengetter') and \
           hasattr(self, '_tokensetter') and \
           hasattr(self, '_noncegetter') and \
           hasattr(self, '_noncesetter') and \
           hasattr(self, '_grantgetter') and \
           hasattr(self, '_grantsetter') and \
           hasattr(self, '_verifiergetter') and \
           hasattr(self, '_verifiersetter'):

            validator = OAuth1RequestValidator(
                clientgetter=self._clientgetter,
                tokengetter=self._tokengetter,
                tokensetter=self._tokensetter,
                grantgetter=self._grantgetter,
                grantsetter=self._grantsetter,
                noncegetter=self._noncegetter,
                noncesetter=self._noncesetter,
                verifiergetter=self._verifiergetter,
                verifiersetter=self._verifiersetter,
                config=self.app.config,
            )

            self._validator = validator
            server = Server(validator)
            if self.app.testing:
                # It will always be false, since the redirect_uri
                # didn't match when doing the testing
                server._check_signature = lambda *args, **kwargs: True
            return server
        raise RuntimeError(
            'application not bound to required getters and setters'
        )

    def before_request(self, f):
        """Register functions to be invoked before accessing the resource.

        The function accepts nothing as parameters, but you can get
        information from `Flask.request` object. It is usually useful
        for setting limitation on the client request::

            @oauth.before_request
            def limit_client_request():
                client_key = request.values.get('client_key')
                if not client_key:
                    return
                client = Client.get(client_key)
                if over_limit(client):
                    return abort(403)

                track_request(client)
        """
        self._before_request_funcs.append(f)
        return f

    def after_request(self, f):
        """Register functions to be invoked after accessing the resource.

        The function accepts ``valid`` and ``request`` as parameters,
        and it should return a tuple of them::

            @oauth.after_request
            def valid_after_request(valid, oauth):
                if oauth.user in black_list:
                    return False, oauth
                return valid, oauth
        """
        self._after_request_funcs.append(f)
        return f

    def clientgetter(self, f):
        """Register a function as the client getter.

        The function accepts one parameter `client_key`, and it returns
        a client object with at least these information:

            - client_key: A random string
            - client_secret: A random string
            - redirect_uris: A list of redirect uris
            - default_realms: Default scopes of the client

        The client may contain more information, which is suggested:

            - default_redirect_uri: One of the redirect uris

        Implement the client getter::

            @oauth.clientgetter
            def get_client(client_key):
                client = get_client_model(client_key)
                # Client is an object
                return client
        """
        self._clientgetter = f
        return f

    def tokengetter(self, f):
        """Register a function as the access token getter.

        The function accepts `client_key` and `token` parameters, and it
        returns an access token object contains:

            - client: Client associated with this token
            - user: User associated with this token
            - token: Access token
            - secret: Access token secret
            - realms: Realms with this access token

        Implement the token getter::

            @oauth.tokengetter
            def get_access_token(client_key, token):
                return AccessToken.get(client_key=client_key, token=token)
        """
        self._tokengetter = f
        return f

    def tokensetter(self, f):
        """Register a function as the access token setter.

        The setter accepts two parameters at least, one is token,
        the other is request::

            @oauth.tokensetter
            def save_access_token(token, request):
                access_token = AccessToken(
                    client=request.client,
                    user=request.user,
                    token=token['oauth_token'],
                    secret=token['oauth_token_secret'],
                    realms=token['oauth_authorized_realms'].split(' '),
                )
                return access_token.save()

        The parameter token is a dict, that looks like::

            {
                u'oauth_token': u'arandomstringoftoken',
                u'oauth_token_secret': u'arandomstringofsecret',
                u'oauth_authorized_realms': u'email address'
            }

        The `request` object would provide these information (at least)::

            - client: Client object associated with this token
            - user: User object associated with this token
            - request_token: Requst token for exchanging this access token
        """
        self._tokensetter = f
        return f

    def grantgetter(self, f):
        """Register a function as the request token getter.

        The function accepts a `token` parameter, and it returns an
        request token object contains:

            - client: Client associated with this token
            - token: Access token
            - secret: Access token secret
            - realms: Realms with this access token
            - redirect_uri: A URI for redirecting

        Implement the token getter::

            @oauth.tokengetter
            def get_request_token(token):
                return RequestToken.get(token=token)
        """
        self._grantgetter = f
        return f

    def grantsetter(self, f):
        """Register a function as the request token setter.

        The setter accepts a token and request parameters::

            @oauth.grantsetter
            def save_request_token(token, request):
                data = RequestToken(
                    token=token['oauth_token'],
                    secret=token['oauth_token_secret'],
                    client=request.client,
                    redirect_uri=oauth.redirect_uri,
                    realms=request.realms,
                )
                return data.save()
        """
        self._grantsetter = f
        return f

    def noncegetter(self, f):
        """Register a function as the nonce and timestamp getter.

        The function accepts parameters:

            - client_key: The client/consure key
            - timestamp: The ``oauth_timestamp`` parameter
            - nonce: The ``oauth_nonce`` parameter
            - request_token: Request token string, if any
            - access_token: Access token string, if any

        A nonce and timestamp make each request unique. The implementation::

            @oauth.noncegetter
            def get_nonce(client_key, timestamp, nonce, request_token,
                          access_token):
                return Nonce.get("...")
        """
        self._noncegetter = f
        return f

    def noncesetter(self, f):
        """Register a function as the nonce and timestamp setter.

        The parameters are the same with :meth:`noncegetter`::

            @oauth.noncegetter
            def save_nonce(client_key, timestamp, nonce, request_token,
                           access_token):
                data = Nonce("...")
                return data.save()

        The timestamp will be expired in 60s, it would be a better design
        if you put timestamp and nonce object in a cache.
        """
        self._noncesetter = f
        return f

    def verifiergetter(self, f):
        """Register a function as the verifier getter.

        The return verifier object should at least contain a user object
        which is the current user.

        The implemented code looks like::

            @oauth.verifiergetter
            def load_verifier(verifier, token):
                data = Verifier.get(verifier)
                if data.request_token == token:
                    # check verifier for safety
                    return data
                return data
        """
        self._verifiergetter = f
        return f

    def verifiersetter(self, f):
        """Register a function as the verifier setter.

        A verifier is better together with request token, but it is not
        required. A verifier is used together with request token for
        exchanging access token, it has an expire time, in this case, it
        would be a better design if you put them in a cache.

        The implemented code looks like::

            @oauth.verifiersetter
            def save_verifier(verifier, token, *args, **kwargs):
                data = Verifier(
                    verifier=verifier['oauth_verifier'],
                    request_token=token,
                    user=get_current_user()
                )
                return data.save()
        """
        self._verifiersetter = f
        return f

    def authorize_handler(self, f):
        """Authorization handler decorator.

        This decorator will sort the parameters and headers out, and
        pre validate everything::

            @app.route('/oauth/authorize', methods=['GET', 'POST'])
            @oauth.authorize_handler
            def authorize(*args, **kwargs):
                if request.method == 'GET':
                    # render a page for user to confirm the authorization
                    return render_template('oauthorize.html')

                confirm = request.form.get('confirm', 'no')
                return confirm == 'yes'
        """
        @wraps(f)
        def decorated(*args, **kwargs):
            if request.method == 'POST':
                if not f(*args, **kwargs):
                    uri = add_params_to_uri(
                        self.error_uri, [('error', 'denied')]
                    )
                    return redirect(uri)
                return self.confirm_authorization_request()

            server = self.server

            uri, http_method, body, headers = extract_params()
            try:
                realms, credentials = server.get_realms_and_credentials(
                    uri, http_method=http_method, body=body, headers=headers
                )
                kwargs['realms'] = realms
                kwargs.update(credentials)
                return f(*args, **kwargs)
            except errors.OAuth1Error as e:
                return redirect(e.in_uri(self.error_uri))
            except errors.InvalidClientError as e:
                return redirect(e.in_uri(self.error_uri))
        return decorated

    def confirm_authorization_request(self):
        """When consumer confirm the authrozation."""
        server = self.server

        uri, http_method, body, headers = extract_params()
        try:
            realms, credentials = server.get_realms_and_credentials(
                uri, http_method=http_method, body=body, headers=headers
            )
            ret = server.create_authorization_response(
                uri, http_method, body, headers, realms, credentials
            )
            log.debug('Authorization successful.')
            return create_response(*ret)
        except errors.OAuth1Error as e:
            return redirect(e.in_uri(self.error_uri))
        except errors.InvalidClientError as e:
            return redirect(e.in_uri(self.error_uri))

    def request_token_handler(self, f):
        """Request token handler decorator.

        The decorated function should return an dictionary or None as
        the extra credentials for creating the token response.

        If you don't need to add any extra credentials, it could be as
        simple as::

            @app.route('/oauth/request_token')
            @oauth.request_token_handler
            def request_token():
                return {}
        """
        @wraps(f)
        def decorated(*args, **kwargs):
            server = self.server
            uri, http_method, body, headers = extract_params()
            credentials = f(*args, **kwargs)
            try:
                ret = server.create_request_token_response(
                    uri, http_method, body, headers, credentials)
                return create_response(*ret)
            except errors.OAuth1Error as e:
                return _error_response(e)
        return decorated

    def access_token_handler(self, f):
        """Access token handler decorator.

        The decorated function should return an dictionary or None as
        the extra credentials for creating the token response.

        If you don't need to add any extra credentials, it could be as
        simple as::

            @app.route('/oauth/access_token')
            @oauth.access_token_handler
            def access_token():
                return {}
        """
        @wraps(f)
        def decorated(*args, **kwargs):
            server = self.server
            uri, http_method, body, headers = extract_params()
            credentials = f(*args, **kwargs)
            try:
                ret = server.create_access_token_response(
                    uri, http_method, body, headers, credentials)
                return create_response(*ret)
            except errors.OAuth1Error as e:
                return _error_response(e)
        return decorated

    def require_oauth(self, *realms, **kwargs):
        """Protect resource with specified scopes."""
        def wrapper(f):
            @wraps(f)
            def decorated(*args, **kwargs):
                for func in self._before_request_funcs:
                    func()

                if hasattr(request, 'oauth') and request.oauth:
                    return f(*args, **kwargs)

                server = self.server
                uri, http_method, body, headers = extract_params()
                try:
                    valid, req = server.validate_protected_resource_request(
                        uri, http_method, body, headers, realms
                    )
                except Exception as e:
                    log.warn('Exception: %r', e)
                    e.urlencoded = urlencode([('error', 'unknown')])
                    e.status_code = 400
                    return _error_response(e)
                for func in self._after_request_funcs:
                    valid, req = func(valid, req)

                if not valid:
                    return abort(401)
                # alias user for convenience
                req.user = req.access_token.user
                request.oauth = req
                return f(*args, **kwargs)
            return decorated
        return wrapper


class OAuth1RequestValidator(RequestValidator):
    """Subclass of Request Validator.

    :param clientgetter: a function to get client object
    :param tokengetter: a function to get access token
    :param tokensetter: a function to save access token
    :param grantgetter: a function to get request token
    :param grantsetter: a function to save request token
    :param noncegetter: a function to get nonce and timestamp
    :param noncesetter: a function to save nonce and timestamp
    """

    def __init__(self, clientgetter, tokengetter, tokensetter,
                 grantgetter, grantsetter, noncegetter, noncesetter,
                 verifiergetter, verifiersetter, config=None):
        self._clientgetter = clientgetter

        # access token getter and setter
        self._tokengetter = tokengetter
        self._tokensetter = tokensetter

        # request token getter and setter
        self._grantgetter = grantgetter
        self._grantsetter = grantsetter

        # nonce and timestamp
        self._noncegetter = noncegetter
        self._noncesetter = noncesetter

        # verifier getter and setter
        self._verifiergetter = verifiergetter
        self._verifiersetter = verifiersetter

        self._config = config or {}

    @property
    def allowed_signature_methods(self):
        """Allowed signature methods.

        Default value: SIGNATURE_HMAC and SIGNATURE_RSA.

        You can customize with Flask Config:

            - OAUTH1_PROVIDER_SIGNATURE_METHODS
        """
        return self._config.get(
            'OAUTH1_PROVIDER_SIGNATURE_METHODS',
            SIGNATURE_METHODS,
        )

    @property
    def client_key_length(self):
        return self._config.get(
            'OAUTH1_PROVIDER_KEY_LENGTH',
            (20, 30)
        )

    @property
    def request_token_length(self):
        return self._config.get(
            'OAUTH1_PROVIDER_KEY_LENGTH',
            (20, 30)
        )

    @property
    def access_token_length(self):
        return self._config.get(
            'OAUTH1_PROVIDER_KEY_LENGTH',
            (20, 30)
        )

    @property
    def nonce_length(self):
        return self._config.get(
            'OAUTH1_PROVIDER_KEY_LENGTH',
            (20, 30)
        )

    @property
    def verifier_length(self):
        return self._config.get(
            'OAUTH1_PROVIDER_KEY_LENGTH',
            (20, 30)
        )

    @property
    def realms(self):
        return self._config.get('OAUTH1_PROVIDER_REALMS', [])

    @property
    def enforce_ssl(self):
        """Enforce SSL request.

        Default is True. You can customize with:

            - OAUTH1_PROVIDER_ENFORCE_SSL
        """
        return self._config.get('OAUTH1_PROVIDER_ENFORCE_SSL', True)

    @property
    def dummy_client(self):
        return to_unicode('dummy_client', 'utf-8')

    @property
    def dummy_request_token(self):
        return to_unicode('dummy_request_token', 'utf-8')

    @property
    def dummy_access_token(self):
        return to_unicode('dummy_access_token', 'utf-8')

    def get_client_secret(self, client_key, request):
        """Get client secret.

        The client object must has ``client_secret`` attribute.
        """
        log.debug('Get client secret of %r', client_key)
        if not request.client:
            request.client = self._clientgetter(client_key=client_key)
        if request.client:
            return request.client.client_secret
        return None

    def get_request_token_secret(self, client_key, token, request):
        """Get request token secret.

        The request token object should a ``secret`` attribute.
        """
        log.debug('Get request token secret of %r for %r',
                  token, client_key)
        tok = request.request_token or self._grantgetter(token=token)
        if tok and tok.client_key == client_key:
            request.request_token = tok
            return tok.secret
        return None

    def get_access_token_secret(self, client_key, token, request):
        """Get access token secret.

        The access token object should a ``secret`` attribute.
        """
        log.debug('Get access token secret of %r for %r',
                  token, client_key)
        tok = request.access_token or self._tokengetter(
            client_key=client_key,
            token=token,
        )
        if tok:
            request.access_token = tok
            return tok.secret
        return None

    def get_default_realms(self, client_key, request):
        """Default realms of the client."""
        log.debug('Get realms for %r', client_key)

        if not request.client:
            request.client = self._clientgetter(client_key=client_key)

        client = request.client
        if hasattr(client, 'default_realms'):
            return client.default_realms
        return []

    def get_realms(self, token, request):
        """Realms for this request token."""
        log.debug('Get realms of %r', token)
        tok = request.request_token or self._grantgetter(token=token)
        if not tok:
            return []
        request.request_token = tok
        if hasattr(tok, 'realms'):
            return tok.realms or []
        return []

    def get_redirect_uri(self, token, request):
        """Redirect uri for this request token."""
        log.debug('Get redirect uri of %r', token)
        tok = request.request_token or self._grantgetter(token=token)
        return tok.redirect_uri

    def get_rsa_key(self, client_key, request):
        """Retrieves a previously stored client provided RSA key."""
        if not request.client:
            request.client = self._clientgetter(client_key=client_key)
        if hasattr(request.client, 'rsa_key'):
            return request.client.rsa_key
        return None

    def invalidate_request_token(self, client_key, request_token, request):
        """Invalidates a used request token."""
        # TODO

    def validate_client_key(self, client_key, request):
        """Validates that supplied client key."""
        log.debug('Validate client key for %r', client_key)
        if not request.client:
            request.client = self._clientgetter(client_key=client_key)
        if request.client:
            return True
        return False

    def validate_request_token(self, client_key, token, request):
        """Validates request token is available for client."""
        log.debug('Validate request token %r for %r',
                  token, client_key)
        tok = request.request_token or self._grantgetter(token=token)
        if tok and tok.client_key == client_key:
            request.request_token = tok
            return True
        return False

    def validate_access_token(self, client_key, token, request):
        """Validates access token is available for client."""
        log.debug('Validate access token %r for %r',
                  token, client_key)
        tok = request.access_token or self._tokengetter(
            client_key=client_key,
            token=token,
        )
        if tok:
            request.access_token = tok
            return True
        return False

    def validate_timestamp_and_nonce(self, client_key, timestamp, nonce,
                                     request, request_token=None,
                                     access_token=None):
        """Validate the timestamp and nonce is used or not."""
        log.debug('Validate timestamp and nonce %r', client_key)
        nonce_exists = self._noncegetter(
            client_key=client_key, timestamp=timestamp,
            nonce=nonce, request_token=request_token,
            access_token=access_token
        )
        if nonce_exists:
            return False
        self._noncesetter(
            client_key=client_key, timestamp=timestamp,
            nonce=nonce, request_token=request_token,
            access_token=access_token
        )
        return True

    def validate_redirect_uri(self, client_key, redirect_uri, request):
        """Validate if the redirect_uri is allowed by the client."""
        log.debug('Validate redirect_uri %r for %r', redirect_uri, client_key)
        if not request.client:
            request.client = self._clientgetter(client_key=client_key)
        if not request.client:
            return False
        if not request.client.redirect_uris and redirect_uri is None:
            return True
        request.redirect_uri = redirect_uri
        return redirect_uri in request.client.redirect_uris

    def validate_requested_realms(self, client_key, realms, request):
        log.debug('Validate requested realms %r for %r', realms, client_key)
        if not request.client:
            request.client = self._clientgetter(client_key=client_key)

        client = request.client
        if not client:
            return False

        if hasattr(client, 'validate_realms'):
            return client.validate_realms(realms)
        if set(client.default_realms).issuperset(set(realms)):
            return True
        return True

    def validate_realms(self, client_key, token, request, uri=None,
                        realms=None):
        """Check if the token has permission on those realms."""
        log.debug('Validate realms %r for %r', realms, client_key)
        if request.access_token:
            tok = request.access_token
        else:
            tok = self._tokengetter(client_key=client_key, token=token)
            request.access_token = tok
        if not tok:
            return False
        return set(tok.realms).issuperset(set(realms))

    def validate_verifier(self, client_key, token, verifier, request):
        """Validate verifier exists."""
        log.debug('Validate verifier %r for %r', verifier, client_key)
        data = self._verifiergetter(verifier=verifier, token=token)
        if not data:
            return False
        if not hasattr(data, 'user'):
            log.debug('Verifier should has user attribute')
            return False
        request.user = data.user
        if hasattr(data, 'client_key'):
            return data.client_key == client_key
        return True

    def verify_request_token(self, token, request):
        """Verify if the request token is existed."""
        log.debug('Verify request token %r', token)
        tok = request.request_token or self._grantgetter(token=token)
        if tok:
            request.request_token = tok
            return True
        return False

    def verify_realms(self, token, realms, request):
        """Verify if the realms match the requested realms."""
        log.debug('Verify realms %r', realms)
        tok = request.request_token or self._grantgetter(token=token)
        if not tok:
            return False

        request.request_token = tok
        if not hasattr(tok, 'realms'):
            # realms not enabled
            return True
        return set(tok.realms) == set(realms)

    def save_access_token(self, token, request):
        """Save access token to database.

        A tokensetter is required, which accepts a token and request
        parameters::

            def tokensetter(token, request):
                access_token = Token(
                    client=request.client,
                    user=request.user,
                    token=token['oauth_token'],
                    secret=token['oauth_token_secret'],
                    realms=token['oauth_authorized_realms'],
                )
                return access_token.save()
        """
        log.debug('Save access token %r', token)
        self._tokensetter(token, request)

    def save_request_token(self, token, request):
        """Save request token to database.

        A grantsetter is required, which accepts a token and request
        parameters::

            def grantsetter(token, request):
                grant = Grant(
                    token=token['oauth_token'],
                    secret=token['oauth_token_secret'],
                    client=request.client,
                    redirect_uri=oauth.redirect_uri,
                    realms=request.realms,
                )
                return grant.save()
        """
        log.debug('Save request token %r', token)
        self._grantsetter(token, request)

    def save_verifier(self, token, verifier, request):
        """Save verifier to database.

        A verifiersetter is required. It would be better to combine request
        token and verifier together::

            def verifiersetter(token, verifier, request):
                tok = Grant.query.filter_by(token=token).first()
                tok.verifier = verifier['oauth_verifier']
                tok.user = get_current_user()
                return tok.save()

        .. admonition:: Note:

            A user is required on verifier, remember to attach current
            user to verifier.
        """
        log.debug('Save verifier %r for %r', verifier, token)
        self._verifiersetter(
            token=token, verifier=verifier, request=request
        )


def _error_response(e):
    res = make_response(e.urlencoded, e.status_code)
    res.headers['Content-Type'] = 'application/x-www-form-urlencoded'
    return res
