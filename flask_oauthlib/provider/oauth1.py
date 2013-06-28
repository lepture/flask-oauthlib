# coding: utf-8
"""
    flask_oauthlib.provider.oauth1
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Implemnts OAuth1 provider support for Flask.

    :copyright: (c) 2013 by Hsiaoming Yang.
"""

from functools import wraps
from werkzeug import cached_property
from flask import request, redirect
from flask import make_response, abort
from oauthlib.oauth1 import RequestValidator
from oauthlib.oauth1 import WebApplicationServer as Server
from oauthlib.oauth1 import SIGNATURE_HMAC, SIGNATURE_RSA
from oauthlib.common import to_unicode, add_params_to_uri
from oauthlib.oauth1.rfc5849.errors import OAuth1Error
from .._utils import log, _extract_params

SIGNATURE_METHODS = (SIGNATURE_HMAC, SIGNATURE_RSA)

__all__ = ('OAuth1Provider', 'OAuth1RequestValidator')


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

    And now you can protect the resource with realm::

        @app.route('/api/user')
        @oauth.require_oauth('email', 'username')
        def user():
            return jsonify(g.user)
    """

    def __init__(self, app=None):
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
           hasattr(self, '_grantsetter'):
            validator = OAuth1RequestValidator(
                clientgetter=self._clientgetter,
                tokengetter=self._tokengetter,
                tokensetter=self._tokensetter,
                grantgetter=self._grantgetter,
                grantsetter=self._grantsetter,
                noncegetter=self._noncegetter,
                noncesetter=self._noncesetter,
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

    def clientgetter(self, f):
        """Register a function as the client getter.

        The function accepts one parameter `client_key`, and it returns
        a client object with at least these information:

            - client_key: A random string
            - client_secret: A random string
            - redirect_uris: A list of redirect uris
            - realms: Default scopes of the client

        The client may contain more information, which is suggested:

            - default_redirect_uri: One of the redirect uris
            - default_realms: Certain default realms

        Implement the client getter::

            @oauth.clientgetter
            def get_client(client_key):
                client = get_client_model(client_key)
                # Client is an object
                return client
        """
        self._clientgetter = f

    def tokengetter(self, f):
        self._tokengetter = f

    def tokensetter(self, f):
        self._tokensetter = f

    def grantgetter(self, f):
        self._grantgetter = f

    def grantsetter(self, f):
        self._grantsetter = f

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
                return get_nonce_from_database("...")
        """
        self._noncegetter = f

    def noncesetter(self, f):
        """Register a function as the nonce and timestamp setter.

        The parameters are the same with :meth:`noncegetter`::

            @oauth.noncegetter
            def save_nonce(client_key, timestamp, nonce, request_token,
                           access_token):
                return save_to_database("...")
        """
        self._noncesetter = f

    def authorize_handler(self, f):
        """Authorization handler decorator."""
        @wraps(f)
        def decorated(*args, **kwargs):
            server = self.server

            uri, http_method, body, headers = _extract_params()
            realms, credentials = server.get_realms_and_credentials(
                uri, http_method=http_method, body=body, headers=headers
            )

            if request.method == 'GET':
                kwargs['realms'] = realms
                kwargs.update(credentials)
                return f(*args, **kwargs)

            if request.method == 'POST':
                if not f(*args, **kwargs):
                    uri = add_params_to_uri(
                        self.error_uri, [('error', 'denied')]
                    )
                    return redirect(uri)
                return self.confirm_authorization_request()
        return decorated

    def confirm_authorization_request(self):
        """When consumer confirm the authrozation."""
        server = self.server

        # TODO
        realms = []
        credentials = {}
        uri, http_method, body, headers = _extract_params()
        try:
            ret = server.create_authorization_response(
                uri, http_method, body, headers, realms, credentials)
            log.debug('Authorization successful.')
            return redirect(ret[0])
        except OAuth1Error as e:
            redirect_uri = request.values.get('redirect_uri', None)
            return redirect(e.in_uri(redirect_uri))

    def request_token_handler(self, f):
        """Request token decorator."""
        @wraps(f)
        def decorated(*args, **kwargs):
            server = self.server
            uri, http_method, body, headers = _extract_params()
            credentials = f(*args, **kwargs)
            try:
                ret = server.create_request_token_response(
                    uri, http_method, body, headers, credentials)
                uri, headers, body, status = ret
                response = make_response(body or '', status)
                for k, v in headers.items():
                    response.headers[k] = v
                return response
            except OAuth1Error as e:
                return _error_response(e)
        return decorated

    def access_token_handler(self, f):
        """Access token decorator."""
        @wraps(f)
        def decorated(*args, **kwargs):
            server = self.server
            uri, http_method, body, headers = _extract_params()
            credentials = f(*args, **kwargs)
            try:
                ret = server.create_access_token_response(
                    uri, http_method, body, headers, credentials)
                uri, headers, body, status = ret
                response = make_response(body or '', status)
                for k, v in headers.items():
                    response.headers[k] = v
                return response
            except OAuth1Error as e:
                return _error_response(e)
        return decorated

    def require_oauth(self, *realms, **kwargs):
        """Protect resource with specified scopes."""
        def wrapper(f):
            @wraps(f)
            def decorated(*args, **kwargs):
                server = self.server
                uri, http_method, body, headers = _extract_params()
                valid, req = server.verify_request(
                    uri, http_method, body, headers
                )
                if not valid:
                    return abort(403)
                return f(*((req,) + args), **kwargs)
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
                 config=None):
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
    def reqeust_token_length(self):
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
    def dummy_resource_owner(self):
        return to_unicode('dummy_resource_owner', 'utf-8')

    @property
    def dummy_request_token(self):
        return to_unicode('dummy_request_token', 'utf-8')

    def get_client_secret(self, client_key, request):
        log.debug('Get client secret of %r', client_key)
        if not request.client:
            request.client = self._clientgetter(client_key=client_key)
        if request.client:
            return request.client.client_secret
        return None

    def get_request_token_secret(self, client_key, token, request):
        log.debug('Get request token secret of %r for %r',
                  token, client_key)
        tok = request.request_token or self._grantgetter(
            client_key=client_key,
            token=token,
        )
        if tok:
            request.request_token = tok
            return tok.secret
        return None

    def get_access_token_secret(self, client_key, token, request):
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
        log.debug('Get realms for %r', client_key)

        if not request.client:
            request.client = self._clientgetter(client_key=client_key)

        client = request.client
        if hasattr(client, 'default_realms'):
            return client.default_realms
        return []

    def get_realms(self, token, request):
        log.debug('Get realms of %r', token)
        # TODO
        return []

    def get_redirect_uri(self, token, request):
        log.debug('Get redirect uri of %r', token)
        # TODO
        return 'http://localhost:8000/authorized'

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
        tok = request.request_token or self._grantgetter(
            client_key=client_key,
            token=token,
        )
        if tok:
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
            request, request_token=None, access_token=None):
        log.debug('Validate timestamp and nonce %r', client_key)
        nonce = self._noncegetter(
            client_key=client_key, timestamp=timestamp,
            nonce=nonce, request_token=request_token,
            access_token=access_token
        )
        if nonce:
            return False
        # TODO: should we put it here
        self._noncesetter(
            client_key=client_key, timestamp=timestamp,
            nonce=nonce, request_token=request_token,
            access_token=access_token
        )
        return True

    def validate_redirect_uri(self, client_key, redirect_uri, request):
        log.debug('Validate redirect_uri %r for %r', redirect_uri, client_key)
        if not request.client:
            request.client = self._clientgetter(client_key=client_key)
        if not request.client:
            return False
        if not request.client.redirect_uris and redirect_uri is None:
            return True
        request.redirect_uri = redirect_uri
        return redirect_uri in request.client.redirect_uris

    def validate_requested_realm(self, client_key, realm, request):
        log.debug('Validate requested realm %r for %r', realm, client_key)
        if not request.client:
            request.client = self._clientgetter(client_key=client_key)
        # TODO
        return True

    def validate_realm(self, client_key, token, request, uri=None,
                       required_realm=None):
        log.debug('Validate realm for %r', client_key)

        if not request.client:
            request.client = self._clientgetter(client_key=client_key)
        # TODO
        return True

    def validate_verifier(self, client_key, token, verifier, request):
        log.debug('Validate verifier %r for %r', verifier, client_key)
        # TODO
        if not request.client:
            request.client = self._clientgetter(client_key=client_key)
        return True

    def verify_request_token(self, token, request):
        log.debug('Validate request token %r', token)
        # TODO
        return True

    def verify_realms(self, token, realms, request):
        log.debug('Validate realms %r', realms)
        # TODO
        return True

    def save_access_token(self, token, request):
        log.debug('Save access token %r', token)
        self._tokensetter(token, request)

    def save_request_token(self, token, request):
        log.debug('Save request token %r', token)
        self._grantsetter(token, request)

    def save_verifier(self, token, verifier, request):
        log.debug('Save verifier %r for %r', verifier, token)
        pass


def _error_response(e):
    res = make_response(e.urlencoded, e.status_code)
    res.headers['Content-Type'] = 'application/x-www-form-urlencoded'
    return res
