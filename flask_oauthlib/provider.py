# coding: utf-8
"""
    flask_oauthlib.provider
    ~~~~~~~~~~~~~~~~~~~~~~~

    Implemnts OAuth2 provider support for Flask.

    :copyright: (c) 2013 by Hsiaoming Yang.
"""

import logging
import datetime
from functools import wraps
from flask import _app_ctx_stack
from flask import request, url_for, redirect
from werkzeug import cached_property
from oauthlib.command import urlencoded
from oauthlib.oauth2 import errors
from oauthlib.oauth2 import RequestValidator, WebApplicationServer


log = logging.getLogger('flask_oauthlib.provider')


class OAuth(object):
    """Provide secure services using OAuth2.

    The server should provide an authorize handler, access token hander,
    refresh token hander::

        @oauth.clientgetter
        def client(client_id):
            client = get_client_model(client_id)
            # Client is an object
            return client

        @oauth.tokengetter
        def bearer_token(access_token=None, refresh_token=None):
            # implemented get token by access token or refresh token
            token = get_token_model(access_token, refresh_token)
            # Token is an object, it should has `client_id`
            return token

        @app.route('/oauth/authorize', methods=['GET', 'POST'])
        @app.authorize_handler
        def authorize(client_id, response_type,
                      redirect_uri, scopes, **kwargs):
            return render_template('oauthorize.html')

        @app.route('/oauth/access_token')
        @app.access_token_handler
        def access_token(client):
            # maybe you need a record
            return {}

        @app.route('/oauth/access_token')
        @app.refresh_token_handler
        def refresh_token(client):
            # maybe you need a record
            return {}

    Protect the resource with scopes::

        @app.route('/api/user')
        @oauth.require_oauth(['email'])
        def user():
            return jsonify(g.user)
    """

    def __init__(self, app=None):
        if app:
            self.init_app(app)

    def init_app(self, app):
        self.app = app
        app.extensions = getattr(app, 'extensions', {})
        app.extensions['oauth-provider'] = self

    def get_app(self):
        if self.app is not None:
            return self.app
        ctx = _app_ctx_stack.top
        if ctx is not None:
            return ctx.app
        raise RuntimeError(
            'application not registered on Oauth '
            'instance and no application bound to current context'
        )

    @cached_property
    def error_uri(self):
        app = self.get_app()
        error_uri = app.config.get('OAUTH_PROVIDER_ERROR_URI')
        if error_uri:
            return error_uri
        error_endpoint = app.config.get('OAUTH_PROVIDER_ERROR_ENDPOINT')
        if error_endpoint:
            return url_for(error_endpoint)
        return '/errors'

    @cached_property
    def server(self):
        if hasattr(self, '_clientgetter') and hasattr(self, '_tokengetter'):
            validator = OAuthRequestValidator(
                self._clientgetter, self._tokengetter
            )
            return WebApplicationServer(validator)
        raise RuntimeError('application not bound to client getter')

    def access_token_methods(self):
        app = self.get_app()
        methods = app.config.get('OAUTH_ACCESS_TOKEN_METHODS', ['POST'])
        if isinstance(methods, (list, tuple)):
            return methods
        return [methods]

    def clientgetter(self, f):
        self._clientgetter = f

    def tokengetter(self, f):
        self._tokengetter = f

    def authorize_handler(self, f):
        @wraps(f)
        def decorated(*args, **kwargs):
            uri, http_method, body, headers = _extract_params()
            redirect_uri = request.args.get('redirect_uri', None)
            log.debug('Found redirect_uri %s.', redirect_uri)

            # raise if server not implemented
            server = self.server
            try:
                scopes, credentials = server.validate_authorization_request(
                    uri, http_method, body, headers)
                kwargs['scopes'] = scopes
                kwargs.update(credentials)
                return f(*args, **kwargs)
            except errors.FatalClientError as e:
                log.debug('Fatal client error')
                return redirect(e.in_uri(self.error_uri))
        return decorated

    def access_token_handler(self, func):
        if request.method not in self.access_token_methods():
            # method invalid
            pass

    def refresh_token_handler(self, func):
        pass

    def require_oauth(self, scope=None):
        pass


class OAuthRequestValidator(RequestValidator):
    """Subclass of Request Validator.

    :param clientgetter: a function to get the client object
    :param tokengetter: a function to get the token object

    The `client` is an object contains at least:

        - client_id
        - client_secret
        - client_type
        - redirect_uris
        - default_redirect_uri
        - default_scopes

    The `token` is an object contains at least:

        - scopes
        - expires
        - user
    """
    def __init__(self, clientgetter, tokengetter):
        self._clientgetter = clientgetter
        self._tokengetter = tokengetter

    def authenticate_client(self, request, *args, **kwargs):
        """Authenticate itself in other means.

        Other means means is described in `Section 3.2.1`_.

        .. _`Section 3.2.1`: http://tools.ietf.org/html/rfc6749#section-3.2.1
        """
        # TODO

    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        """Authenticate a non-confidential client.

        :param client_id: Client ID of the non-confidential client
        :param request: The Request object passed by oauthlib
        """
        client = request.client or self._clientgetter(client_id)
        if not client:
            return False

        # attach client on request for convenience
        request.client = client

        # authenticate non-confidential client_type only
        # most of the clients are of public client_type
        confidential = 'confidential'
        if hasattr(client, 'confidential'):
            confidential = client.confidential
        return client.client_type != confidential

    def confirm_scopes(self, refresh_token, scopes, request, *args, **kwargs):
        tok = self._tokengetter(refresh_token=refresh_token)
        return set(tok.scopes) == set(scopes)

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        client = request.client or self._clientgetter(client_id)
        return client.default_redirect_uri

    def get_default_scopes(self, client_id, request, *args, **kwargs):
        client = request.client or self._clientgetter(client_id)
        return client.default_scopes

    def invalidate_authorization_code(self, client_id, code, request,
                                      *args, **kwargs):
        # TODO
        pass

    def save_authorization_code(self, client_id, code, request,
                                *args, **kwargs):
        # TODO
        pass

    def validate_bearer_token(self, token, scopes, request):
        """Validate access token.

        :param token: A string of random characters
        :param scopes: A list of scopes
        :param request: The Request object passed by oauthlib

        The validation validates:

            1) if the token is available
            2) if the token has expired
            3) if the scopes are available
        """
        tok = self._tokengetter(access_token=token)
        if not tok:
            return False

        # validate expires
        if datetime.datetime.utcnow() > tok.expires:
            return False

        # validate scopes
        if not set(tok.scopes).issuperset(set(scopes)):
            return False

        request.user = tok.user
        request.scopes = scopes
        return True

    def validate_client_id(self, client_id, request, *args, **kwargs):
        client = request.client or self._clientgetter(client_id)
        if client:
            # attach client to request object
            request.client = client
            return True
        return False

    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        # TODO
        pass

    def validate_grant_type(self, client_id, grant_type, client, request,
                            *args, **kwargs):
        # TODO
        pass

    def validate_redirect_uri(self, client_id, redirect_uri, request,
                              *args, **kwargs):
        request.client = request.client = self._clientgetter(client_id)
        # TODO: redirect_uri = clean(redirect_uri)
        return redirect_uri in request.client.redirect_uris

    def validate_refresh_token(self, refresh_token, client, request,
                               *args, **kwargs):
        # TODO
        pass

    def validate_response_type(self, client_id, response_type, client, request,
                               *args, **kwargs):
        # TODO
        pass

    def validate_scopes(self, client_id, scopes, client, request,
                        *args, **kwargs):
        # TODO
        pass

    def validate_user(self, username, password, client, request,
                      *args, **kwargs):
        # TODO
        pass


def _extract_params():
    """Extract request params."""
    log.debug('Extracting parameters from request.')
    uri = request.url
    http_method = request.method
    headers = dict(request.headers)
    if 'wsgi.input' in headers:
        del headers['wsgi.input']
    if 'wsgi.errors' in headers:
        del headers['wsgi.errors']
    if 'HTTP_AUTHORIZATION' in headers:
        headers['Authorization'] = headers['HTTP_AUTHORIZATION']
    body = urlencoded(request.form.items())
    return uri, http_method, body, headers
