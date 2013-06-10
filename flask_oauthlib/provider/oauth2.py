# coding: utf-8
"""
    flask_oauthlib.provider.oauth2
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Implemnts OAuth2 provider support for Flask.

    :copyright: (c) 2013 by Hsiaoming Yang.
"""

import os
import logging
import datetime
from functools import wraps
from flask import _app_ctx_stack
from flask import request, url_for
from flask import redirect, make_response, abort
from flask import session
from werkzeug import cached_property
from oauthlib import oauth2
from oauthlib.oauth2 import RequestValidator, Server
from oauthlib.common import to_unicode

__all__ = ('OAuth2Provider', 'OAuth2RequestValidator')

log = logging.getLogger('flask_oauthlib')


class OAuth2Provider(object):
    """Provide secure services using OAuth2.

    The server should provide an authorize handler, access token hander,
    refresh token hander. But before the handlers are implemented, the
    server should provide the client getter, token getter and grant getter.

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
        return '/oauth/errors'

    @cached_property
    def server(self):
        """All in one endpoints."""
        app = self.get_app()
        expires_in = app.config.get('OAUTH_PROVIDER_TOKEN_EXPIRES_IN')
        if hasattr(self, '_validator'):
            return Server(self._validator, token_expires_in=expires_in)

        if hasattr(self, '_clientgetter') and \
           hasattr(self, '_tokengetter') and \
           hasattr(self, '_tokensetter') and \
           hasattr(self, '_grantgetter') and \
           hasattr(self, '_grantsetter'):

            usergetter = None
            if hasattr(self, '_usergetter'):
                usergetter = self._usergetter

            validator = OAuth2RequestValidator(
                clientgetter=self._clientgetter,
                tokengetter=self._tokengetter,
                grantgetter=self._grantgetter,
                usergetter=usergetter,
                tokensetter=self._tokensetter,
                grantsetter=self._grantsetter,
            )
            return Server(validator, token_expires_in=expires_in)
        raise RuntimeError('application not bound to required getters')

    def clientgetter(self, f):
        """Register a function as the client getter.

        The function accepts one parameter `client_id`, and it returns
        a client object with at least these information:

            - client_id: A random string
            - client_secret: A random string
            - client_type: A string represents if it is `confidential`
            - redirect_uris: A list of redirect uris
            - default_redirect_uri: One of the redirect uris
            - default_scopes: Default scopes of the client

        The client may contain more information, which is suggested:

            - allowed_grant_types: A list of grant types
            - allowed_response_types: A list of response types

        Implement the client getter::

            @oauth.clientgetter
            def get_client(client_id):
                client = get_client_model(client_id)
                # Client is an object
                return client
        """
        self._clientgetter = f

    def tokengetter(self, f):
        """Register a function as the token getter.

        The function accepts an `access_token` or `refresh_token` parameters,
        and it returns a token object with at least these information:

            - scopes: A list of scopes
            - expires: A `datetime.datetime` object
            - user: The user object

        Implement the token getter::

            @oauth.tokengetter
            def bearer_token(access_token=None, refresh_token=None):
                if access_token:
                    return get_token(access_token=access_token)
                if refresh_token:
                    return get_token(refresh_token=refresh_token)
                return None
        """
        self._tokengetter = f

    def usergetter(self, f):
        """Register a function as the user getter.

        This decorator is only required for password credential
        authorization::

            @oauth.usergetter
            def get_user(username=username, password=password,
                         *args, **kwargs):
                return get_user_by_username(username, password)
        """
        self._usergetter = f

    def tokensetter(self, f):
        """Register a function to save the bearer token.

        The function accepts the folllowing parameters:

            - access_token: A string token
            - token_type: A string describing the type of token provided
            - scopes: A list of scopes for the token 
            - client: The client object 
            - user: The user object 
            - expires_in: Number of seconds until token should expire
            - refresh_token: Either a string token or None
        
        Implement the token setter::
        
            @oauth.tokensetter
            def set_token(access_token, scopes, client, user, 
                        expires_in, refresh_token):
                expires_at = datetime.now() + timedelta(seconds=expires_in)
                save_token(access_token, scopes, client, user, 
                        expires_at, refresh_token)

        """
        self._tokensetter = f

    def grantgetter(self, f):
        """Register a function as the grant getter.

        The function accepts `client_id`, `code` and more::

            @oauth.grantgetter
            def grant(client_id, code):
                return get_grant(client_id, code)

        It returns a grant object with at least these information:

            - user: The user for the grant
            - scopes: A list of scopes provided by the grant
            - delete: A function to delete itself
        """
        self._grantgetter = f

    def grantsetter(self, f):
        """Register a function to save the grant code.

        The function accepts the following arguments:

            - code: A string authorization code
            - redirect_uri: A string representing the redirect uri
            - user: The user object
            - client: The client object
            - scopes: A list of scopes for the code
            - state: A string provided to prevent CSS
            
        Here is an exmample implementation of the setter::

            @oauth.grantsetter
            def set_grant(code, redirect_uri, user, client, scopes, state):
                save_grant(code, redirect_uri, user, client, scopes, state)
        """
        self._grantsetter = f

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
            uri, http_method, body, headers = _extract_params()
            # raise if server not implemented
            server = self.server

            if request.method == 'GET':
                redirect_uri = request.args.get('redirect_uri', None)
                log.debug('Found redirect_uri %s.', redirect_uri)
                try:
                    ret = server.validate_authorization_request(
                        uri, http_method, body, headers
                    )
                    scopes, credentials = ret
                    session['oauth2_credentials'] = credentials
                    kwargs['scopes'] = scopes
                    kwargs.update(credentials)
                    return f(*args, **kwargs)
                except oauth2.FatalClientError as e:
                    log.debug('Fatal client error %r', e)
                    return redirect(e.in_uri(self.error_uri))

            if request.method == 'POST':
                redirect_uri = request.values.get('redirect_uri', None)
                if not f(*args, **kwargs):
                    # denied by user
                    e = oauth2.AccessDeniedError()
                    return redirect(e.in_uri(redirect_uri))
                return self.confirm_authorization_request()
        return decorated

    def confirm_authorization_request(self):
        """When consumer confirm the authrozation."""
        scope = request.values.get('scope') or ''
        scopes = scope.split()
        credentials = dict(
            client_id=request.values.get('client_id'),
            redirect_uri=request.values.get('redirect_uri', None),
            response_type=request.values.get('response_type', None),
            state=request.values.get('state', None)
        )
        log.debug('Fetched credentials from request %r.', credentials)
        credentials.update(session.get('oauth2_credentials', {}))
        log.debug('Fetched credentials from session %r.', credentials)
        redirect_uri = credentials.get('redirect_uri')
        log.debug('Found redirect_uri %s.', redirect_uri)

        server = self.server
        uri, http_method, body, headers = _extract_params()
        try:
            ret = server.create_authorization_response(
                uri, http_method, body, headers, scopes, credentials)
            log.debug('Authorization successful.')
            return redirect(ret[0])
        except oauth2.FatalClientError as e:
            return redirect(e.in_uri(self.error_uri))
        except oauth2.OAuth2Error as e:
            return redirect(e.in_uri(redirect_uri))

    def access_token_handler(self, f):
        """Access token handler decorator.

        The decorated function should return an dictionary or None as
        the extra credentials for creating the token response.

        You can control the access method with standard flask route mechanism.
        If you only allow the `POST` method::

            @app.route('/oauth/access_token', methods=['POST'])
            @oauth.access_token_handler
            def access_token():
                return None
        """
        @wraps(f)
        def decorated(*args, **kwargs):
            uri, http_method, body, headers = _extract_params()
            credentials = f(*args, **kwargs) or {}
            log.debug('Fetched extra credentials, %r.', credentials)
            server = self.server
            uri, headers, body, status = server.create_token_response(
                uri, http_method, body, headers, credentials
            )
            response = make_response(body, status)
            for k, v in headers.items():
                response.headers[k] = v
            return response
        return decorated

    def refresh_token_handler(self, func):
        pass

    def require_oauth(self, scopes=None):
        """Protect resource with specified scopes."""
        def wrapper(f):
            @wraps(f)
            def decorated(*args, **kwargs):
                uri, http_method, body, headers = _extract_params()
                server = self.server
                valid, req = server.verify_request(
                    uri, http_method, body, headers, scopes
                )
                if not valid:
                    return abort(403)
                return f(*((req,) + args), **kwargs)
            return decorated
        return wrapper


class OAuth2RequestValidator(RequestValidator):
    """Subclass of Request Validator.

    :param clientgetter: a function to get client object
    :param tokengetter: a function to get bearer token
    :param tokensetter: a function to save bearer token
    :param grantgetter: a function to get grant token
    :param grantsetter: a function to save grant token
    """
    def __init__(self, clientgetter, tokengetter, grantgetter,
                 usergetter=None, tokensetter=None, grantsetter=None):
        self._clientgetter = clientgetter
        self._tokengetter = tokengetter
        self._usergetter = usergetter
        self._tokensetter = tokensetter
        self._grantgetter = grantgetter
        self._grantsetter = grantsetter

    def authenticate_client(self, request, *args, **kwargs):
        """Authenticate itself in other means.

        Other means means is described in `Section 3.2.1`_.

        .. _`Section 3.2.1`: http://tools.ietf.org/html/rfc6749#section-3.2.1
        """
        auth = request.headers.get('Http-Authorization', None)
        log.debug('Authenticate client %r', auth)
        if auth:
            try:
                _, base64 = auth.split(' ')
                client_id, client_secret = base64.decode('base64').split(':')
                client_id = to_unicode(client_id, 'utf-8')
                client_secret = to_unicode(client_secret, 'utf-8')
            except Exception as e:
                log.debug('Authenticate client failed with exception: %r', e)
                return False
        else:
            client_id = request.client_id
            client_secret = request.client_secret

        client = self._clientgetter(client_id)
        if not client:
            log.debug('Authenticate client failed, client not found.')
            return False

        request.client = client
        if client.client_secret != client_secret:
            log.debug('Authenticate client failed, secret not match.')
            return False

        confidential = 'confidential'
        if hasattr(client, 'confidential'):
            confidential = client.confidential

        if client.client_type != confidential:
            log.debug('Authenticate client failed, not confidential.')
            return False
        log.debug('Authenticate client success.')
        return True

    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        """Authenticate a non-confidential client.

        :param client_id: Client ID of the non-confidential client
        :param request: The Request object passed by oauthlib
        """
        log.debug('Authenticate client %r.', client_id)
        client = request.client or self._clientgetter(client_id)
        if not client:
            log.debug('Authenticate failed, client not found.')
            return False

        # attach client on request for convenience
        request.client = client

        # authenticate non-confidential client_type only
        # most of the clients are of public client_type
        confidential = 'confidential'
        if hasattr(client, 'confidential'):
            confidential = client.confidential

        if client.client_type == confidential:
            log.debug('Authenticate client failed, confidential client.')
            return False
        return True

    def confirm_redirect_uri(self, client_id, code, redirect_uri, client,
                             *args, **kwargs):
        """Ensure client is authorized to redirect to the redirect_uri.

        This method is used in the authorization code grant flow. It will
        compare redirect_uri and the one in grant token strictly, you can
        add a `validate_redirect_uri` function on grant for a customized
        validation.
        """
        log.debug('Confirm redirect uri for client %r and code %r.',
                  client_id, code)
        grant = self._grantgetter(client_id=client_id, code=code)
        if not grant:
            log.debug('Grant not found.')
            return False
        if hasattr(grant, 'validate_redirect_uri'):
            return grant.validate_redirect_uri(redirect_uri)
        log.debug('Compare redirect uri for grant %r and %r.',
                  grant.redirect_uri, redirect_uri)

        if os.environ.get('DEBUG') and redirect_uri is None:
            # For testing
            return True

        return grant.redirect_uri == redirect_uri

    def confirm_scopes(self, refresh_token, scopes, request, *args, **kwargs):
        #TODO
        log.debug('Confirm scopes %r for refresh token %r',
                  scopes, refresh_token)
        tok = self._tokengetter(refresh_token=refresh_token)
        return set(tok.scopes) == set(scopes)

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        """Default redirect_uri for the given client."""
        request.client = request.client or self._clientgetter(client_id)
        redirect_uri = request.client.default_redirect_uri
        log.debug('Found default redirect uri %r', redirect_uri)
        return redirect_uri

    def get_default_scopes(self, client_id, request, *args, **kwargs):
        """Default scopes for the given client."""
        request.client = request.client or self._clientgetter(client_id)
        scopes = request.client.default_scopes
        log.debug('Found default scopes %r', scopes)
        return scopes

    def invalidate_authorization_code(self, client_id, code, request,
                                      *args, **kwargs):
        """Invalidate an authorization code after use.

        We keep the temporary code in a grant, which has a `delete`
        function to destroy itself.
        """
        log.debug('Destroy grant token for client %r, %r', client_id, code)
        grant = self._grantgetter(client_id=client_id, code=code)
        if grant:
            grant.delete()

    def save_authorization_code(self, client_id, code, request,
                                *args, **kwargs):
        """Persist the authorization code."""
        log.debug(
            'Persist authorization code %r for client %r',
            code, client_id
        )
        request.client = request.client or self._clientgetter(client_id)
        request.user = request.user or self._usergetter()
        self._grantsetter(
            code=code['code'], 
            redirect_uri=request.redirect_uri, 
            user=request.user,
            client=request.client,
            scopes=request.scopes,
            state=request.state
        )
        return request.client.default_redirect_uri

    def save_bearer_token(self, token, request, *args, **kwargs):
        """Persist the Bearer token."""
        log.debug('Save bearer token %r', token)
        self._tokensetter(
                access_token = token['access_token'],
                token_type = token['token_type'],
                scopes = request.scopes,
                client = request.client,
                user = request.user,
                expires_in = token['expires_in'],
                refresh_token = token.get('refresh_token', None)
        )
        return request.client.default_redirect_uri

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
        log.debug('Validate bearer token %r', token)
        tok = self._tokengetter(access_token=token)
        if not tok:
            log.debug('Bearer token not found.')
            return False

        # validate expires
        if datetime.datetime.utcnow() > tok.expires:
            log.debug('Bearer token is expired.')
            return False

        # validate scopes
        if not set(tok.scopes).issuperset(set(scopes)):
            log.debug('Bearer token scope not valid.')
            return False

        request.user = tok.user
        request.scopes = scopes
        return True

    def validate_client_id(self, client_id, request, *args, **kwargs):
        """Ensure client_id belong to a valid and active client."""
        log.debug('Validate client %r', client_id)
        client = request.client or self._clientgetter(client_id)
        if client:
            # attach client to request object
            request.client = client
            return True
        return False

    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        """Ensure the grant code is valid."""
        log.debug(
            'Validate code for client %r and code %r', client_id, code
        )
        grant = self._grantgetter(client_id=client_id, code=code)
        if not grant:
            log.debug('Grant not found.')
            return False
        if hasattr(grant, 'expires') and \
           datetime.datetime.utcnow() > grant.expires:
            log.debug('Grant is expired.')
            return False
        request.state = grant.state
        request.user = grant.user
        request.scopes = grant.scopes
        return True

    def validate_grant_type(self, client_id, grant_type, client, request,
                            *args, **kwargs):
        """Ensure the client is authorized to use the grant type requested.

        It will allow any of the four grant types (`authorization_code`,
        `password`, `client_credentials`, `refresh_token`) by default.
        Implemented `allowed_grant_types` for client object to authorize
        the request.

        It is suggested that `allowed_grant_types` should contain at least
        `authorization_code` and `refresh_token`.
        """
        if self._usergetter is None and grant_type == 'password':
            log.debug('Password credential authorization is disabled.')
            return False

        if grant_type not in ('authorization_code', 'password',
                              'client_credentials', 'refresh_token'):
            return False

        if hasattr(client, 'allowed_grant_types'):
            return grant_type in client.allowed_grant_types

        if grant_type == 'client_credentials':
            # TODO: other means
            if hasattr(client, 'user'):
                request.user = client.user
                return True
            log.debug('Client should has a user property')
            return False

        return True

    def validate_redirect_uri(self, client_id, redirect_uri, request,
                              *args, **kwargs):
        """Ensure client is authorized to redirect to the redirect_uri.

        This method is used in the authorization code grant flow and also
        in implicit grant flow. It will detect if redirect_uri in client's
        redirect_uris strictly, you can add a `validate_redirect_uri`
        function on grant for a customized validation.
        """
        request.client = request.client = self._clientgetter(client_id)
        client = request.client
        if hasattr(client, 'validate_redirect_uri'):
            return client.validate_redirect_uri(redirect_uri)
        return redirect_uri in client.redirect_uris

    def validate_refresh_token(self, refresh_token, client, request,
                               *args, **kwargs):
        # TODO
        return True

    def validate_response_type(self, client_id, response_type, client, request,
                               *args, **kwargs):
        """Ensure client is authorized to use the response type requested.

        It will allow any of the two (`code`, `token`) response types by
        default. Implemented `allowed_response_types` for client object
        to authorize the request.
        """
        if response_type not in ('code', 'token'):
            return False

        if hasattr(client, 'allowed_response_types'):
            return response_type in client.allowed_response_types
        return True

    def validate_scopes(self, client_id, scopes, client, request,
                        *args, **kwargs):
        """Ensure the client is authorized access to requested scopes."""
        if not client:
            client = request.client or self._clientgetter(client_id)
            request.client = client
        if set(client.default_scopes).issuperset(set(scopes)):
            return True
        if hasattr(client, 'validate_scopes'):
            return client.validate_scopes(scopes)
        return True

    def validate_user(self, username, password, client, request,
                      *args, **kwargs):
        """Ensure the username and password is valid.

        Attach user object on request for later using.
        """
        log.debug('Validating username %r and password %r',
                  username, password)
        if self._usergetter is not None:
            user = self._usergetter(
                username, password, client, request, *args, **kwargs
            )
            if user:
                request.user = user
                return True
            return False
        log.debug('Password credential authorization is disabled.')
        return False


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
    if 'Http-Authorization' in headers:
        headers['Authorization'] = headers['Http-Authorization']

    body = request.form.to_dict()
    return uri, http_method, body, headers
