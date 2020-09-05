# coding: utf-8
"""
    flask_oauthlib.provider.oauth2
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Implemnts OAuth2 provider support for Flask.

    :copyright: (c) 2013 - 2014 by Hsiaoming Yang.
"""

import os
import logging
import datetime
from functools import wraps
from flask import request, url_for
from flask import redirect, abort
from werkzeug.utils import import_string, cached_property
from oauthlib import oauth2
from oauthlib.oauth2 import RequestValidator, Server
from oauthlib.common import to_unicode, add_params_to_uri
from ..utils import extract_params, decode_base64, create_response

__all__ = ('OAuth2Provider', 'OAuth2RequestValidator')

log = logging.getLogger('flask_oauthlib')


class OAuth2Provider(object):
    """Provide secure services using OAuth2.

    The server should provide an authorize handler and a token hander,
    But before the handlers are implemented, the server should provide
    some getters for the validation.

    Like many other Flask extensions, there are two usage modes. One is
    binding the Flask app instance::

        app = Flask(__name__)
        oauth = OAuth2Provider(app)

    The second possibility is to bind the Flask app later::

        oauth = OAuth2Provider()

        def create_app():
            app = Flask(__name__)
            oauth.init_app(app)
            return app

    Configure :meth:`tokengetter` and :meth:`tokensetter` to get and
    set tokens. Configure :meth:`grantgetter` and :meth:`grantsetter`
    to get and set grant tokens. Configure :meth:`clientgetter` to
    get the client.

    Configure :meth:`usergetter` if you need password credential
    authorization.

    With everything ready, implement the authorization workflow:

        * :meth:`authorize_handler` for consumer to confirm the grant
        * :meth:`token_handler` for client to exchange access token

    And now you can protect the resource with scopes::

        @app.route('/api/user')
        @oauth.require_oauth('email', 'username')
        def user():
            return jsonify(request.oauth.user)
    """

    def __init__(self, app=None, validator_class=None):
        self._before_request_funcs = []
        self._after_request_funcs = []
        self._exception_handler = None
        self._invalid_response = None
        self._validator_class = validator_class
        if app:
            self.init_app(app)

    def init_app(self, app):
        """
        This callback can be used to initialize an application for the
        oauth provider instance.
        """
        self.app = app
        app.extensions = getattr(app, 'extensions', {})
        app.extensions['oauthlib.provider.oauth2'] = self

    def _on_exception(self, error, redirect_content=None):

        if self._exception_handler:
            return self._exception_handler(error, redirect_content)
        else:
            return redirect(redirect_content)

    @cached_property
    def error_uri(self):
        """The error page URI.

        When something turns error, it will redirect to this error page.
        You can configure the error page URI with Flask config::

            OAUTH2_PROVIDER_ERROR_URI = '/error'

        You can also define the error page by a named endpoint::

            OAUTH2_PROVIDER_ERROR_ENDPOINT = 'oauth.error'
        """
        error_uri = self.app.config.get('OAUTH2_PROVIDER_ERROR_URI')
        if error_uri:
            return error_uri
        error_endpoint = self.app.config.get('OAUTH2_PROVIDER_ERROR_ENDPOINT')
        if error_endpoint:
            return url_for(error_endpoint)
        return '/oauth/errors'

    @cached_property
    def server(self):
        """
        All in one endpoints. This property is created automaticly
        if you have implemented all the getters and setters.

        However, if you are not satisfied with the getter and setter,
        you can create a validator with :class:`OAuth2RequestValidator`::

            class MyValidator(OAuth2RequestValidator):
                def validate_client_id(self, client_id):
                    # do something
                    return True

        And assign the validator for the provider::

            oauth._validator = MyValidator()
        """
        expires_in = self.app.config.get('OAUTH2_PROVIDER_TOKEN_EXPIRES_IN')
        token_generator = self.app.config.get(
            'OAUTH2_PROVIDER_TOKEN_GENERATOR', None
        )
        if token_generator and not callable(token_generator):
            token_generator = import_string(token_generator)

        refresh_token_generator = self.app.config.get(
            'OAUTH2_PROVIDER_REFRESH_TOKEN_GENERATOR', None
        )
        if refresh_token_generator and not callable(refresh_token_generator):
            refresh_token_generator = import_string(refresh_token_generator)

        if hasattr(self, '_validator'):
            return Server(
                self._validator,
                token_expires_in=expires_in,
                token_generator=token_generator,
                refresh_token_generator=refresh_token_generator,
            )

        if hasattr(self, '_clientgetter') and \
           hasattr(self, '_tokengetter') and \
           hasattr(self, '_tokensetter') and \
           hasattr(self, '_grantgetter') and \
           hasattr(self, '_grantsetter'):

            usergetter = None
            if hasattr(self, '_usergetter'):
                usergetter = self._usergetter

            validator_class = self._validator_class
            if validator_class is None:
                validator_class = OAuth2RequestValidator
            validator = validator_class(
                clientgetter=self._clientgetter,
                tokengetter=self._tokengetter,
                grantgetter=self._grantgetter,
                usergetter=usergetter,
                tokensetter=self._tokensetter,
                grantsetter=self._grantsetter,
            )
            self._validator = validator
            return Server(
                validator,
                token_expires_in=expires_in,
                token_generator=token_generator,
                refresh_token_generator=refresh_token_generator,
            )
        raise RuntimeError('application not bound to required getters')

    def before_request(self, f):
        """Register functions to be invoked before accessing the resource.

        The function accepts nothing as parameters, but you can get
        information from `Flask.request` object. It is usually useful
        for setting limitation on the client request::

            @oauth.before_request
            def limit_client_request():
                client_id = request.values.get('client_id')
                if not client_id:
                    return
                client = Client.get(client_id)
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

    def exception_handler(self, f):
        """Register a function as custom exception handler.

        **As the default error handling is leaking error to the client, it is
        STRONGLY RECOMMENDED to implement your own handler to mask
        the server side errors in production environment.**

        When an error occur during execution, we can
        handle the error with with the registered function. The function
        accepts two parameters:
            - error: the error raised
            - redirect_content: the content used in the redirect by default

        usage with the flask error handler ::
            @oauth.exception_handler
            def custom_exception_handler(error, *args):
                raise error

            @app.errorhandler(Exception)
            def all_exception_handler(*args):
                # any treatment you need for the error
                return "Server error", 500

        If no function is registered, it will do a redirect with ``redirect_content`` as content.
        """
        self._exception_handler = f
        return f

    def invalid_response(self, f):
        """Register a function for responsing with invalid request.

        When an invalid request proceeds to :meth:`require_oauth`, we can
        handle the request with the registered function. The function
        accepts one parameter, which is an oauthlib Request object::

            @oauth.invalid_response
            def invalid_require_oauth(req):
                return jsonify(message=req.error_message), 401

        If no function is registered, it will return with ``abort(401)``.
        """
        self._invalid_response = f
        return f

    def clientgetter(self, f):
        """Register a function as the client getter.

        The function accepts one parameter `client_id`, and it returns
        a client object with at least these information:

            - client_id: A random string
            - client_secret: A random string
            - is_confidential: A bool represents if it is confidential
            - redirect_uris: A list of redirect uris
            - default_redirect_uri: One of the redirect uris
            - default_scopes: Default scopes of the client

        The client may contain more information, which is suggested:

            - allowed_grant_types: A list of grant types
            - allowed_response_types: A list of response types
            - validate_scopes: A function to validate scopes

        Implement the client getter::

            @oauth.clientgetter
            def get_client(client_id):
                client = get_client_model(client_id)
                # Client is an object
                return client
        """
        self._clientgetter = f
        return f

    def usergetter(self, f):
        """Register a function as the user getter.

        This decorator is only required for **password credential**
        authorization::

            @oauth.usergetter
            def get_user(username, password, client, request,
                         *args, **kwargs):
                # client: current request client
                if not client.has_password_credential_permission:
                    return None
                user = User.get_user_by_username(username)
                if not user.validate_password(password):
                    return None

                # parameter `request` is an OAuthlib Request object.
                # maybe you will need it somewhere
                return user
        """
        self._usergetter = f
        return f

    def tokengetter(self, f):
        """Register a function as the token getter.

        The function accepts an `access_token` or `refresh_token` parameters,
        and it returns a token object with at least these information:

            - access_token: A string token
            - refresh_token: A string token
            - client_id: ID of the client
            - scopes: A list of scopes
            - expires: A `datetime.datetime` object
            - user: The user object

        The implementation of tokengetter should accepts two parameters,
        one is access_token the other is refresh_token::

            @oauth.tokengetter
            def bearer_token(access_token=None, refresh_token=None):
                if access_token:
                    return get_token(access_token=access_token)
                if refresh_token:
                    return get_token(refresh_token=refresh_token)
                return None
        """
        self._tokengetter = f
        return f

    def tokensetter(self, f):
        """Register a function to save the bearer token.

        The setter accepts two parameters at least, one is token,
        the other is request::

            @oauth.tokensetter
            def set_token(token, request, *args, **kwargs):
                save_token(token, request.client, request.user)

        The parameter token is a dict, that looks like::

            {
                u'access_token': u'6JwgO77PApxsFCU8Quz0pnL9s23016',
                u'token_type': u'Bearer',
                u'expires_in': 3600,
                u'scope': u'email address'
            }

        The request is an object, that contains an user object and a
        client object.
        """
        self._tokensetter = f
        return f

    def grantgetter(self, f):
        """Register a function as the grant getter.

        The function accepts `client_id`, `code` and more::

            @oauth.grantgetter
            def grant(client_id, code):
                return get_grant(client_id, code)

        It returns a grant object with at least these information:

            - delete: A function to delete itself
        """
        self._grantgetter = f
        return f

    def grantsetter(self, f):
        """Register a function to save the grant code.

        The function accepts `client_id`, `code`, `request` and more::

            @oauth.grantsetter
            def set_grant(client_id, code, request, *args, **kwargs):
                save_grant(client_id, code, request.user, request.scopes)
        """
        self._grantsetter = f
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
            # raise if server not implemented
            server = self.server
            uri, http_method, body, headers = extract_params()

            if request.method in ('GET', 'HEAD'):
                redirect_uri = request.args.get('redirect_uri', self.error_uri)
                log.debug('Found redirect_uri %s.', redirect_uri)
                try:
                    ret = server.validate_authorization_request(
                        uri, http_method, body, headers
                    )
                    scopes, credentials = ret
                    kwargs['scopes'] = scopes
                    kwargs.update(credentials)
                except oauth2.FatalClientError as e:
                    log.debug('Fatal client error %r', e, exc_info=True)
                    return self._on_exception(e, e.in_uri(self.error_uri))
                except oauth2.OAuth2Error as e:
                    log.debug('OAuth2Error: %r', e, exc_info=True)
                    # on auth error, we should preserve state if it's present according to RFC 6749
                    state = request.values.get('state')
                    if state and not e.state:
                        e.state = state  # set e.state so e.in_uri() can add the state query parameter to redirect uri
                    return self._on_exception(e, e.in_uri(redirect_uri))

                except Exception as e:
                    log.exception(e)
                    return self._on_exception(e, add_params_to_uri(
                        self.error_uri, {'error': str(e)}
                    ))

            else:
                redirect_uri = request.values.get(
                    'redirect_uri', self.error_uri
                )

            try:
                rv = f(*args, **kwargs)
            except oauth2.FatalClientError as e:
                log.debug('Fatal client error %r', e, exc_info=True)
                return self._on_exception(e, e.in_uri(self.error_uri))
            except oauth2.OAuth2Error as e:
                log.debug('OAuth2Error: %r', e, exc_info=True)
                # on auth error, we should preserve state if it's present according to RFC 6749
                state = request.values.get('state')
                if state and not e.state:
                    e.state = state  # set e.state so e.in_uri() can add the state query parameter to redirect uri
                return self._on_exception(e, e.in_uri(redirect_uri))

            if not isinstance(rv, bool):
                # if is a response or redirect
                return rv

            if not rv:
                # denied by user
                e = oauth2.AccessDeniedError(state=request.values.get('state'))
                return self._on_exception(e, e.in_uri(redirect_uri))
              
            return self.confirm_authorization_request()
        return decorated

    def confirm_authorization_request(self):
        """When consumer confirm the authorization."""
        server = self.server
        scope = request.values.get('scope') or ''
        scopes = scope.split()
        credentials = dict(
            client_id=request.values.get('client_id'),
            redirect_uri=request.values.get('redirect_uri', None),
            response_type=request.values.get('response_type', None),
            state=request.values.get('state', None)
        )
        log.debug('Fetched credentials from request %r.', credentials)
        redirect_uri = credentials.get('redirect_uri')
        log.debug('Found redirect_uri %s.', redirect_uri)

        uri, http_method, body, headers = extract_params()
        try:
            ret = server.create_authorization_response(
                uri, http_method, body, headers, scopes, credentials)
            log.debug('Authorization successful.')
            return create_response(*ret)
        except oauth2.FatalClientError as e:
            log.debug('Fatal client error %r', e, exc_info=True)
            return self._on_exception(e, e.in_uri(self.error_uri))
        except oauth2.OAuth2Error as e:
            log.debug('OAuth2Error: %r', e, exc_info=True)
            
            # on auth error, we should preserve state if it's present according to RFC 6749
            state = request.values.get('state')
            if state and not e.state:
                e.state = state  # set e.state so e.in_uri() can add the state query parameter to redirect uri
            return self._on_exception(e, e.in_uri(redirect_uri or self.error_uri))
        except Exception as e:
            log.exception(e)
            return self._on_exception(e, add_params_to_uri(
                self.error_uri, {'error': str(e)}
            ))

    def verify_request(self, scopes):
        """Verify current request, get the oauth data.

        If you can't use the ``require_oauth`` decorator, you can fetch
        the data in your request body::

            def your_handler():
                valid, req = oauth.verify_request(['email'])
                if valid:
                    return jsonify(user=req.user)
                return jsonify(status='error')
        """
        uri, http_method, body, headers = extract_params()
        return self.server.verify_request(
            uri, http_method, body, headers, scopes
        )

    def token_handler(self, f):
        """Access/refresh token handler decorator.

        The decorated function should return an dictionary or None as
        the extra credentials for creating the token response.

        You can control the access method with standard flask route mechanism.
        If you only allow the `POST` method::

            @app.route('/oauth/token', methods=['POST'])
            @oauth.token_handler
            def access_token():
                return None
        """
        @wraps(f)
        def decorated(*args, **kwargs):
            server = self.server
            uri, http_method, body, headers = extract_params()
            credentials = f(*args, **kwargs) or {}
            log.debug('Fetched extra credentials, %r.', credentials)
            ret = server.create_token_response(
                uri, http_method, body, headers, credentials
            )
            return create_response(*ret)
        return decorated

    def revoke_handler(self, f):
        """Access/refresh token revoke decorator.

        Any return value by the decorated function will get discarded as
        defined in [`RFC7009`_].

        You can control the access method with the standard flask routing
        mechanism, as per [`RFC7009`_] it is recommended to only allow
        the `POST` method::

            @app.route('/oauth/revoke', methods=['POST'])
            @oauth.revoke_handler
            def revoke_token():
                pass

        .. _`RFC7009`: http://tools.ietf.org/html/rfc7009
        """
        @wraps(f)
        def decorated(*args, **kwargs):
            server = self.server

            token = request.values.get('token')
            request.token_type_hint = request.values.get('token_type_hint')
            if token:
                request.token = token

            uri, http_method, body, headers = extract_params()
            ret = server.create_revocation_response(
                uri, headers=headers, body=body, http_method=http_method)
            return create_response(*ret)
        return decorated

    def require_oauth(self, *scopes):
        """Protect resource with specified scopes."""
        def wrapper(f):
            @wraps(f)
            def decorated(*args, **kwargs):
                for func in self._before_request_funcs:
                    func()

                if hasattr(request, 'oauth') and request.oauth:
                    return f(*args, **kwargs)

                valid, req = self.verify_request(scopes)

                for func in self._after_request_funcs:
                    valid, req = func(valid, req)

                if not valid:
                    if self._invalid_response:
                        return self._invalid_response(req)
                    return abort(401)
                request.oauth = req
                return f(*args, **kwargs)
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

    def _get_client_creds_from_request(self, request):
        """Return client credentials based on the current request.

        According to the rfc6749, client MAY use the HTTP Basic authentication
        scheme as defined in [RFC2617] to authenticate with the authorization
        server. The client identifier is encoded using the
        "application/x-www-form-urlencoded" encoding algorithm per Appendix B,
        and the encoded value is used as the username; the client password is
        encoded using the same algorithm and used as the password. The
        authorization server MUST support the HTTP Basic authentication scheme
        for authenticating clients that were issued a client password.
        See `Section 2.3.1`_.

        .. _`Section 2.3.1`: https://tools.ietf.org/html/rfc6749#section-2.3.1
        """
        if request.client_id is not None:
            return request.client_id, request.client_secret

        auth = request.headers.get('Authorization')
        # If Werkzeug successfully parsed the Authorization header,
        # `extract_params` helper will replace the header with a parsed dict,
        # otherwise, there is nothing useful in the header and we just skip it.
        if isinstance(auth, dict):
            return auth['username'], auth['password']

        return None, None

    def client_authentication_required(self, request, *args, **kwargs):
        """Determine if client authentication is required for current request.

        According to the rfc6749, client authentication is required in the
        following cases:

        Resource Owner Password Credentials Grant: see `Section 4.3.2`_.
        Authorization Code Grant: see `Section 4.1.3`_.
        Refresh Token Grant: see `Section 6`_.

        .. _`Section 4.3.2`: http://tools.ietf.org/html/rfc6749#section-4.3.2
        .. _`Section 4.1.3`: http://tools.ietf.org/html/rfc6749#section-4.1.3
        .. _`Section 6`: http://tools.ietf.org/html/rfc6749#section-6
        """
        def is_confidential(client):
            if hasattr(client, 'is_confidential'):
                return client.is_confidential
            client_type = getattr(client, 'client_type', None)
            if client_type:
                return client_type == 'confidential'
            return True

        grant_types = ('password', 'authorization_code', 'refresh_token')
        client_id, _ = self._get_client_creds_from_request(request)
        if client_id and request.grant_type in grant_types:
            client = self._clientgetter(client_id)
            if client:
                return is_confidential(client)
        return False

    def authenticate_client(self, request, *args, **kwargs):
        """Authenticate itself in other means.

        Other means means is described in `Section 3.2.1`_.

        .. _`Section 3.2.1`: http://tools.ietf.org/html/rfc6749#section-3.2.1
        """
        client_id, client_secret = self._get_client_creds_from_request(request)
        log.debug('Authenticate client %r', client_id)

        client = self._clientgetter(client_id)
        if not client:
            log.debug('Authenticate client failed, client not found.')
            return False

        request.client = client

        # http://tools.ietf.org/html/rfc6749#section-2
        # The client MAY omit the parameter if the client secret is an empty string.
        if hasattr(client, 'client_secret') and client.client_secret != client_secret:
            log.debug('Authenticate client failed, secret not match.')
            return False

        log.debug('Authenticate client success.')
        return True

    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        """Authenticate a non-confidential client.

        :param client_id: Client ID of the non-confidential client
        :param request: The Request object passed by oauthlib
        """
        if client_id is None:
            client_id, _ = self._get_client_creds_from_request(request)

        log.debug('Authenticate client %r.', client_id)
        client = request.client or self._clientgetter(client_id)
        if not client:
            log.debug('Authenticate failed, client not found.')
            return False

        # attach client on request for convenience
        request.client = client
        return True

    def confirm_redirect_uri(self, client_id, code, redirect_uri, client,
                             *args, **kwargs):
        """Ensure client is authorized to redirect to the redirect_uri.

        This method is used in the authorization code grant flow. It will
        compare redirect_uri and the one in grant token strictly, you can
        add a `validate_redirect_uri` function on grant for a customized
        validation.
        """
        client = client or self._clientgetter(client_id)
        log.debug('Confirm redirect uri for client %r and code %r.',
                  client.client_id, code)
        grant = self._grantgetter(client_id=client.client_id, code=code)
        if not grant:
            log.debug('Grant not found.')
            return False
        if hasattr(grant, 'validate_redirect_uri'):
            return grant.validate_redirect_uri(redirect_uri)
        log.debug('Compare redirect uri for grant %r and %r.',
                  grant.redirect_uri, redirect_uri)

        testing = 'OAUTHLIB_INSECURE_TRANSPORT' in os.environ
        if testing and redirect_uri is None:
            # For testing
            return True

        return grant.redirect_uri == redirect_uri

    def get_original_scopes(self, refresh_token, request, *args, **kwargs):
        """Get the list of scopes associated with the refresh token.

        This method is used in the refresh token grant flow.  We return
        the scope of the token to be refreshed so it can be applied to the
        new access token.
        """
        log.debug('Obtaining scope of refreshed token.')
        tok = self._tokengetter(refresh_token=refresh_token)
        return tok.scopes

    def confirm_scopes(self, refresh_token, scopes, request, *args, **kwargs):
        """Ensures the requested scope matches the scope originally granted
        by the resource owner. If the scope is omitted it is treated as equal
        to the scope originally granted by the resource owner.

        DEPRECATION NOTE: This method will cease to be used in oauthlib>0.4.2,
        future versions of ``oauthlib`` use the validator method
        ``get_original_scopes`` to determine the scope of the refreshed token.
        """
        if not scopes:
            log.debug('Scope omitted for refresh token %r', refresh_token)
            return True
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
        self._grantsetter(client_id, code, request, *args, **kwargs)
        return request.client.default_redirect_uri

    def save_bearer_token(self, token, request, *args, **kwargs):
        """Persist the Bearer token."""
        log.debug('Save bearer token %r', token)
        self._tokensetter(token, request, *args, **kwargs)
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
            msg = 'Bearer token not found.'
            request.error_message = msg
            log.debug(msg)
            return False

        # validate expires
        if tok.expires is not None and \
                datetime.datetime.utcnow() > tok.expires:
            msg = 'Bearer token is expired.'
            request.error_message = msg
            log.debug(msg)
            return False

        # validate scopes
        if scopes and not set(tok.scopes) & set(scopes):
            msg = 'Bearer token scope not valid.'
            request.error_message = msg
            log.debug(msg)
            return False

        request.access_token = tok
        request.user = tok.user
        request.scopes = scopes

        if hasattr(tok, 'client'):
            request.client = tok.client
        elif hasattr(tok, 'client_id'):
            request.client = self._clientgetter(tok.client_id)
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
        client = client or self._clientgetter(client_id)
        log.debug(
            'Validate code for client %r and code %r', client.client_id, code
        )
        grant = self._grantgetter(client_id=client.client_id, code=code)
        if not grant:
            log.debug('Grant not found.')
            return False
        if hasattr(grant, 'expires') and \
           datetime.datetime.utcnow() > grant.expires:
            log.debug('Grant is expired.')
            return False

        request.state = kwargs.get('state')
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

        default_grant_types = (
            'authorization_code', 'password',
            'client_credentials', 'refresh_token',
        )

        # Grant type is allowed if it is part of the 'allowed_grant_types'
        # of the selected client or if it is one of the default grant types
        if hasattr(client, 'allowed_grant_types'):
            if grant_type not in client.allowed_grant_types:
                return False
        else:
            if grant_type not in default_grant_types:
                return False

        if grant_type == 'client_credentials':
            if not hasattr(client, 'user'):
                log.debug('Client should have a user property')
                return False
            request.user = client.user

        return True

    def validate_redirect_uri(self, client_id, redirect_uri, request,
                              *args, **kwargs):
        """Ensure client is authorized to redirect to the redirect_uri.

        This method is used in the authorization code grant flow and also
        in implicit grant flow. It will detect if redirect_uri in client's
        redirect_uris strictly, you can add a `validate_redirect_uri`
        function on grant for a customized validation.
        """
        request.client = request.client or self._clientgetter(client_id)
        client = request.client
        if hasattr(client, 'validate_redirect_uri'):
            return client.validate_redirect_uri(redirect_uri)
        return redirect_uri in client.redirect_uris

    def validate_refresh_token(self, refresh_token, client, request,
                               *args, **kwargs):
        """Ensure the token is valid and belongs to the client

        This method is used by the authorization code grant indirectly by
        issuing refresh tokens, resource owner password credentials grant
        (also indirectly) and the refresh token grant.
        """

        token = self._tokengetter(refresh_token=refresh_token)

        if token and token.client_id == client.client_id:
            # Make sure the request object contains user and client_id
            request.client_id = token.client_id
            request.user = token.user
            return True
        return False

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
        if hasattr(client, 'validate_scopes'):
            return client.validate_scopes(scopes)
        return set(client.default_scopes).issuperset(set(scopes))

    def validate_user(self, username, password, client, request,
                      *args, **kwargs):
        """Ensure the username and password is valid.

        Attach user object on request for later using.
        """
        log.debug('Validating username %r and its password', username)
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

    def revoke_token(self, token, token_type_hint, request, *args, **kwargs):
        """Revoke an access or refresh token.
        """
        if token_type_hint:
            tok = self._tokengetter(**{token_type_hint: token})
        else:
            tok = self._tokengetter(access_token=token)
            if not tok:
                tok = self._tokengetter(refresh_token=token)

        if tok:
            request.client_id = tok.client_id
            request.user = tok.user
            tok.delete()
            return True

        msg = 'Invalid token supplied.'
        log.debug(msg)
        request.error_message = msg
        return False
