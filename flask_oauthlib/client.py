# coding: utf-8
"""
    flask_oauthlib.client
    ~~~~~~~~~~~~~~~~~~~~~

    Implemnts OAuth1 and OAuth2 support for Flask.

    :copyright: (c) 2013 by Hsiaoming Yang.
"""

import urllib2
import logging
import oauthlib.oauth1
import oauthlib.oauth2
from functools import wraps
from oauthlib.common import to_unicode
from urlparse import urljoin, urlparse
from flask import request, redirect, json, session
from werkzeug import url_quote, url_decode, url_encode, parse_options_header


__all__ = ('OAuth', 'OAuthRemoteApp', 'OAuthResponse', 'OAuthException')

log = logging.getLogger('flask_oauthlib')


class OAuth(object):
    """Registry for remote applications.

    :param app: the app instance of Flask

    Create an instance with Flask::

        oauth = OAuth(app)
    """

    def __init__(self, app=None):
        self.remote_apps = {}

        self.app = app
        if app:
            self.init_app(app)

    def init_app(self, app):
        """Init app with Flask instance.

        You can also pass the instance of Flask later::

            oauth = OAuth()
            oauth.init_app(app)
        """
        self.app = app
        app.extensions = getattr(app, 'extensions', {})
        app.extensions['oauthlib.client'] = self

    def remote_app(self, name, register=True, **kwargs):
        """Registers a new remote application.

        :param name: the name of the remote application
        :param register: whether the remote app will be registered

        Find more parameters from :class:`OAuthRemoteApp`.
        """

        if self.app and self.app.testing:
            kwargs['test_client'] = self.app.test_client()

        remote = OAuthRemoteApp(self, name, **kwargs)
        if register:
            assert name not in self.remote_apps
            self.remote_apps[name] = remote
        return remote

    def __getattr__(self, key):
        try:
            return object.__getattribute__(self, key)
        except AttributeError:
            app = self.remote_apps.get(key)
            if app:
                return app
            raise AttributeError('No such app: %s' % key)


_etree = None


def get_etree():  # pragma: no cover
    global _etree
    if _etree is not None:
        return _etree
    try:
        from lxml import etree as _etree
    except ImportError:
        try:
            from xml.etree import cElementTree as _etree
        except ImportError:
            try:
                from xml.etree import ElementTree as _etree
            except ImportError:
                raise TypeError('lxml or etree not found')
    return _etree


def parse_response(resp, content, strict=False, content_type=None):
    """
    Parse the response returned by :meth:`make_request`.
    """
    if not content_type:
        content_type = resp.headers.get('content-type', 'application/json')
    ct, options = parse_options_header(content_type)

    if ct in ('application/json', 'text/javascript'):
        return json.loads(content)

    if ct in ('application/xml', 'text/xml'):
        charset = options.get('charset', 'utf-8')
        return get_etree().fromstring(content.decode(charset))

    if ct != 'application/x-www-form-urlencoded' and strict:
        return content
    charset = options.get('charset', 'utf-8')
    return url_decode(content, charset=charset).to_dict()


def make_request(uri, headers=None, data=None, method=None,
                 test_client=None):
    if headers is None:
        headers = {}

    if data and not method:
        method = 'POST'
    elif not method:
        method = 'GET'

    if method == 'GET' and data:
        uri = add_query(uri, data)
        data = None

    log.debug('Request %r with %r method' % (uri, method))

    if test_client:
        # test client is a `werkzeug.test.Client`
        parsed = urlparse(uri)
        uri = '%s?%s' % (parsed.path, parsed.query)
        resp = test_client.open(
            uri, headers=headers, data=data, method=method
        )
        # for compatible
        resp.code = resp.status_code
        return resp, resp.data

    req = urllib2.Request(uri, headers=headers, data=data)
    req.get_method = lambda: method.upper()
    try:
        resp = urllib2.urlopen(req)
    except urllib2.HTTPError as resp:
        pass
    content = resp.read()
    resp.close()
    return resp, content


def add_query(url, args):
    if not args:
        return url
    return url + ('?' in url and '&' or '?') + url_encode(args)


def encode_request_data(data, format):
    if format is None:
        return data, None
    if format == 'json':
        return json.dumps(data or {}), 'application/json'
    if format == 'urlencoded':
        return url_encode(data or {}), 'application/x-www-form-urlencoded'
    raise TypeError('Unknown format %r' % format)


class OAuthResponse(object):
    def __init__(self, resp, content, content_type=None):
        self._resp = resp
        self.raw_data = content
        self.data = parse_response(
            resp, content, strict=True,
            content_type=content_type,
        )

    @property
    def status(self):
        """The status code of the response."""
        return self._resp.code


class OAuthException(RuntimeError):
    def __init__(self, message, type=None, data=None):
        self.message = message
        self.type = type
        self.data = data

    def __str__(self):
        return self.message.encode('utf-8')

    def __unicode__(self):
        return self.message


class OAuthRemoteApp(object):
    """Represents a remote application.

    :param oauth: the associated :class:`OAuth` object
    :param name: the name of the remote application
    :param base_url: the base url for every request
    :param request_token_url: the url for requesting new tokens
    :param access_token_url: the url for token exchange
    :param authorize_url: the url for authorization
    :param consumer_key: the application specific consumer key
    :param consumer_secret: the application specific consumer secret
    :param request_token_params: an optional dictionary of parameters
                                 to forward to the request token url
                                 or authorize url depending on oauth
                                 version
    :param access_token_params: an optional dictionary of parameters to
                                forward to the access token url
    :param access_token_method: the HTTP method that should be used for
                                the access_token_url. Default is ``GET``
    :param content_type: force to parse the content with this content_type,
                         usually used when the server didn't return the
                         right content type.
    """
    def __init__(
        self, oauth, name,
        base_url, request_token_url,
        access_token_url, authorize_url,
        consumer_key, consumer_secret,
        request_token_params=None,
        access_token_params=None,
        access_token_method='GET',
        content_type=None,
        test_client=None,
        encoding='utf-8',
    ):

        self.oauth = oauth
        self.base_url = base_url
        self.name = name
        self.request_token_url = request_token_url
        self.access_token_url = access_token_url
        self.authorize_url = authorize_url
        self.consumer_key = consumer_key
        self.consumer_secret = consumer_secret
        self.request_token_params = request_token_params or {}
        self.access_token_params = access_token_params or {}
        self.access_token_method = access_token_method
        self.content_type = content_type
        self.test_client = test_client
        self.encoding = encoding

        self._tokengetter = None

    def make_client(self, token=None):
        # request_token_url is for oauth1
        if self.request_token_url:
            client = oauthlib.oauth1.Client(
                self.consumer_key, self.consumer_secret
            )
            if token and isinstance(token, (tuple, list)):
                client.resource_owner_key, client.resource_owner_secret = token
        else:
            if token and isinstance(token, (tuple, list)):
                token = {'access_token': token[0]}
            client = oauthlib.oauth2.WebApplicationClient(
                self.consumer_key, token=token
            )
        return client

    def get(self, *args, **kwargs):
        """Sends a ``GET`` request. Accepts the same paramters as
        :meth:`request`.
        """
        kwargs['method'] = 'GET'
        return self.request(*args, **kwargs)

    def post(self, *args, **kwargs):
        """Sends a ``POST`` request. Accepts the same paramters as
        :meth:`request`.
        """
        kwargs['method'] = 'POST'
        return self.request(*args, **kwargs)

    def put(self, *args, **kwargs):
        """Sends a ``PUT`` request. Accepts the same paramters as
        :meth:`request`.
        """
        kwargs['method'] = 'PUT'
        return self.request(*args, **kwargs)

    def delete(self, *args, **kwargs):
        """Sends a ``DELETE`` request. Accepts the same paramters as
        :meth:`request`.
        """
        kwargs['method'] = 'DELETE'
        return self.request(*args, **kwargs)

    def request(self, url, data=None, headers=None, format='urlencoded',
                method='GET', content_type=None, token=None):
        """
        Sends a request to the remote server with OAuth tokens attached.

        :param data: the data to be sent to the server.
        :param headers: an optional dictionary of headers.
        :param format: the format for the `data`. Can be `urlencoded` for
                       URL encoded data or `json` for JSON.
        :param method: the HTTP request method to use.
        :param content_type: an optional content type. If a content type
                             is provided, the data is passed as it, and
                             the `format` is ignored.
        :param token: an optional token to pass, if it is None, token will
                      be generated be tokengetter.
        """

        headers = dict(headers or {})
        if not token:
            token = self.get_request_token()

        client = self.make_client(token)
        url = self.expand_url(url)
        if method == 'GET':
            assert format == 'urlencoded'
            if data:
                url = add_query(url, data)
                data = None
        else:
            if content_type is None:
                data, content_type = encode_request_data(data, format)
            if content_type is not None:
                headers['Content-Type'] = content_type

        if self.request_token_url:
            # oauth1
            uri, headers, body = client.sign(
                url, http_method=method, body=data, headers=headers
            )
        else:
            # oauth2
            uri, headers, body = client.add_token(
                url, http_method=method, body=data, headers=headers
            )

        if hasattr(self, 'pre_request'):
            # this is desgined for some rubbish serice like weibo
            # since they don't follow the standards, we need to
            # change the uri, headers, or body
            uri, headers, body = self.pre_request(uri, headers, body)

        resp, content = make_request(
            uri, headers, data=body, method=method,
            test_client=self.test_client
        )
        return OAuthResponse(resp, content, self.content_type)

    def authorize(self, callback=None):
        """
        Returns a redirect response to the remote authorization URL with
        the signed callback given.
        """
        if self.request_token_url:
            token = self.generate_request_token(callback)[0]
            url = '%s?oauth_token=%s' % (
                self.expand_url(self.authorize_url), url_quote(token)
            )
        else:
            assert callback is not None, 'Callback is required OAuth2'

            params = dict(self.request_token_params)
            client = self.make_client()

            scope = params.pop('scope')
            if isinstance(scope, str):
                # oauthlib need unicode
                scope = _encode(scope, self.encoding)

            session['%s_oauthredir' % self.name] = callback
            url = client.prepare_request_uri(
                self.expand_url(self.authorize_url),
                redirect_uri=callback,
                scope=scope,
                **params
            )
        return redirect(url)

    def tokengetter(self, f):
        """
        Register a function as token getter.
        """
        self._tokengetter = f
        return f

    def expand_url(self, url):
        return urljoin(self.base_url, url)

    def generate_request_token(self, callback=None):
        # for oauth1 only
        if callback is not None:
            callback = urljoin(request.url, callback)

        client = self.make_client()
        client.callback_uri = _encode(callback, self.encoding)
        uri, headers, _ = client.sign(
            self.expand_url(self.request_token_url)
        )
        resp, content = make_request(
            uri, headers, test_client=self.test_client
        )
        if resp.code not in (200, 201):
            raise OAuthException(
                'Failed to generate request token',
                type='token_generation_failed'
            )
        data = parse_response(resp, content)
        if data is None:
            raise OAuthException(
                'Invalid token response from %s' % self.name,
                type='token_generation_failed'
            )
        tup = (data['oauth_token'], data['oauth_token_secret'])
        session['%s_oauthtok' % self.name] = tup
        return tup

    def get_request_token(self):
        assert self._tokengetter is not None, 'missing tokengetter'
        rv = self._tokengetter()
        if rv is None:
            raise OAuthException('No token available', type='token_missing')
        return rv

    def handle_oauth1_response(self):
        """Handles an oauth1 authorization response."""
        client = self.make_client()
        client.verifier = request.args.get('oauth_verifier')
        tup = session.get('%s_oauthtok' % self.name)
        client.resource_owner_key = tup[0]
        client.resource_owner_secret = tup[1]

        uri, headers, data = client.sign(
            self.expand_url(self.access_token_url),
            _encode(self.access_token_method)
        )

        resp, content = make_request(
            uri, headers, data, test_client=self.test_client
        )
        data = parse_response(resp, content)
        if resp.code not in (200, 201):
            raise OAuthException(
                'Invalid response from %s' % self.name,
                type='invalid_response', data=data
            )
        return data

    def handle_oauth2_response(self):
        """Handles an oauth2 authorization response."""

        client = self.make_client()
        remote_args = {
            'code': request.args.get('code'),
            'client_secret': self.consumer_secret,
            'redirect_uri': session.get('%s_oauthredir' % self.name)
        }
        log.debug('Prepare oauth2 remote args %r', remote_args)
        remote_args.update(self.access_token_params)
        if self.access_token_method == 'POST':
            body = client.prepare_request_body(**remote_args)
            resp, content = make_request(
                self.expand_url(self.access_token_url),
                data=body,
                method=self.access_token_method,
                test_client=self.test_client,
            )
        elif self.access_token_method == 'GET':
            qs = client.prepare_request_body(**remote_args)
            url = self.expand_url(self.access_token_url)
            url += ('?' in url and '&' or '?') + qs
            resp, content = make_request(
                url,
                method=self.access_token_method,
                test_client=self.test_client,
            )
        else:
            raise OAuthException(
                'Unsupported access_token_method: ' %
                self.access_token_method
            )

        data = parse_response(resp, content, content_type=self.content_type)
        if resp.code not in (200, 201):
            raise OAuthException(
                'Invalid response from %s' % self.name,
                type='invalid_response', data=data
            )
        return data

    def handle_unknown_response(self):
        """Handles a unknown authorization response."""
        return None

    def authorized_handler(self, f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if 'oauth_verifier' in request.args:
                try:
                    data = self.handle_oauth1_response()
                except OAuthException as e:
                    data = e
            elif 'code' in request.args:
                try:
                    data = self.handle_oauth2_response()
                except OAuthException as e:
                    data = e
            else:
                data = self.handle_unknown_response()

            # free request token
            session.pop('%s_oauthtok' % self.name, None)
            session.pop('%s_oauthredir' % self.name, None)
            return f(*((data,) + args), **kwargs)
        return decorated


def _encode(text, encoding='utf-8'):
    if encoding:
        return to_unicode(text, encoding)
    return text
