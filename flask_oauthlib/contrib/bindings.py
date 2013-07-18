# coding: utf-8
"""
    flask_oauthlib.contrib.bindings
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    SQLAlchemy and Grant-Caching for OAuth2 provider.

    contributed by: Randy Topliffe
"""

from datetime import datetime, timedelta
from werkzeug.contrib.cache import (
    NullCache,
    SimpleCache,
    MemcachedCache,
    RedisCache,
    FileSystemCache
)
import logging


__all__ = ('GrantCacheBinding', 'SQLAlchemyBinding')


log = logging.getLogger('flask_oauthlib')


class Grant(object):
    """Grant is only used by `GrantCacheBinding` to store the data
    returned from the cache system.

    :param cache: Werkzeug cache instance
    :param client_id: ID of the client
    :param code: A random string
    :param redirect_uri: A URI string
    :param scopes: A space delimited list of scopes
    :param user: the authorizatopm user
    """

    def __init__(self, cache=None, client_id=None, code=None,
                 redirect_uri=None, scopes=None, user=None):
        self._cache = cache
        self.client_id = client_id
        self.code = code
        self.redirect_uri = redirect_uri
        self.scopes = scopes
        self.user = user

    def delete(self):
        """Removes itself from the cache

        Note: This is required by the oauthlib
        """
        log.debug("Deleting grant")
        log.debug("Code: {0}".format(self.code))
        log.debug("Client id: {0}".format(self.client_id))
        self._cache.delete(self.key)
        return None

    @property
    def key(self):
        """The string used as the key for the cache"""
        key = '{code}{client_id}'.format(
            code=self.code,
            client_id=self.client_id
        )
        return key

    def __getitem__(self, item):
        return getattr(self, item)

    def keys(self):
        return ['client_id', 'code', 'redirect_uri', 'scopes', 'user']


class GrantCacheBinding(object):
    """Configures an :class:`OAuth2Provider` instance to use various caching
    systems to get and set the grant token. This removes the need to
    register :func:`grantgetter` and :func:`grantsetter` yourself.

    :param app: Flask application instance
    :param provider: :class:`OAuth2Provider` instance
    :param current_user: function that returns an :class:`User` object
    :param config: Additional configuration

    A usage example::

        oauth = OAuth2Provider(app)
        config = {'OAUTH2_CACHE_TYPE': 'redis'}

        GrantCacheBinding(app, oauth, current_user, config=config)

    You can define which cache system you would like to use by setting the
    following configuration option::

        OAUTH2_CACHE_TYPE = 'null' // memcache, simple, redis, filesystem

    For more information on the supported cache systems please visit:
    `Cache <http://werkzeug.pocoo.org/docs/contrib/cache/>`_

    """

    def __init__(self, app, provider, current_user, config=None):

        if config is None:
            config = app.config
        else:
            from itertools import chain
            config = dict(chain(app.config.items(), config.items()))

        self.current_user = current_user

        settings = (
            {
                'flask_oauthlib_key': 'OAUTH2_CACHE_DEFAULT_TIMEOUT',
                'flask_cache_key': 'CACHE_DEFAULT_TIMEOUT',
                'default_value': 100
            },
            {
                'flask_oauthlib_key': 'OAUTH2_CACHE_THRESHOLD',
                'flask_cache_key': 'CACHE_THRESHOLD',
                'default_value': 500
            },
            {
                'flask_oauthlib_key': 'OAUTH2_CACHE_KEY_PREFIX',
                'flask_cache_key': 'CACHE_KEY_PREFIX',
                'default_value': None
            },
            {
                'flask_oauthlib_key': 'OAUTH2_CACHE_MEMCACHED_SERVERS',
                'flask_cache_key': 'CACHE_MEMCACHED_SERVERS',
                'default_value': None
            },
            {
                'flask_oauthlib_key': 'OAUTH2_CACHE_REDIS_HOST',
                'flask_cache_key': 'CACHE_REDIS_HOST',
                'default_value': 'localhost'
            },
            {
                'flask_oauthlib_key': 'OAUTH2_CACHE_REDIS_PORT',
                'flask_cache_key': 'CACHE_REDIS_PORT',
                'default_value': 6379
            },
            {
                'flask_oauthlib_key': 'OAUTH2_CACHE_REDIS_PASSWORD',
                'flask_cache_key': 'CACHE_REDIS_PASSWORD',
                'default_value': None
            },
            {
                'flask_oauthlib_key': 'OAUTH2_CACHE_REDIS_DB',
                'flask_cache_key': 'CACHE_REDIS_DB',
                'default_value': 0
            },
            {
                'flask_oauthlib_key': 'OAUTH2_CACHE_DIR',
                'flask_cache_key': 'CACHE_DIR',
                'default_value': None
            },
            {
                'flask_oauthlib_key': 'OAUTH2_CACHE_MODE',
                'flask_cache_key': 'CACHE_MODE',
                'default_value': '0600'
            },
            {
                'flask_oauthlib_key': 'OAUTH2_CACHE_TYPE',
                'flask_cache_key': 'CACHE_TYPE',
                'default_value': 'null'
            },
        )

        for setting in settings:
            flask_oauthlib_key = setting['flask_oauthlib_key']
            flask_cache_key = setting['flask_cache_key']
            if flask_cache_key in config and flask_oauthlib_key not in config:
                config[flask_oauthlib_key] = config[flask_cache_key]
            else:
                config.setdefault(flask_oauthlib_key, setting['default_value'])

        self.config = config
        kwargs = dict(default_timeout=config['OAUTH2_CACHE_DEFAULT_TIMEOUT'])
        cache_type = '_{0}'.format(config['OAUTH2_CACHE_TYPE'])

        try:
            self.cache = getattr(self, cache_type)(kwargs)
        except AttributeError:
            raise AttributeError(
                '`{0}` is not a valid cache type!'.format(cache_type))

        provider.grantgetter(self.get)
        provider.grantsetter(self.set)

    def _null(self, kwargs):
        """Returns a :class:`NullCache` instance"""
        return NullCache()

    def _simple(self, kwargs):
        """Returns a :class:`SimpleCache` instance

        .. warning::

            This cache system might not be thread safe. Use with caution.

        """
        kwargs.update(dict(threshold=self.config['OAUTH2_CACHE_THRESHOLD']))
        return SimpleCache(**kwargs)

    def _memcache(self, kwargs):
        """Returns a :class:`MemcachedCache` instance"""
        kwargs.update(dict(
            servers=self.config['OAUTH2_CACHE_MEMCACHED_SERVERS'],
            key_prefix=self.config['OAUTH2_CACHE_KEY_PREFIX']
        ))
        return MemcachedCache(**kwargs)

    def _redis(self, kwargs):
        """Returns a :class:`RedisCache` instance"""
        kwargs.update(dict(
            host=self.config['OAUTH2_CACHE_REDIS_HOST'],
            port=self.config['OAUTH2_CACHE_REDIS_PORT'],
            password=self.config['OAUTH2_CACHE_REDIS_PASSWORD'],
            db=self.config['OAUTH2_CACHE_REDIS_DB'],
            key_prefix=self.config['OAUTH2_CACHE_KEY_PREFIX']
        ))
        return RedisCache(**kwargs)

    def _filesystem(self, kwargs):
        """Returns a :class:`FileSystemCache` instance"""
        kwargs.update(dict(
            threshold=self.config['OAUTH2_CACHE_THRESHOLD']
        ))
        return FileSystemCache(self.config['OAUTH2_CACHE_DIR'], **kwargs)

    def set(self, client_id, code, request, *args, **kwargs):
        """Sets the grant token with the configured cache system"""
        grant = Grant(
            self.cache,
            client_id=request.client.client_id,
            code=code['code'],
            redirect_uri=request.redirect_uri,
            scopes=request.scopes,
            user=self.current_user()
        )
        log.debug("Set Grant Token with key {0}".format(grant.key))
        self.cache.set(grant.key, dict(grant))

    def get(self, client_id, code):
        """Gets the grant token with the configured cache system"""
        grant = Grant(self.cache, client_id=client_id, code=code)
        kwargs = self.cache.get(grant.key)
        if kwargs:
            log.debug("Grant Token found with key {0}".format(grant.key))
            for k, v in kwargs.items():
                setattr(grant, k, v)
            return grant
        log.debug("Grant Token not found with key {0}".format(grant.key))
        return None


class SQLAlchemyBinding(object):
    """Configures the given :class:`OAuth2Provider` instance with the
    required getters and setters for persistence with SQLAlchemy.

    An example of using all models::

        oauth = OAuth2Provider(app)

        SQLAlchemyBinding(oauth, session, user=User, client=Client,
                          token=Token, grant=Grant, current_user=current_user)

    You can omit any model if you wish to register the functions yourself.
    It is also possible to override the functions by registering them
    afterwards::

        oauth = OAuth2Provider(app)

        SQLAlchemyBinding(oauth, session, user=User, client=Client,
                          token=Token)

        @oauth.grantgetter
        def get_grant(client_id, code):
            pass

        @oauth.grantsetter
        def set_grant(client_id, code, request, *args, **kwargs):
            pass

        # register tokensetter with oauth but keeping the tokengetter
        # registered by `SQLAlchemyBinding`
        # You would only do this for the token and grant since user and client
        # only have getters
        @oauth.tokensetter
        def set_token(token, request, *args, **kwargs):
            pass

    Note that current_user is only required if you're using SQLAlchemy
    for grant caching. If you're using another caching system with
    GrantCacheBinding instead, omit current_user.

    :param provider: :class:`OAuth2Provider` instance
    :param session: A :class:`Session` object
    :param user: :class:`User` model
    :param client: :class:`Client` model
    :param token: :class:`Token` model
    :param grant: :class:`Grant` model
    :param current_user: function that returns a :class:`User` object

    """

    def __init__(self, provider, session, user=None, client=None,
                 token=None, grant=None, current_user=None):

        if user:
            user_binding = UserBinding(user, session)
            provider.usergetter(user_binding.get)

        if client:
            client_binding = ClientBinding(client, session)
            provider.clientgetter(client_binding.get)

        if token:
            token_binding = TokenBinding(token, session)
            provider.tokengetter(token_binding.get)
            provider.tokensetter(token_binding.set)

        if grant:
            if not current_user:
                raise ValueError(('`current_user` is required'
                                  'for Grant Binding'))
            grant_binding = GrantBinding(grant, session, current_user)
            provider.grantgetter(grant_binding.get)
            provider.grantsetter(grant_binding.set)


class BaseBinding(object):
    """Base Binding

    :param model: SQLAlchemy Model class
    :param session: A :class:`Session` object
    """

    def __init__(self, model, session):
        self.session = session
        self.model = model

    @property
    def query(self):
        """Determines which method of getting the query object for use"""
        if hasattr(self.model, 'query'):
            return self.model.query
        else:
            return self.session.query(self.model)


class UserBinding(BaseBinding):
    """Object use by SQLAlchemyBinding to register the user getter"""

    def get(self, username, password, *args, **kwargs):
        """Returns the User object

        Returns None if the user isn't found or the passwords don't match

        :param username: username of the user
        :param password: password of the user
        """
        user = self.query.filter_by(username=username).first()
        if user and user.check_password(password):
            return user
        return None


class ClientBinding(BaseBinding):
    """Object use by SQLAlchemyBinding to register the client getter"""

    def get(self, client_id):
        """Returns a Client object with the given client ID

        :param client_id: ID if the client
        """
        return self.query.filter_by(client_id=client_id).first()


class TokenBinding(BaseBinding):
    """Object use by SQLAlchemyBinding to register the token
    getter and setter
    """

    def get(self, access_token=None, refresh_token=None):
        """returns a Token object with the given access token or refresh token

        :param access_token: User's access token
        :param refresh_token: User's refresh token
        """
        if access_token:
            return self.query.filter_by(access_token=access_token).first()
        elif refresh_token:
            return self.query.filter_by(refresh_token=refresh_token).first()
        return None

    def set(self, token, request, *args, **kwargs):
        """Creates a Token object and removes all expired tokens that belong
        to the user

        :param token: token object
        :param request: OAuthlib request object
        """
        tokens = self.query.filter_by(client_id=request.client.client_id,
                                      user_id=request.user.id).all()
        if tokens:
            for tk in tokens:
                self.session.delete(tk)
            self.session.commit()

        expires_in = token.get('expires_in')
        expires = datetime.utcnow() + timedelta(seconds=expires_in)

        tok = self.model(**token)
        tok.expires = expires
        tok.client_id = request.client.client_id
        tok.user_id = request.user.id

        self.session.add(tok)
        self.session.commit()
        return tok


class GrantBinding(BaseBinding):
    """Object use by SQLAlchemyBinding to register the grant
    getter and setter
    """

    def __init__(self, model, session, current_user):
        self.current_user = current_user
        super(GrantBinding, self).__init__(model, session)

    def set(self, client_id, code, request, *args, **kwargs):
        """Creates Grant object with the given params

        :param client_id: ID of the client
        :param code:
        :param request: OAuthlib request object
        """
        expires = datetime.utcnow() + timedelta(seconds=100)
        grant = self.model(
            client_id=request.client.client_id,
            code=code['code'],
            redirect_uri=request.redirect_uri,
            scope=' '.join(request.scopes),
            user=self.current_user(),
            expires=expires
        )
        self.session.add(grant)

        self.session.commit()

    def get(self, client_id, code):
        """Get the Grant object with the given client ID and code

        :param client_id: ID of the client
        :param code:
        """
        return self.query.filter_by(client_id=client_id, code=code).first()
