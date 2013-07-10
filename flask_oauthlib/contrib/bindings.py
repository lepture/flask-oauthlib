# coding: utf-8
"""
    flask_oauthlib.contrib.sqlalchemy
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    SQLAlchemy and Cache support for OAuth2 provider.

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


log = logging.getLogger('flask_oauthlib')


class Grant(object):
    """Grant object returned back to the provider

    :param cache: cache instance
    :param client_id:
    :param code:
    :param redirect_uri:
    :param scopes: a space delimited list of scopes
    :param user: user object returned from self.current_user
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
        """Removes itself from the cache"""
        log.debug("Deleting grant")
        log.debug("Code: {0}".format(self.code))
        log.debug("Client id: {0}".format(self.client_id))
        self._cache.delete(self.key)
        return None

    @property
    def key(self):
        """String used as the key for the cache"""
        key = '{code}{client_id}'.format(
            code=self.code,
            client_id=self.client_id
        )
        return key

    def __getitem__(self, item):
        return getattr(self, item)

    def keys(self):
        return ['client_id', 'code', 'redirect_uri', 'scopes']


class GrantCacheBinding(object):
    """
    """

    def __init__(self, app, provider, current_user, config=None):

        if config is None:
            config = app.config

        self.current_user = current_user

        config.setdefault('OAUTH2_CACHE_DEFAULT_TIMEOUT', 100)
        config.setdefault('OAUTH2_CACHE_THRESHOLD', 500)
        config.setdefault('OAUTH2_CACHE_KEY_PREFIX', None)
        config.setdefault('OAUTH2_CACHE_MEMCACHED_SERVERS', None)
        config.setdefault('OAUTH2_CACHE_REDIS_HOST', 'localhost')
        config.setdefault('OAUTH2_CACHE_REDIS_PORT', 6379)
        config.setdefault('OAUTH2_CACHE_REDIS_PASSWORD', None)
        config.setdefault('OAUTH2_CACHE_REDIS_DB', 0)
        config.setdefault('OAUTH2_CACHE_DIR', None)
        config.setdefault('OAUTH2_CACHE_MODE', '0600')
        config.setdefault('OAUTH2_CACHE_TYPE', 'null')

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
        return NullCache()

    def _simple(self, kwargs):
        kwargs.update(dict(threshold=self.config['OAUTH2_CACHE_THRESHOLD']))
        return SimpleCache(**kwargs)

    def _memcache(self, kwargs):
        kwargs.update(dict(
            servers=self.config['OAUTH2_CACHE_MEMCACHED_SERVERS'],
            key_prefix=self.config['OAUTH2_CACHE_KEY_PREFIX']
        ))
        return MemcachedCache(**kwargs)

    def _redis(self, kwargs):
        kwargs.update(dict(
            host=self.config['OAUTH2_CACHE_REDIS_HOST'],
            port=self.config['OAUTH2_CACHE_REDIS_PORT'],
            password=self.config['OAUTH2_CACHE_REDIS_PASSWORD'],
            db=self.config['OAUTH2_CACHE_REDIS_DB'],
            key_prefix=self.config['OAUTH2_CACHE_KEY_PREFIX']
        ))
        return RedisCache(**kwargs)

    def _filesystem(self, kwargs):
        kwargs.update(dict(
            threshold=self.config['OAUTH2_CACHE_THRESHOLD']
        ))
        return FileSystemCache(self.config['OAUTH2_CACHE_DIR'], **kwargs)

    def set(self, client_id, code, request, *args, **kwargs):
        log.debug("SET GRANT")
        grant = Grant(
            self.cache,
            client_id=request.client.client_id,
            code=code['code'],
            redirect_uri=request.redirect_uri,
            scopes=request.scopes,
            user=self.current_user()
        )
        self.cache.set(grant.key, dict(grant))

    def get(self, client_id, code):
        log.debug("GET GRANT")
        grant = Grant(self.cache, client_id=client_id,
                      code=code, user=self.current_user())
        kwargs = self.cache.get(grant.key)
        log.debug("KWARGS: {0}".format(kwargs))
        if kwargs:
            for k, v in kwargs.iteritems():
                setattr(grant, k, v)
            return grant
        log.debug("GET NOT FOUND")
        return None


class SQLAlchemyBinding(object):

    def __init__(self, provider, get_session, user=None, client=None,
                 token=None, grant=None, current_user=None):

        if user:
            user_binding = UserBinding(user, get_session)
            provider.usergetter(user_binding.get)

        if client:
            client_binding = ClientBinding(client, get_session)
            provider.clientgetter(client_binding.get)

        if token:
            token_binding = TokenBinding(token, get_session)
            provider.tokengetter(token_binding.get)
            provider.tokensetter(token_binding.set)

        if grant:
            if not current_user:
                raise ValueError(('`current_user` is required'
                                  'for Grant Binding'))
            grant_binding = GrantBinding(grant, get_session, current_user)
            provider.grantgetter(grant_binding.get)
            provider.grantsetter(grant_binding.set)


class BaseBinding(object):

    def __init__(self, model, get_session):
        self.get_session = get_session
        # self.query = _QueryObject(model, get_session)
        self.model = model

    @property
    def query(self):
        log.debug('GET QUERY')
        if hasattr(self.model, 'query'):
            return self.model.query
        else:
            return self.get_session().query(self.model)


class UserBinding(BaseBinding):

    def get(self, username, password, *args, **kwargs):
        user = self.query.filter_by(username=username).first()
        if user.check_password(password):
            return user
        return None


class ClientBinding(BaseBinding):

    def get(self, client_id):
        # log.debug("QUERY {}".format(self.query))
        return self.query.filter_by(client_id=client_id).first()


class TokenBinding(BaseBinding):

    def get(self, access_token=None, refresh_token=None):
        if access_token:
            return self.query.filter_by(access_token=access_token).first()
        elif refresh_token:
            return self.query.filter_by(refresh_token=refresh_token).first()
        return None

    def set(self, token, request, *args, **kwargs):
        session = self.get_session()
        tokens = self.query.filter_by(client_id=request.client.client_id,
                                      user_id=request.user.id).all()
        if tokens:
            for tk in tokens:
                session.delete(tk)
            session.commit()

        expires_in = token.get('expires_in')
        expires = datetime.utcnow() + timedelta(seconds=expires_in)

        tok = self.model(**token)
        tok.expires = expires
        tok.client_id = request.client.client_id
        tok.user_id = request.user.id

        session.add(tok)
        session.commit()
        return tok


class GrantBinding(BaseBinding):

    def __init__(self, model, session, current_user):
        self.current_user = current_user
        super(GrantBinding, self).__init__(model, session)

    def set(self, client_id, code, request, *args, **kwargs):
        session = self.get_session()
        expires = datetime.utcnow() + timedelta(seconds=100)
        grant = self.model(
            client_id=request.client.client_id,
            code=code['code'],
            redirect_uri=request.redirect_uri,
            scope=' '.join(request.scopes),
            user=self.current_user(),
            expires=expires
        )
        session.add(grant)

        session.commit()

    def get(self, client_id, code):
        return self.query.filter_by(client_id=client_id, code=code).first()
