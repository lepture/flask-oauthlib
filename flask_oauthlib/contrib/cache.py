# coding: utf-8

from cachelib import NullCache, SimpleCache, FileSystemCache
from cachelib import MemcachedCache, RedisCache


class Cache(object):
    def __init__(self, app, config_prefix='OAUTHLIB', **kwargs):
        self.config_prefix = config_prefix
        self.config = app.config

        cache_type = '_%s' % self._config('type')
        kwargs.update(dict(
            default_timeout=self._config('DEFAULT_TIMEOUT', 100)
        ))

        try:
            self.cache = getattr(self, cache_type)(**kwargs)
        except AttributeError:
            raise RuntimeError(
                '`%s` is not a valid cache type!' % cache_type
            )
        app.extensions[config_prefix.lower() + '_cache'] = self.cache

    def __getattr__(self, key):
        try:
            return object.__getattribute__(self, key)
        except AttributeError:
            try:
                return getattr(self.cache, key)
            except AttributeError:
                raise AttributeError('No such attribute: %s' % key)

    def _config(self, key, default='error'):
        key = key.upper()
        prior = '%s_CACHE_%s' % (self.config_prefix, key)
        if prior in self.config:
            return self.config[prior]
        fallback = 'CACHE_%s' % key
        if fallback in self.config:
            return self.config[fallback]
        if default == 'error':
            raise RuntimeError('%s is missing.' % prior)
        return default

    def _null(self, **kwargs):
        """Returns a :class:`NullCache` instance"""
        return NullCache()

    def _simple(self, **kwargs):
        """Returns a :class:`SimpleCache` instance

        .. warning::

            This cache system might not be thread safe. Use with caution.
        """
        kwargs.update(dict(threshold=self._config('threshold', 500)))
        return SimpleCache(**kwargs)

    def _memcache(self, **kwargs):
        """Returns a :class:`MemcachedCache` instance"""
        kwargs.update(dict(
            servers=self._config('MEMCACHED_SERVERS', None),
            key_prefix=self._config('key_prefix', None),
        ))
        return MemcachedCache(**kwargs)

    def _redis(self, **kwargs):
        """Returns a :class:`RedisCache` instance"""
        kwargs.update(dict(
            host=self._config('REDIS_HOST', 'localhost'),
            port=self._config('REDIS_PORT', 6379),
            password=self._config('REDIS_PASSWORD', None),
            db=self._config('REDIS_DB', 0),
            key_prefix=self._config('KEY_PREFIX', None),
        ))
        return RedisCache(**kwargs)

    def _filesystem(self, **kwargs):
        """Returns a :class:`FileSystemCache` instance"""
        kwargs.update(dict(
            threshold=self._config('threshold', 500),
        ))
        return FileSystemCache(self._config('dir', None), **kwargs)
