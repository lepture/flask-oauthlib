Additional Features
===================

This documentation covers some additional features. They are not required,
but they may be very helpful.

Request Hooks
-------------

Like Flask, Flask-OAuthlib has before_request and after_request hooks too.
It is usually useful for setting limitation on the client request with
before_request::

    @oauth.before_request
    def limit_client_request():
        client_id = request.values.get('client_id')
        if not client_id:
            return
        client = Client.get(client_id)
        if over_limit(client):
            return abort(403)

        track_request(client)

And you can also modify the response with after_request::

    @oauth.after_request
    def valid_after_request(valid, request):
        if request.user in black_list:
            return False, request
        return valid, oauth

Bindings
--------

Bindings are objects you can use to configure flask-oauthlib for use with
various data stores. They allow you to define the required getters and setters
for each data store with little effort.

SQLAlchemy OAuth2
`````````````````

:class:`SQLAlchemyBinding` sets up getters and setters for storing the user,
client, token and grant with SQLAlchemy, with some sane defaults. To use this
class you'll need to create a SQLAlchemy model for each object. You can find
examples of how to setup your SQLAlchemy models here: ref:`oauth2`.

You'll also need to provide another function which returns the currently
logged-in user.

An example of how to use :class:`SQLAlchemyBinding`::

    oauth = OAuth2Provider(app)

    SQLAlchemyBinding(oauth, db.session, user=User, client=Client,
                      token=Token, grant=Grant, current_user=current_user)

Any of the classes can be omitted if you wish to register the getters and
setters yourself::

    oauth = OAuth2Provider(app)

    SQLAlchemyBinding(oauth, db.session, user=User, client=Client,
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

`current_user` is only used with the Grant bindings, therefore if you are going
to register your own grant getter and setter you don't need to provide that
function.

Grant Cache
```````````

Since the life of a Grant token is very short (usually about 100 seconds),
storing it in a relational database is inefficient.
The :class:`GrantCacheBinding` allows you to more efficiently cache the grant
token using Memcache, Redis, or some other caching system.

An example::

    oauth = OAuth2Provider(app)
    config = {'OAUTH2_CACHE_TYPE': 'redis'}

    GrantCacheBinding(app, oauth, current_user, config=config)

- `app`: flask application
- `oauth`: OAuth2Provider instance
- `current_user`: a function that returns the current user
- `config`: Any extra configuration

The configuration options are described below. The :class:`GrantCacheBinding`
will use the configuration options from `Flask-Cache` if they are set, else it
will set them to the following defaults. Any configuration specific to
:class:`GrantCacheBinding` will take precedence over any `Flask-Cache`
configuration that has been set.

+------------------------------------+-------------------------------------------------------------------------------------------------------------------+-------------------------+-------------+
| **Option**                         | **Description**                                                                                                   | **Flask-Cache Default** | **Default** |
+------------------------------------+-------------------------------------------------------------------------------------------------------------------+-------------------------+-------------+
| **OAUTH2_CACHE_DEFAULT_TIMEOUT**   | The default timeout that is used. A grant token expires after this length of time.                                | CACHE_DEFAULT_TIMEOUT   | 100s        |
+------------------------------------+-------------------------------------------------------------------------------------------------------------------+-------------------------+-------------+
| **OAUTH2_CACHE_THRESHOLD**         | The maximum number of items the cache stores before it starts deleting some                                       | CACHE_THRESHOLD         | 500s        |
+------------------------------------+-------------------------------------------------------------------------------------------------------------------+-------------------------+-------------+
| **OAUTH2_CACHE_KEY_PREFIX**        | A prefix that is added before all keys                                                                            | CACHE_KEY_PREFIX        | None        |
+------------------------------------+-------------------------------------------------------------------------------------------------------------------+-------------------------+-------------+
| **OAUTH2_CACHE_MEMCACHED_SERVERS** | A list or tuple of server addresses or alternatively a :class:`memcache.Client` or a compatible client            | CACHE_MEMCACHED_SERVERS | None        |
+------------------------------------+-------------------------------------------------------------------------------------------------------------------+-------------------------+-------------+
| **OAUTH2_CACHE_REDIS_HOST**        | Address of the Redis server or an object which API is compatible with the official Python Redis client (redis-py) | CACHE_REDIS_HOST        | localhost   |
+------------------------------------+-------------------------------------------------------------------------------------------------------------------+-------------------------+-------------+
| **OAUTH2_CACHE_REDIS_PORT**        | Port number on which Redis server listens for connections                                                         | CACHE_REDIS_PORT        | 6379        |
+------------------------------------+-------------------------------------------------------------------------------------------------------------------+-------------------------+-------------+
| **OAUTH2_CACHE_REDIS_PASSWORD**    | Password authentication for the Redis server                                                                      | CACHE_REDIS_PASSWORD    | None        |
+------------------------------------+-------------------------------------------------------------------------------------------------------------------+-------------------------+-------------+
| **OAUTH2_CACHE_REDIS_DB**          | Database (zero-based numeric index) on Redis Server to connect                                                    | CACHE_REDIS_DB          | 0           |
+------------------------------------+-------------------------------------------------------------------------------------------------------------------+-------------------------+-------------+
| **OAUTH2_CACHE_DIR**               | The directory where cache files are stored                                                                        | CACHE_DIR               | None        |
+------------------------------------+-------------------------------------------------------------------------------------------------------------------+-------------------------+-------------+
| **OAUTH2_CACHE_MODE**              | The file mode wanted for the cache files                                                                          | CACHE_MODE              | 0600        |
+------------------------------------+-------------------------------------------------------------------------------------------------------------------+-------------------------+-------------+
| **OAUTH2_CACHE_TYPE**              | The cache system to be used (null, simple, redis, memcache, filesystem)                                           | CACHE_TYPE              | null        |
+------------------------------------+-------------------------------------------------------------------------------------------------------------------+-------------------------+-------------+
