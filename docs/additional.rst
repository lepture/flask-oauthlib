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
        from flask_oauthlib.utils import extract_params
        uri, http_method, body, headers = extract_params()
        request = oauth._create_request(uri, http_method, body, headers)

        client_id = request.client_key
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

.. versionchanged:: 0.4

.. module:: flask_oauthlib.contrib.oauth2

Bindings are objects you can use to configure flask-oauthlib for use with
various data stores. They allow you to define the required getters and setters
for each data store with little effort.

SQLAlchemy OAuth2
`````````````````

:meth:`bind_sqlalchemy` sets up getters and setters for storing the user,
client, token and grant with SQLAlchemy, with some sane defaults. To use this
class you'll need to create a SQLAlchemy model for each object. You can find
examples of how to setup your SQLAlchemy models here: ref:`oauth2`.

You'll also need to provide another function which returns the currently
logged-in user.

An example of how to use :meth:`bind_sqlalchemy`::

    oauth = OAuth2Provider(app)

    bind_sqlalchemy(oauth, db.session, user=User, client=Client,
                    token=Token, grant=Grant, current_user=current_user)

Any of the classes can be omitted if you wish to register the getters and
setters yourself::

    oauth = OAuth2Provider(app)

    bind_sqlalchemy(oauth, db.session, user=User, client=Client,
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
The :meth:`bind_cache_grant` allows you to more efficiently cache the grant
token using Memcache, Redis, or some other caching system.

An example::

    oauth = OAuth2Provider(app)
    app.config.update({'OAUTH2_CACHE_TYPE': 'redis'})

    bind_cache_grant(app, oauth, current_user)

- `app`: flask application
- `oauth`: OAuth2Provider instance
- `current_user`: a function that returns the current user

The configuration options are described below. The :meth:`bind_cache_grant`
will use the configuration options from `Flask-Cache` if they are set, else it
will set them to the following defaults. Any configuration specific to
:meth:`bind_cache_grant` will take precedence over any `Flask-Cache`
configuration that has been set.
