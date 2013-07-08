Client
======

The client part keeps the same API as `Flask-OAuth`_. The only changes are
the imports::

    from flask_oauthlib.client import OAuth

.. _`Flask-OAuth`: http://pythonhosted.org/Flask-OAuth/


OAuth1 Client
-------------

The difference between OAuth1 and OAuth2 in the configuation is
``request_token_url``. In OAuth1 it is required, in OAuth2 it should be
``None``.

Find the OAuth1 client example at `twitter.py`_.

.. _`twitter.py`: https://github.com/lepture/flask-oauthlib/blob/master/example/twitter.py


OAuth2 Client
-------------

Find the OAuth2 client example at `github.py`_.

.. _`github.py`: https://github.com/lepture/flask-oauthlib/blob/master/example/github.py

.. _lazy-configuration:

Lazy Configuration
------------------

.. versionadded:: 0.3.0

When creating an open source project, we need to keep our consumer key and
consumer secret secret. We usually keep them in a config file, and don't
keep track of the config in the version control.

Client of Flask-OAuthlib has a mechanism for you to lazy load your
configuration from your Flask config object::

    from flask_oauthlib.client import OAuth

    oauth = OAuth()
    twitter = oauth.remote_app(
        'twitter',
        base_url='https://api.twitter.com/1/',
        request_token_url='https://api.twitter.com/oauth/request_token',
        access_token_url='https://api.twitter.com/oauth/access_token',
        authorize_url='https://api.twitter.com/oauth/authenticate',
        app_key='TWITTER'
    )

At this moment, we didn't put the ``consumer_key`` and ``consumer_secret``
in the ``remote_app``, instead, we set a ``app_key``. It will load from
Flask config by the key ``TWITTER``, the configuration looks like::

    app.config['TWITTER'] = {
        'consumer_key': 'a random string key',
        'consumer_secret': 'a random string secret',
    }

    oauth.init_app(app)

Twitter can get consumer key and secret from the Flask instance now.

You can put all the configuration in ``app.config`` if you like, which
means you can do it this way::

    from flask_oauthlib.client import OAuth

    oauth = OAuth()
    twitter = oauth.remote_app(
        'twitter',
        app_key='TWITTER'
    )

    app.config['TWITTER'] = dict(
        consumer_key='a random key',
        consumer_secret='a random secret',
        base_url='https://api.twitter.com/1/',
        request_token_url='https://api.twitter.com/oauth/request_token',
        access_token_url='https://api.twitter.com/oauth/access_token',
        authorize_url='https://api.twitter.com/oauth/authenticate',
    )
    oauth.init_app(app)

Fix non-standard OAuth
----------------------

There are services that claimed they are providing OAuth API, but with a
little differences. Some services even return with the wrong Content Type.

This library takes all theses into consideration. Take an Chinese clone of
twitter which is called weibo as the example. When you implement the
authorization flow, the content type changes in the progress. Sometime it
is application/json which is right. Sometime it is text/plain, which is
wrong. And sometime, it didn't return anything.

We can force to parse the returned response in a specified content type::

    from flask_oauthlib.client import OAuth

    oauth = OAuth()

    weibo = oauth.remote_app(
        'weibo',
        consumer_key='909122383',
        consumer_secret='2cdc60e5e9e14398c1cbdf309f2ebd3a',
        request_token_params={'scope': 'email,statuses_to_me_read'},
        base_url='https://api.weibo.com/2/',
        authorize_url='https://api.weibo.com/oauth2/authorize',
        request_token_url=None,
        access_token_method='POST',
        access_token_url='https://api.weibo.com/oauth2/access_token',

        # force to parse the response in applcation/json
        content_type='application/json',
    )

The weibo site didn't follow the Bearer token, the acceptable header is::

    'OAuth2 a-token-string'

The original behavior of Flask OAuthlib client is::

    'Bearer a-token-string'

We can configure with a `pre_request` method to change the headers::

    def change_weibo_header(uri, headers, body):
        auth = headers.get('Authorization')
        if auth:
            auth = auth.replace('Bearer', 'OAuth2')
            headers['Authorization'] = auth
        return uri, headers, body

    weibo.pre_request = change_weibo_header

You can change uri, headers and body in the pre request.
