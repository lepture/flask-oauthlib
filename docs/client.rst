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
