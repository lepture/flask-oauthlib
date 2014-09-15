Client
======

The client part keeps the same API as `Flask-OAuth`_. The only changes are
the imports::

    from flask_oauthlib.client import OAuth

.. attention:: If you are testing the provider and the client locally, do not
   make them start listening on the same address because they will
   override the `session` of each other leading to strange bugs.
   eg: start the provider listening on `127.0.0.1:4000` and client
   listening on `localhost:4000` to avoid this problem.

.. _`Flask-OAuth`: http://pythonhosted.org/Flask-OAuth/


OAuth1 Client
-------------

The difference between OAuth1 and OAuth2 in the configuation is
``request_token_url``. In OAuth1 it is required, in OAuth2 it should be
``None``.

To connect to a remote application create a :class:`OAuth`
object and register a remote application on it using
the :meth:`~OAuth.remote_app` method::

    from flask_oauthlib.client import OAuth

    oauth = OAuth()
    the_remote_app = oauth.remote_app('the remote app',
        ...
    )

A remote application must define several URLs required by the
OAuth machinery:

- `request_token_url`
- `access_token_url`
- `authorize_url`

Additionally the application should define an issued `consumer_key`
and `consumer_secret`.

You can find these values by registering your application with the remote
application you want to connect with.

Additionally you can provide a `base_url` that is prefixed to *all*
relative URLs used in the remote app.

For Twitter the setup would look like this::

    twitter = oauth.remote_app('twitter',
        base_url='https://api.twitter.com/1/',
        request_token_url='https://api.twitter.com/oauth/request_token',
        access_token_url='https://api.twitter.com/oauth/access_token',
        authorize_url='https://api.twitter.com/oauth/authenticate',
        consumer_key='<your key here>',
        consumer_secret='<your secret here>'
    )

Now that the application is created one can start using the OAuth system.
One thing is missing: the tokengetter. OAuth uses a token and a secret to
figure out who is connecting to the remote application.  After
authentication/authorization this information is passed to a function on
your side and it is your responsibility to remember it.

The following rules apply:

-   It's your responsibility to store that information somewhere
-   That information lives for as long as the user did not revoke the
    access for your application on the remote application.  If it was
    revoked and the user re-enabled the application you will get different
    keys, so if you store them in the database don't forget to check if
    they changed in the authorization callback.
-   During the authorization handshake a temporary token and secret are
    issued. Your tokengetter is not used during that period.

For a simple test application, storing that information in the session is
probably sufficient::

    from flask import session

    @twitter.tokengetter
    def get_twitter_token(token=None):
        return session.get('twitter_token')

If the token does not exist, the function must return `None`, and
otherwise return a tuple in the form ``(token, secret)``.  The function
might also be passed a `token` parameter.  This is user defined and can be
used to indicate another token.  Imagine for instance you want to support
user and application tokens or different tokens for the same user.

The name of the token can be passed to to the
:meth:`~OAuthRemoteApp.request` function.

Signing in / Authorizing
------------------------

To sign in with Twitter or link a user account with a remote
Twitter user, simply call into
:meth:`~OAuthRemoteApp.authorize` and pass it the URL that the user should be
redirected back to. For example::

    @app.route('/login')
    def login():
        return twitter.authorize(callback=url_for('oauth_authorized',
            next=request.args.get('next') or request.referrer or None))

If the application redirects back, the remote application can fetch
all relevant information in the `oauth_authorized` function with
:meth:`~OAuthRemoteApp.authorized_response`::

    from flask import redirect

    @app.route('/oauth-authorized')
    def oauth_authorized():
        next_url = request.args.get('next') or url_for('index')
        resp = twitter.authorized_response()
        if resp is None:
            flash(u'You denied the request to sign in.')
            return redirect(next_url)

        session['twitter_token'] = (
            resp['oauth_token'],
            resp['oauth_token_secret']
        )
        session['twitter_user'] = resp['screen_name']

        flash('You were signed in as %s' % resp['screen_name'])
        return redirect(next_url)

We store the token and the associated secret in the session so that the
tokengetter can return it.  Additionally, we also store the Twitter username
that was sent back to us so that we can later display it to the user.  In
larger applications it is recommended to store satellite information in a
database instead to ease debugging and more easily handle additional information
associated with the user.

Facebook OAuth
--------------

For Facebook the flow is very similar to Twitter or other OAuth systems
but there is a small difference.  You're not using the `request_token_url`
at all and you need to provide a scope in the `request_token_params`::

    facebook = oauth.remote_app('facebook',
        base_url='https://graph.facebook.com/',
        request_token_url=None,
        access_token_url='/oauth/access_token',
        authorize_url='https://www.facebook.com/dialog/oauth',
        consumer_key=FACEBOOK_APP_ID,
        consumer_secret=FACEBOOK_APP_SECRET,
        request_token_params={'scope': 'email'}
    )

Furthermore the `callback` is mandatory for the call to
:meth:`~OAuthRemoteApp.authorize` and has to match the base URL that was
specified in the Facebook application control panel.  For development you
can set it to ``localhost:5000``.

The `APP_ID` and `APP_SECRET` can be retrieved from the Facebook app
control panel.  If you don't have an application registered yet you can do
this at `facebook.com/developers <https://www.facebook.com/developers/createapp.php>`_.

Invoking Remote Methods
-----------------------

Now the user is signed in, but you probably want to use
OAuth to call protected remote API methods and not just sign in.  For
that, the remote application object provides a
:meth:`~OAuthRemoteApp.request` method that can request information from
an OAuth protected resource.  Additionally there are shortcuts like
:meth:`~OAuthRemoteApp.get` or :meth:`~OAuthRemoteApp.post` to request
data with a certain HTTP method.

For example to create a new tweet you would call into the Twitter
application as follows::

    resp = twitter.post('statuses/update.json', data={
        'status':   'The text we want to tweet'
    })
    if resp.status == 403:
        flash('Your tweet was too long.')
    else:
        flash('Successfully tweeted your tweet (ID: #%s)' % resp.data['id'])

Or to display the users' feed we can do something like this::

    resp = twitter.get('statuses/home_timeline.json')
    if resp.status == 200:
        tweets = resp.data
    else:
        tweets = None
        flash('Unable to load tweets from Twitter. Maybe out of '
              'API calls or Twitter is overloaded.')

Flask-OAuthlib will do its best to send data encoded in the right format to
the server and to decode it when it comes back.  Incoming data is encoded
based on the `mimetype` the server sent and is stored in the
:attr:`~OAuthResponse.data` attribute.  For outgoing data a default of
``'urlencode'`` is assumed. When a different format is needed, one can
specify it with the `format` parameter.  The following formats are
supported:

**Outgoing**:
    - ``'urlencode'`` - form encoded data (`GET` as URL and `POST`/`PUT` as
      request body)
    - ``'json'`` - JSON encoded data (`POST`/`PUT` as request body)

**Incoming**
    - ``'urlencode'`` - stored as flat unicode dictionary
    - ``'json'`` - decoded with JSON rules, most likely a dictionary
    - ``'xml'`` - stored as elementtree element

Unknown incoming data is stored as a string.  If outgoing data of a different
format is needed, `content_type` should be specified instead and the
data provided should be an encoded string.


Find the OAuth1 client example at `twitter.py`_.

.. _`twitter.py`: https://github.com/lepture/flask-oauthlib/blob/master/example/twitter.py


OAuth2 Client
-------------

Find the OAuth2 client example at `github.py`_.

.. _`github.py`: https://github.com/lepture/flask-oauthlib/blob/master/example/github.py

.. versionadded:: 0.4.2

Request state parameters in authorization can be a function::

    from werkzeug import security

    remote = oauth.remote_app(
        request_token_params={
            'state': lambda: security.gen_salt(10)
        }
    )


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

.. versionadded:: 0.4.0

Or looks like that::

    app.config['TWITTER_CONSUMER_KEY'] = 'a random string key'
    app.config['TWITTER_CONSUMER_SECRET'] = 'a random string secret'

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
