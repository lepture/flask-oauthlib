import logging

from flask import Flask, redirect, url_for, session, request, jsonify, flash, current_app
from flask_oauthlib.client import OAuth, OAuthException

from flask.ext.login import login_user, logout_user, login_required, current_user, session

from . import auth
from ...models import User


'''
Inspired from Miguel Grinberg's multi-provider example, which uses rauth.

See:
http://blog.miguelgrinberg.com/post/oauth-authentication-with-flask
https://github.com/miguelgrinberg/flask-oauth-example/blob/master/oauth.py

This RemoteAppMgr uses oauthlib, via flask_oauthlib, integrated within the
same

'''

class RemoteAppMgr(object):
    oauth = None
    remote_apps = None

    def __init__(self, provider_name):
        self.provider_name = provider_name
        credentials = current_app.config['OAUTH_CREDENTIALS'][provider_name]
        self.consumer_id = credentials['id']
        self.consumer_secret = credentials['secret']

    def index(self):
        pass

    def login(self):
        pass

    def logout(self):
        pass


    @classmethod
    def get_remote_app(self, provider_name):
        if self.oauth is None:
            self.oauth = OAuth(current_app)
        if self.remote_apps is None:
            self.remote_apps = {}
            for provider_class in self.__subclasses__():
                provider = provider_class()
                self.remote_apps[provider.provider_name] = provider
        return self.remote_apps[provider_name]



class GoogleRemoteApp(RemoteAppMgr):
    def __init__(self):
        super(GoogleRemoteApp, self).__init__('google')
        oauth_credentials = current_app.config['OAUTH_CREDENTIALS']['google']
        self.remote_app = self.oauth.remote_app(
            'google',
            consumer_key=oauth_credentials.get('id'),
            consumer_secret=oauth_credentials.get('secret'),
            request_token_params={
                'scope': 'https://www.googleapis.com/auth/userinfo.email'
            },
            base_url='https://www.googleapis.com/oauth2/v1/',
            request_token_url=None,
            access_token_method='POST',
            access_token_url='https://accounts.google.com/o/oauth2/token',
            authorize_url='https://accounts.google.com/o/oauth2/auth',
        )
        self.remote_app._tokengetter = self.get_oauth_token


    def index(self):
        print "Google / Index"
        if 'google_token' in session:
            oauth_provider = self.remote_app.name            # or "google"
            userinfo = self.remote_app.get('userinfo')
            oauth_id = "google$" + userinfo.data.get('id')
            email = userinfo.data.get('email')
            return oauth_login_user(oauth_provider, oauth_id, email, userinfo)
        return redirect(url_for('.oauth_login', provider=self.remote_app.name))

    def login(self):
        print "Google / Login"
        return self.remote_app.authorize(callback=url_for('.oauth_callback', provider=self.remote_app.name, _external=True))

    def logout(self):
        session.pop('google_token', None)
        return redirect('/')

    def authorized(self):
        print "Google / Authorized"
        resp = self.remote_app.authorized_response()
        if resp is None:
            return 'Access denied: reason=%s error=%s' % (
                request.args['error_reason'],
                request.args['error_description']
            )
        session['google_token'] = (resp['access_token'], '')
        userinfo = self.remote_app.get('userinfo').data

        oauth_provider = "google"
        oauth_id = userinfo.get('id')
        email = userinfo.get('email')

        return oauth_login_user(oauth_provider, oauth_id, email, userinfo)


    def get_oauth_token(self):
        return session.get('google_token')




class TwitterRemoteApp(RemoteAppMgr):
    def __init__(self):
        super(TwitterRemoteApp, self).__init__('twitter')
        oauth_credentials = current_app.config['OAUTH_CREDENTIALS']['twitter']
        self.remote_app = self.oauth.remote_app(
            'twitter',
            consumer_key=oauth_credentials.get('id'),
            consumer_secret=oauth_credentials.get('secret'),
            base_url='https://api.twitter.com/1.1/',
            request_token_url='https://api.twitter.com/oauth/request_token',
            access_token_url='https://api.twitter.com/oauth/access_token',
            authorize_url='https://api.twitter.com/oauth/authenticate',
        )
        self.remote_app._tokengetter = self.get_oauth_token


    def index(self):
        if 'google_token' in session:
            me = self.remote_app.get('userinfo')
            return jsonify({"data": me.data})
        return redirect(url_for('.oauth_login', provider=self.remote_app.name))  # provider='google'

    def login(self):
        return self.remote_app.authorize(callback=url_for('.oauth_callback', provider=self.remote_app.name, _external=True))

    def logout(self):
        session.pop('twitter_oauth', None)
        return redirect('/')

    def authorized(self):
        resp = self.remote_app.authorized_response()
        if resp is None:
            flash('Access denied: reason=%s error=%s' % (
                request.args['error_reason'],
                request.args['error_description']))
            return redirect('/')

        session['twitter_oauth'] = resp
        userinfo = self.remote_app.get('account/verify_credentials.json').data

        oauth_provider = "twitter"
        oauth_id = userinfo.get('id')
        email = userinfo.get('email')

        return oauth_login_user(oauth_provider, oauth_id, email, userinfo)


    def get_oauth_token(self):
        if 'twitter_oauth' in session:
            resp = session['twitter_oauth']
            return resp['oauth_token'], resp['oauth_token_secret']



class FacebookRemoteApp(RemoteAppMgr):
    def __init__(self):
        super(FacebookRemoteApp, self).__init__('facebook')
        oauth_credentials = current_app.config['OAUTH_CREDENTIALS']['facebook']
        self.remote_app = self.oauth.remote_app(
            'facebook',
            consumer_key=oauth_credentials.get('id'),
            consumer_secret=oauth_credentials.get('secret'),
            request_token_params={
                'scope': 'email'
            },
            base_url='https://graph.facebook.com',
            request_token_url=None,
            access_token_url='/oauth/access_token',
            authorize_url='https://www.facebook.com/dialog/oauth'
        )
        self.remote_app._tokengetter = self.get_oauth_token


    def index(self):
        if 'google_token' in session:
            me = self.remote_app.get('userinfo')
            return jsonify({"data": me.data})
        return redirect(url_for('.oauth_login', provider=self.remote_app.name))  # provider='google'


    def login(self):
        callback = url_for('.oauth_callback', provider=self.remote_app.name,
                           next=request.args.get('next') or request.referrer or None,
                           _external=True)
        return self.remote_app.authorize(callback=callback)


    def logout(self):
        session.pop('twitter_oauth', None)
        return redirect('/')


    def authorized(self):
        resp = self.remote_app.authorized_response()
        if resp is None:
            flash('Access denied: reason=%s error=%s' % (
                request.args['error_reason'],
                request.args['error_description']))
            return redirect('/')

        if isinstance(resp, OAuthException):
            return 'Access denied: %s' % resp.message

        session['oauth_token'] = (resp['access_token'], '')
        userinfo = self.remote_app.get('/me').data

        oauth_provider = "facebook"
        oauth_id = userinfo.get('id')
        email = userinfo.get('email')
        return oauth_login_user(oauth_provider, oauth_id, email, userinfo)


    def get_oauth_token(self):
        return session.get('oauth_token')



@auth.route('/oauth/<string:provider>')
def oauth_index(provider):
    remote_app = RemoteAppMgr.get_remote_app(provider)
    return remote_app.index()

@auth.route('/oauth/<string:provider>/login')
def oauth_login(provider):
    remote_app = RemoteAppMgr.get_remote_app(provider)
    return remote_app.login()

@auth.route('/oauth/<string:provider>/logout')
def oauth_logout(provider):
    remote_app = RemoteAppMgr.get_remote_app(provider)
    return remote_app.logout()

@auth.route('/oauth/<string:provider>/callback')
def oauth_callback(provider):
    remote_app = RemoteAppMgr.get_remote_app(provider)
    return remote_app.authorized()



def oauth_login_user(oauth_provider, oauth_id, email, userinfo):
    '''
    End of the oauth login flow:
    User is accepted by id provider.
    See if we know him/already, sign-up if needed, then login.
    '''

    oauth_id = str(oauth_id)
    user = User.query(User.oauth_provider == oauth_provider, User.oauth_id == oauth_id).get()
    if user:
        # User is already known by his oauth_id, just log-in
        login_user(user, True)
        flash('You have been logged in through a ' + oauth_provider + ' session')
        return redirect('/')

    user = User.query(User.email == email).get()
    if user:
        # User is known by his/her email, but not oauth_id.   Add oauth_id to user data
        user.oauth_provider = oauth_provider
        user.oauth_id = oauth_id
        user.oauth_userinfo = userinfo
        user.put()
        login_user(user, True)
        flash('Your social id was added to your profile: ' + oauth_provider + '/' + oauth_id)
        return redirect('/')

    # Create new User.
    # TODO:  consider showing form for user to complete and validate, particularly for Twitter, which does not return email.
    user = User(email=userinfo.get('email'),
                oauth_provider=oauth_provider,
                oauth_id=oauth_id,
                oauth_userinfo=userinfo,
                username=userinfo.get('name'),
                last_name=userinfo.get('family_name'), first_name=userinfo.get('given_name'))
    user.put()
    login_user(user)
    # flash('A new user was created for ' + email)
    return redirect('/')

