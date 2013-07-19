# coding: utf-8
from datetime import datetime, timedelta
from flask import g, render_template, request, jsonify
from flask.ext.sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_oauthlib.provider import OAuth2Provider
from flask_oauthlib.contrib.bindings import (
    SQLAlchemyBinding,
    GrantCacheBinding
)


db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True, index=True,
                         nullable=False)

    def check_password(self, password):
        return True


class Client(db.Model):
    #id = db.Column(db.Integer, primary_key=True)
    # human readable name
    name = db.Column(db.String(40))
    client_id = db.Column(db.String(40), primary_key=True)
    client_secret = db.Column(db.String(55), unique=True, index=True,
                              nullable=False)
    client_type = db.Column(db.String(20), default='public')
    _redirect_uris = db.Column(db.Text)
    default_scope = db.Column(db.Text)

    @property
    def user(self):
        return User.query.get(1)

    @property
    def redirect_uris(self):
        if self._redirect_uris:
            return self._redirect_uris.split()
        return []

    @property
    def default_redirect_uri(self):
        return self.redirect_uris[0]

    @property
    def default_scopes(self):
        if self.default_scope:
            return self.default_scope.split()
        return []


class Grant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id', ondelete='CASCADE')
    )
    user = relationship('User')

    client_id = db.Column(
        db.String(40), db.ForeignKey('client.client_id', ondelete='CASCADE'),
        nullable=False,
    )
    client = relationship('Client')
    code = db.Column(db.String(255), index=True, nullable=False)

    redirect_uri = db.Column(db.String(255))
    scope = db.Column(db.Text)
    expires = db.Column(db.DateTime)

    def delete(self):
        db.session.delete(self)
        db.session.commit()
        return self

    @property
    def scopes(self):
        if self.scope:
            return self.scope.split()
        return None


class Token(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(
        db.String(40), db.ForeignKey('client.client_id', ondelete='CASCADE'),
        nullable=False,
    )
    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id', ondelete='CASCADE')
    )
    user = relationship('User')
    client = relationship('Client')
    token_type = db.Column(db.String(40))
    access_token = db.Column(db.String(255))
    refresh_token = db.Column(db.String(255))
    expires = db.Column(db.DateTime)
    scope = db.Column(db.Text)

    def __init__(self, **kwargs):
        expires_in = kwargs.pop('expires_in')
        self.expires = datetime.utcnow() + timedelta(seconds=expires_in)
        for k, v in kwargs.items():
            setattr(self, k, v)

    @property
    def scopes(self):
        if self.scope:
            return self.scope.split()
        return []


def current_user():
    return g.user


def cache_provider(app):
    oauth = OAuth2Provider(app)

    SQLAlchemyBinding(oauth, db.session, user=User,
                      token=Token, client=Client)

    GrantCacheBinding(app, oauth, current_user,
                      config={'OAUTH2_CACHE_TYPE': 'simple'})

    return oauth


def sqlalchemy_provider(app):
    oauth = OAuth2Provider(app)

    SQLAlchemyBinding(oauth, db.session, user=User, token=Token,
                      client=Client, grant=Grant, current_user=current_user)

    return oauth


def default_provider(app):
    oauth = OAuth2Provider(app)

    @oauth.clientgetter
    def get_client(client_id):
        return Client.query.filter_by(client_id=client_id).first()

    @oauth.grantgetter
    def get_grant(client_id, code):
        return Grant.query.filter_by(client_id=client_id, code=code).first()

    @oauth.tokengetter
    def get_token(access_token=None, refresh_token=None):
        if access_token:
            return Token.query.filter_by(access_token=access_token).first()
        if refresh_token:
            return Token.query.filter_by(refresh_token=refresh_token).first()
        return None

    @oauth.grantsetter
    def set_grant(client_id, code, request, *args, **kwargs):
        expires = datetime.utcnow() + timedelta(seconds=100)
        grant = Grant(
            client_id=client_id,
            code=code['code'],
            redirect_uri=request.redirect_uri,
            scope=' '.join(request.scopes),
            user_id=g.user.id,
            expires=expires,
        )
        db.session.add(grant)
        db.session.commit()

    @oauth.tokensetter
    def set_token(token, request, *args, **kwargs):
        # In real project, a token is unique bound to user and client.
        # Which means, you don't need to create a token every time.
        tok = Token(**token)
        tok.user_id = request.user.id
        tok.client_id = request.client.client_id
        db.session.add(tok)
        db.session.commit()

    @oauth.usergetter
    def get_user(username, password, *args, **kwargs):
        # This is optional, if you don't need password credential
        # there is no need to implement this method
        return User.query.filter_by(username=username).first()

    return oauth


def prepare_app(app):
    db.init_app(app)
    db.app = app
    db.create_all()

    client1 = Client(
        name='dev', client_id='dev', client_secret='dev',
        _redirect_uris=(
            'http://localhost:8000/authorized '
            'http://localhost/authorized'
        ),
    )

    client2 = Client(
        name='confidential', client_id='confidential',
        client_secret='confidential', client_type='confidential',
        _redirect_uris=(
            'http://localhost:8000/authorized '
            'http://localhost/authorized'
        ),
    )

    user = User(username='admin')

    try:
        db.session.add(client1)
        db.session.add(client2)
        db.session.add(user)
        db.session.commit()
    except:
        db.session.rollback()
    return app


def create_server(app, oauth):
    app = prepare_app(app)

    @app.before_request
    def load_current_user():
        user = User.query.get(1)
        g.user = user

    @app.route('/home')
    def home():
        return render_template('home.html')

    @app.route('/oauth/authorize', methods=['GET', 'POST'])
    @oauth.authorize_handler
    def authorize(*args, **kwargs):
        # NOTICE: for real project, you need to require login
        if request.method == 'GET':
            # render a page for user to confirm the authorization
            return render_template('confirm.html')

        confirm = request.form.get('confirm', 'no')
        return confirm == 'yes'

    @app.route('/oauth/token')
    @oauth.token_handler
    def access_token():
        return {}

    @app.route('/api/email')
    @oauth.require_oauth('email')
    def email_api(oauth):
        return jsonify(email='me@oauth.net', username=oauth.user.username)

    @app.route('/api/address/<city>')
    @oauth.require_oauth('address')
    def address_api(oauth, city):
        return jsonify(address=city, username=oauth.user.username)

    @app.route('/api/method', methods=['GET', 'POST', 'PUT', 'DELETE'])
    @oauth.require_oauth()
    def method_api(oauth):
        return jsonify(method=request.method)

    return app


if __name__ == '__main__':
    from flask import Flask
    app = Flask(__name__)
    app.debug = True
    app.secret_key = 'development'
    app.config.update({
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///test.sqlite'
    })
    app = create_server(app)
    app.run()
