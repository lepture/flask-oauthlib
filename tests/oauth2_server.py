# coding: utf-8
import datetime
from flask import g, render_template, request, jsonify
from flask.ext.sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_oauthlib.provider import OAuth2Provider


db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.Unicode(40), unique=True, index=True,
                         nullable=False)


class Client(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # human readable name
    name = db.Column(db.Unicode(40))
    client_id = db.Column(db.Unicode(40), unique=True, index=True,
                          nullable=False)
    client_secret = db.Column(db.Unicode(55), unique=True, index=True,
                              nullable=False)
    client_type = db.Column(db.Unicode(20), default=u'public')
    _redirect_uris = db.Column(db.UnicodeText)
    default_scope = db.Column(db.UnicodeText)

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

    client_id = db.Column(db.Unicode(40), nullable=False)
    code = db.Column(db.Unicode(255), index=True, nullable=False)

    redirect_uri = db.Column(db.Unicode(255))
    scope = db.Column(db.UnicodeText)
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
    client_id = db.Column(db.Unicode(40), nullable=False)
    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id', ondelete='CASCADE')
    )
    user = relationship('User')
    token_type = db.Column(db.Unicode(40))
    access_token = db.Column(db.Unicode(255))
    refresh_token = db.Column(db.Unicode(255))
    expires = db.Column(db.DateTime)
    scope = db.Column(db.UnicodeText)

    def __init__(self, **kwargs):
        expires_in = kwargs.get('expires_in')
        self.expires = datetime.datetime.utcnow() + \
                datetime.timedelta(seconds=expires_in)
        for k, v in kwargs.items():
            setattr(self, k, v)

    @property
    def scopes(self):
        if self.scope:
            return self.scope.split()
        return []


def prepare_app(app):
    db.init_app(app)
    db.app = app
    db.create_all()

    client = Client(
        name=u'dev', client_id=u'dev', client_secret=u'dev',
        _redirect_uris=u'http://localhost:8000/authorized'
    )
    user = User(username=u'admin')
    try:
        db.session.add(user)
        db.session.add(client)
        db.session.commit()
    except:
        pass
    return app


def create_server(app):
    app = prepare_app(app)

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
        expires = datetime.datetime.utcnow() + datetime.timedelta(seconds=100)
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

    @app.route('/oauth/access_token')
    @oauth.access_token_handler
    def access_token():
        return {}

    @app.route('/api/email')
    @oauth.require_oauth(['email'])
    def email(data):
        return jsonify(email='me@oauth.net', username=data.user.username)

    @app.route('/api/address')
    @oauth.require_oauth(['address'])
    def address(data):
        return jsonify(address='earth', username=data.user.username)

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
