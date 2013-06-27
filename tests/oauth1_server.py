# coding: utf-8
from datetime import datetime, timedelta
from flask import g, render_template, request, jsonify
from flask.ext.sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_oauthlib.provider import OAuth1Provider


db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.Unicode(40), unique=True, index=True,
                         nullable=False)


class Client(db.Model):
    #id = db.Column(db.Integer, primary_key=True)
    # human readable name
    client_key = db.Column(db.Unicode(40), primary_key=True)
    client_secret = db.Column(db.Unicode(55), unique=True, index=True,
                              nullable=False)
    rsa_key = db.Column(db.Unicode(55))
    _realms = db.Column(db.UnicodeText)
    _redirect_uris = db.Column(db.UnicodeText)

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
    def realms(self):
        if self._realms:
            return self._realms.split()
        return []


class Grant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id', ondelete='CASCADE')
    )
    user = relationship('User')

    client_key = db.Column(
        db.Unicode(40), db.ForeignKey('client.client_key'),
        nullable=False,
    )
    client = relationship('Client')

    request_token = db.Column(db.Unicode(255), index=True, nullable=False)
    request_token_secret = db.Column(db.Unicode(255), nullable=False)

    verifier = db.Column(db.Unicode(255), nullable=False)

    expires = db.Column(db.DateTime)
    redirect_uri = db.Column(db.UnicodeText)
    _realms = db.Column(db.UnicodeText)

    def delete(self):
        db.session.delete(self)
        db.session.commit()
        return self

    @property
    def realms(self):
        if self._realms:
            return self._realms.split()
        return []


class Token(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_key = db.Column(
        db.Unicode(40), db.ForeignKey('client.client_key'),
        nullable=False,
    )
    client = relationship('Client')

    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id'),
    )
    user = relationship('User')

    access_token = db.Column(db.Unicode(255))
    access_token_secret = db.Column(db.Unicode(255))

    _realms = db.Column(db.UnicodeText)

    def __init__(self, **kwargs):
        expires_in = kwargs.get('expires_in')
        self.expires = datetime.utcnow() + timedelta(seconds=expires_in)
        for k, v in kwargs.items():
            setattr(self, k, v)

    @property
    def realms(self):
        if self._realms:
            return self._realms.split()
        return []


def prepare_app(app):
    db.init_app(app)
    db.app = app
    db.create_all()

    client1 = Client(
        client_key=u'dev', client_secret=u'dev',
        _redirect_uris=u'http://localhost:8000/authorized'
    )

    user = User(username=u'admin')

    try:
        db.session.add(client1)
        db.session.add(user)
        db.session.commit()
    except:
        db.session.rollback()
    return app


def create_server(app):
    app = prepare_app(app)

    oauth = OAuth1Provider(app)

    @oauth.clientgetter
    def get_client(client_key):
        return Client.query.filter_by(client_key=client_key).first()

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

    @app.route('/oauth/request_token')
    @oauth.request_token_handler
    def request_token():
        return {}

    @app.route('/oauth/access_token')
    @oauth.access_token_handler
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
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///oauth1.sqlite'
    })
    app = create_server(app)
    app.run()
