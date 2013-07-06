# coding: utf-8
from flask import g, render_template, request, jsonify
from flask.ext.sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from sqlalchemy.orm import relationship


db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.Unicode(40), unique=True, index=True,
                         nullable=False)

    def check_password(self, password):
        return True


class Client(db.Model):
    #id = db.Column(db.Integer, primary_key=True)
    # human readable name
    name = db.Column(db.Unicode(40))
    client_id = db.Column(db.Unicode(40), primary_key=True)
    client_secret = db.Column(db.Unicode(55), unique=True, index=True,
                              nullable=False)
    client_type = db.Column(db.Unicode(20), default=u'public')
    _redirect_uris = db.Column(db.UnicodeText)
    default_scope = db.Column(db.UnicodeText)

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
        db.Unicode(40), db.ForeignKey('client.client_id', ondelete='CASCADE'),
        nullable=False,
    )
    client = relationship('Client')
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
    client_id = db.Column(
        db.Unicode(40), db.ForeignKey('client.client_id', ondelete='CASCADE'),
        nullable=False,
    )
    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id', ondelete='CASCADE')
    )
    user = relationship('User')
    client = relationship('Client')
    token_type = db.Column(db.Unicode(40))
    access_token = db.Column(db.Unicode(255))
    refresh_token = db.Column(db.Unicode(255))
    expires = db.Column(db.DateTime)
    scope = db.Column(db.UnicodeText)

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


def setup_oauth(app, oauth):

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


def create_server(app):
    db.init_app(app)
    db.app = app
    db.create_all()

    client1 = Client(
        name=u'dev', client_id=u'dev', client_secret=u'dev',
        _redirect_uris=u'http://localhost:8000/authorized'
    )

    client2 = Client(
        name=u'confidential', client_id=u'confidential',
        client_secret=u'confidential', client_type=u'confidential',
        _redirect_uris=u'http://localhost:8000/authorized'
    )

    user = User(username=u'admin')

    try:
        db.session.add(client1)
        db.session.add(client2)
        db.session.add(user)
        db.session.commit()
    except:
        db.session.rollback()

    @app.before_request
    def load_current_user():
        user = User.query.get(1)
        g.user = user

    @app.route('/home')
    def home():
        return render_template('home.html')

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
