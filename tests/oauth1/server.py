# coding: utf-8
from flask import g, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_oauthlib.provider import OAuth1Provider


db = SQLAlchemy()


def enable_log(name='flask_oauthlib'):
    import logging
    logger = logging.getLogger(name)
    logger.addHandler(logging.StreamHandler())
    logger.setLevel(logging.DEBUG)


# enable_log()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True, index=True,
                         nullable=False)


class Client(db.Model):
    # id = db.Column(db.Integer, primary_key=True)
    # human readable name
    client_key = db.Column(db.String(40), primary_key=True)
    client_secret = db.Column(db.String(55), unique=True, index=True,
                              nullable=False)
    rsa_key = db.Column(db.String(55))
    _realms = db.Column(db.Text)
    _redirect_uris = db.Column(db.Text)

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
    def default_realms(self):
        if self._realms:
            return self._realms.split()
        return []


class Grant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id', ondelete='CASCADE')
    )
    user = db.relationship('User')

    client_key = db.Column(
        db.String(40), db.ForeignKey('client.client_key'),
        nullable=False,
    )
    client = db.relationship('Client')

    token = db.Column(db.String(255), index=True, unique=True)
    secret = db.Column(db.String(255), nullable=False)

    verifier = db.Column(db.String(255))

    expires = db.Column(db.DateTime)
    redirect_uri = db.Column(db.Text)
    _realms = db.Column(db.Text)

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
        db.String(40), db.ForeignKey('client.client_key'),
        nullable=False,
    )
    client = db.relationship('Client')

    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id'),
    )
    user = db.relationship('User')

    token = db.Column(db.String(255))
    secret = db.Column(db.String(255))

    _realms = db.Column(db.Text)

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
        client_key='dev', client_secret='dev',
        _redirect_uris=(
            'http://localhost:8000/authorized '
            'http://localhost/authorized'
        ),
        _realms='email',
    )

    user = User(username='admin')

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

    @oauth.tokengetter
    def load_access_token(client_key, token, *args, **kwargs):
        t = Token.query.filter_by(client_key=client_key, token=token).first()
        return t

    @oauth.tokensetter
    def save_access_token(token, req):
        tok = Token(
            client_key=req.client.client_key,
            user_id=req.user.id,
            token=token['oauth_token'],
            secret=token['oauth_token_secret'],
            _realms=token['oauth_authorized_realms'],
        )
        db.session.add(tok)
        db.session.commit()

    @oauth.grantgetter
    def load_request_token(token):
        grant = Grant.query.filter_by(token=token).first()
        return grant

    @oauth.grantsetter
    def save_request_token(token, oauth):
        if oauth.realms:
            realms = ' '.join(oauth.realms)
        else:
            realms = None
        grant = Grant(
            token=token['oauth_token'],
            secret=token['oauth_token_secret'],
            client_key=oauth.client.client_key,
            redirect_uri=oauth.redirect_uri,
            _realms=realms,
        )
        db.session.add(grant)
        db.session.commit()
        return grant

    @oauth.verifiergetter
    def load_verifier(verifier, token):
        return Grant.query.filter_by(verifier=verifier, token=token).first()

    @oauth.verifiersetter
    def save_verifier(token, verifier, *args, **kwargs):
        tok = Grant.query.filter_by(token=token).first()
        tok.verifier = verifier['oauth_verifier']
        tok.user_id = g.user.id
        db.session.add(tok)
        db.session.commit()
        return tok

    @oauth.noncegetter
    def load_nonce(*args, **kwargs):
        return None

    @oauth.noncesetter
    def save_nonce(*args, **kwargs):
        return None

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
    def email_api():
        oauth = request.oauth
        return jsonify(email='me@oauth.net', username=oauth.user.username)

    @app.route('/api/address/<city>')
    @oauth.require_oauth('address')
    def address_api(city):
        oauth = request.oauth
        return jsonify(address=city, username=oauth.user.username)

    @app.route('/api/method', methods=['GET', 'POST', 'PUT', 'DELETE'])
    @oauth.require_oauth()
    def method_api():
        return jsonify(method=request.method)

    return app


if __name__ == '__main__':
    from flask import Flask
    app = Flask(__name__)
    app.debug = True
    app.secret_key = 'development'
    app.config.update({
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///oauth1.sqlite',
        'OAUTH1_PROVIDER_ENFORCE_SSL': False,
        'OAUTH1_PROVIDER_KEY_LENGTH': (3, 30),
        'OAUTH1_PROVIDER_REALMS': ['email', 'address']
    })
    app = create_server(app)
    app.run()
