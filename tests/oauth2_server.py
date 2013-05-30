from flask import Flask
from flask.ext.sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship


app = Flask(__name__)
app.debug = True
app.secret_key = 'development'

db = SQLAlchemy(app)


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
    client_secret = db.Column(db.Unicode(255), unique=True, index=True,
                              nullable=False)
    client_type = db.Column(db.Unicode(20), default='public')
    _redirect_uris = db.Column(db.UnicodeText)
    default_scope = db.Column(db.UnicodeText)

    @property
    def redirect_uris(self):
        if self._redirect_uris:
            return self._redirect_uris.split()
        return []

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
    client_id = db.Column(db.Unicode(40), nullable=False)
    user = relationship('User')
    code = db.Column(db.Unicode(255), index=True, nullable=False)
    expires = db.Column(db.DateTime)


class Token(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Unicode(40), nullable=False)
    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id', ondelete='CASCADE')
    )
    user = relationship('User')
    access_token = db.Column(db.Unicode(255))
    refresh_token = db.Column(db.Unicode(255))
    expires = db.Column(db.DateTime)
    scope = db.Column(db.UnicodeText)

    @property
    def scopes(self):
        if self.scope:
            return self.scope.split()
        return []


@app.route('/authorize')
def authorize():
    return ''


@app.route('/access_token')
def access_token():
    return ''
