from flask import Flask
from .oauth2_server import create_server
from .oauth2_client import create_client


app = Flask(__name__)
app.debug = True
app.secret_key = 'development'
