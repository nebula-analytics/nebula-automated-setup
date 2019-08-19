from __future__ import print_function

import inspect
import os
import os.path
import pickle
import re
import traceback as tb
from typing import Callable

from flask import Flask, jsonify, redirect, request
from flask import url_for
from flask_cors import CORS
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

app = Flask(__name__)
# app.wsgi_app = ReverseProxied(app.wsgi_app)
CORS(app)

app.config["creds"] = None
app.config["pickle"] = "./token.pickle"
app.config["state"] = None
app.config["redirect"] = "/"

# Items here will not be redirected to authenticate
oauth_whitelist = [
    r"^(?:\/api)?\/$",
    r"^(?:\/api)?\/oauth\/callback\/?$",
    r"^(?:\/api)?\/oauth\/authorize\/?$",
]

scopes = [
    "https://www.googleapis.com/auth/analytics.readonly"
]


@app.route("/")
def hello():
    return jsonify({
        "message": "Hello World",
        "status": "Online",
        "upstream": {
            "GDrive": not app.config["creds"] and "Unauthorized" or app.config[
                "creds"].valid and "Connected" or "Paused"
        },
        "host": request.host_url,
        "auth_url": os.getenv("API_URL") + url_for("oauth_authorize"),
    })


@app.before_request
def oauth_check():
    if all(re.match(path, request.path) is None for path in oauth_whitelist):
        if not app.config["creds"] or not app.config["creds"].valid:
            app.config["redirect"] = os.getenv("API_URL") + url_for(request.endpoint)
            return redirect(os.getenv("API_URL") + url_for("oauth_authorize"))


def require_access(service_name, version):
    """
    Annotate a method with the access required
    :param service_name:
    :param version:
    :return:
    """

    def receive(fn: Callable):
        def wrapper(*args, **kwargs):
            kwargs["auth"] = build(service_name, version, credentials=app.config["creds"])
            return fn(*args, **kwargs)

        wrapper.__name__ = fn.__name__
        wrapper.__signature__ = inspect.signature(fn)
        return wrapper

    return receive


@app.route("/oauth/callback")
def oauth_callback():
    try:
        state = request.args["state"]
        flow = Flow.from_client_secrets_file(
            'credentials.json', scopes, state=state)
        flow.redirect_uri = os.getenv("API_URL") + url_for("oauth_callback")

        flow.fetch_token(
            authorization_response=request.url)
        app.config["creds"] = flow.credentials
        with open(app.config["pickle"], "wb") as fin:
            pickle.dump(app.config["creds"], fin)
            app.config["state"] = None
    except:
        tb.print_exc()
    return redirect(app.config["redirect"])


@app.route("/oauth/authorize")
def oauth_authorize():
    if "return_to" in request.args:
        app.config["redirect"] = request.args["return_to"]

    # Try loading in the token from previous session
    if not app.config["creds"] and os.path.exists(app.config["pickle"]):
        with open(app.config["pickle"], "r") as fin:
            app.config["creds"] = pickle.load(fin)

    # Check for token expiry
    if app.config["creds"] and app.config["creds"].expired and app.config["creds"].refresh_token:
        print("Refresh Token")
        app.config["creds"].refresh(Request())

    if app.config["creds"] and app.config["creds"].valid:
        print("Authorized")
        return redirect(app.config["redirect"])

    flow = Flow.from_client_secrets_file(
        'credentials.json', scopes)
    flow.redirect_uri = os.getenv("API_URL") + url_for("oauth_callback")

    auth_url, app.config["state"] = flow.authorization_url(
        prompt='consent',
        access_type='offline',
        include_granted_scopes='true'
    )
    # For some reason redirect_uri is not attached by the lib
    return redirect(auth_url)


if __name__ == '__main__':
    app.run(threaded=False, debug=True)