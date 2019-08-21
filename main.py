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
os.environ['DEBUG'] = '1'
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
app.config["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

# Items here will not be redirected to authenticate
oauth_whitelist = [
    r"^(?:\/api)?\/$",
    r"^(?:\/api)?\/oauth\/callback\/?$",
    r"^(?:\/api)?\/oauth\/authorize\/?$",
]

scopes = [
    "https://www.googleapis.com/auth/analytics.readonly"
]

discovery_urls = {
    ("analytics", "v4"): "https://analyticsreporting.googleapis.com/$discovery/rest"
}


class SetupError(Exception):
    pass


@app.before_first_request
def validate_environment():
    if "API_URL" not in os.environ:
        os.environ["API_URL"] = "https://localhost:5000"


@app.route("/")
def hello():
    return jsonify({
        "message": "Hello World",
        "status": "Online",
        "upstream": {
            "Google Analytics": not app.config["creds"] and "Unauthorized" or app.config[
                "creds"].valid and "Connected" or "Paused"
        },
        "host": request.host_url,
        "auth_url": os.getenv("API_URL") + url_for("oauth_authorize"),
    })


@app.before_request
def oauth_check():
    if all(re.match(path, request.path) is None for path in oauth_whitelist):
        if not app.config["creds"] or not app.config["creds"].valid:
            if request.endpoint:
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


@app.route("/oauth/callback/")
def oauth_callback():
    try:
        state = request.args["state"]
        flow = Flow.from_client_secrets_file(
            'credentials.json', scopes, state=state)
        flow.redirect_uri = os.getenv("API_URL") + url_for("oauth_callback")

        auth_url = request.url

        if auth_url.startswith("http://"):
            print("replace with https")
            auth_url = "https" + auth_url[4:]
        flow.fetch_token(authorization_response=auth_url)
        app.config["creds"] = flow.credentials
        with open(app.config["pickle"], "wb") as fin:
            pickle.dump(app.config["creds"], fin)
            app.config["state"] = None
    except:
        tb.print_exc()
    return redirect(app.config["redirect"])


@app.route("/oauth/authorize/")
def oauth_authorize():
    if "return_to" in request.args:
        app.config["redirect"] = request.args["return_to"]

    # Try loading in the token from previous session
    if not app.config["creds"] and os.path.exists(app.config["pickle"]):
        with open(app.config["pickle"], "rb") as fin:
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


@app.route("/analytics")
@require_access("analyticsreporting", "v4")
def access_reporting(auth):
    ids = require_analytics_id()
    data = auth.reports().batchGet(
        body={
            'reportRequests': [
                {
                    'viewId': ids,
                    'dateRanges': [{'startDate': '7daysAgo', 'endDate': 'today'}],
                    'dimensions': [{"name": "ga:pagePath"}, {"name": "ga:pageTitle"}],
                    'metrics': [{'expression': 'ga:pageviews'}, {'expression': 'ga:uniquePageviews'},
                                {'expression': 'ga:timeOnPage'}]
                }]
        }
    ).execute()
    return jsonify(data)


@app.route("/realtime")
@require_access("analytics", "v3")
def access_realtime(auth):
    ids = require_analytics_id()
    data = auth.data().realtime().get(
        ids=f"ga:{ids}",
        metrics='rt:pageviews',
        dimensions='rt:pagePath').execute()
    return jsonify(data)


def require_analytics_id():
    if "ga" not in request.args:
        raise Exception("Google analytics required")
    ga_id = request.args.get("ga")
    if not re.match("^[0-9]+$", ga_id):
        raise Exception("Invalid GA ID")
    return ga_id


if __name__ == '__main__':
    app.run(threaded=False, debug=True, ssl_context='adhoc')
