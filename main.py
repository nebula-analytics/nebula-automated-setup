from __future__ import print_function

import logging
from collections import OrderedDict
from logging.handlers import RotatingFileHandler
import inspect
import os
import os.path
import pickle
import re
import traceback as tb
from typing import Callable
from pickle import UnpicklingError
import json
import yaml
import subprocess

from flask import Flask, jsonify, redirect, request, render_template, flash, session
from flask import url_for
from flask_cors import CORS
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from pandas import DataFrame


class AuthenticationException(Exception):
    pass


app = Flask(__name__, template_folder='templates')
# app.wsgi_app = ReverseProxied(app.wsgi_app)
CORS(app)

app.config["creds"] = None
app.config["pickle"] = os.path.dirname(__file__) + "/configuration/token.pickle"
app.config["state"] = None
app.config["redirect"] = "/"

app.secret_key = os.getenv("SECRET")
viewIDs = []

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

progression = [
    "about", "primo", "google_cloud", "analytics", "confirm_and_complete"
]


class SetupError(Exception):
    pass


@app.before_first_request
def validate_environment():
    if "API_URL" not in os.environ:
        os.environ["API_URL"] = "https://localhost:5000"


@app.route("/")
def index():
    return render_template("about.html", progression=get_progression("about"))


@app.route("/setup/about")
def about():
    return redirect(url_for("index"))


@app.route("/setup/primo", methods=["GET", "POST"])
def setup_primo():
    if request.method == "POST":
        fields = ["primo_url", "primo_key"]
        data = request.form
        state = session.setdefault("primo", {})

        """Validate data"""
        valid = True
        for field in fields:
            if not data.get(field, False):
                flash("{} cannot be empty".format(field.replace("_", " ").capitalize()))
                valid = False

        if valid:
            for field in fields:
                state[field] = data.get(field)
            if not state["primo_url"].startswith("https://"):
                state["primo_url"] = "https://" + state["primo_url"]
            if not state["primo_url"].endswith("/pnxs"):
                state["primo_url"] = state["primo_url"] + "/pnxs"
            return redirect(url_for('setup_google_cloud'))
    return render_template('primo.html', progression=get_progression("primo"))


@app.route("/setup/google_cloud", methods=["GET", "POST"])
def setup_google_cloud():
    print(session)
    if request.method == "POST":
        fields = ["client_id", "client_secret"]
        data = request.form
        state = session.setdefault("google_cloud", {})

        """Validate data"""
        valid = True
        for field in fields:
            if not data.get(field, False):
                flash("{} cannot be empty".format(field.replace("_", " ").capitalize()))
                valid = False

        if valid:
            state.update({
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            })
            for field in fields:
                state[field] = data.get(field)

            if not state["client_id"].endswith(".apps.googleusercontent.com"):
                state["client_id"] = state["client_id"] + ".apps.googleusercontent.com"

            session["google_cloud"] = state
            return redirect(url_for('setup_analytics'))
    return render_template('google_cloud.html', progression=get_progression("google_cloud"))


@app.route("/setup/analytics", methods=["GET", "POST"])
def setup_analytics():
    print(session)
    state = session.setdefault("analytics", {})
    if "token" in state:
        if request.method == "POST":
            data = request.form
            if "view_id" in data:
                state.update({"view_id": data.get("view_id")})
                session["analytics"] = state
                return redirect(url_for("confirm_and_complete"))
            flash("No idea how you managed to not pick any")
        if "available_views" not in session:
            auth = build("analytics", "v3", credentials=pickle.loads(state["token"]))
            session["available_views"] = get_views(auth)
        views = session["available_views"]
        return render_template('analytics.html', progression=get_progression("analytics"), views=list(enumerate(views)))
    else:
        print(request.method)
        print()
        if request.method == "POST":
            return redirect(url_for("oauth_authorize", return_to=url_for("setup_analytics")))

    return render_template('analytics.html', progression=get_progression("analytics"))


@app.route("/setup/confirm_and_complete", methods=["GET", "POST"])
def confirm_and_complete():
    if request.method == "POST":
        output_token_pickle()
        output_config_yaml()
        session["confirm_and_complete"] = True
        flash("Your configuration has been saved, run docker-compose restart to put changes in effect")
        return redirect(url_for("done"))

    sensitive_fields = ["token", "primo_key"]
    state = {
        key: list(
            (skey, str(value) if skey not in sensitive_fields else "*" * min(len(value), 50))
            for skey, value in session[key].items())
        for key in ["primo", "analytics"]
    }

    return render_template("complete.html", state=state, progression=get_progression("confirm_and_complete"))


@app.route("/setup/success")
def done():
    return render_template("successful.html", progression=get_progression("confirm_and_complete"))


def output_config_yaml():
    target_directory = os.getenv("CONFIG_DIR", "./configuration")
    config_file = os.path.join(target_directory, "config.yaml.docker")
    with open(config_file, "w") as config_f:
        yaml.safe_dump({
            "primo": {
                "host": session["primo"]["primo_url"],
                "api_key": session["primo"]["primo_key"],
            }
        }, config_f)


def output_token_pickle():
    target_directory = os.getenv("CONFIG_DIR", "./configuration")
    token_file = os.path.join(target_directory, "token.pickle")
    with open(token_file, "wb") as token_f:
        token_f.write(session["analytics"]["token"])


def get_progression(current_step: str):
    return OrderedDict(
        (progression[i], {
            "class": "active" if current_step == progression[i] else "",
            "url": "/setup/{}".format(progression[i]),
            "next": progression[i] if i < len(progression) else None,
            "completed": bool(session.get(progression[i]))
        })
        for i in range(len(progression))
        if i <= progression.index(current_step) or i > 0 and session.get(progression[i - 1], False) or session.get(
            progression[i])

    )


def update_config(new: dict):
    with open("./configuration/credentials.json", "r") as fin:
        data = json.load(fin)
    update_recursive(data, new)
    with open("./configuration/credentials.json", "w") as fout:
        json.dump(data, fout)


def update_recursive(dest: dict, values: dict):
    for key, value in values.items():
        if isinstance(value, dict):
            if key in dest and isinstance(dest[key], dict):
                update_recursive(dest[key], values[key])
                continue
        if not value:
            continue
        dest[key] = value


@app.route("/auth", methods=["POST"])
def oauth_check():
    if all(re.match(path, request.path) is None for path in oauth_whitelist):
        if not app.config["creds"] or not app.config["creds"].valid:
            # Retrieve data from POST request with form's name
            client_secret = request.form['client_secret']
            client_id = request.form['client_id']
            primo_url = request.form['primo_url']
            primo_key = request.form['primo_key']

            with open("./configuration/credentials.json", "r") as jsonFile:
                data = json.load(jsonFile)

            tmp = data["web"]
            data["web"]["client_secret"] = client_secret
            data["web"]["client_id"] = client_id
            with open("./configuration/credentials.json", "w") as jsonFile:
                json.dump(data, jsonFile)
            # New dict from the Form for necessary configuration
            new_yaml_data_dict = {
                'primo': {
                    'host': primo_url,
                    'api_key': primo_key,
                    'contexts': ["L", "PC"],
                    'common_fields': ['title', 'identifier', "doc_id", "language", "_type"],
                    'excluded_fields': ["_id"],
                    'name_mapping': {"lang3": "language", "pnx_id": "doc_id"},
                    'key_by': ""

                }
            }

            with open('./configuration/config.yaml.secret', 'w') as yamlfile:
                yaml.safe_dump(new_yaml_data_dict, yamlfile, default_flow_style=False, allow_unicode=True,
                               encoding=None)  # Also note the safe_dump
            app.config["redirect"] = "/viewslist"
            return redirect(os.getenv("API_URL") + url_for("oauth_authorize"))


def require_access(service_name, version):
    """
    Annotate a method with the access required
    :param service_name:
    :param version:
    :return:
    """
    if not os.path.isfile(app.config['pickle']):
        def receive(fn: Callable):
            def wrapper(*args, **kwargs):
                kwargs["auth"] = build(service_name, version, credentials=app.config["creds"])
                return fn(*args, **kwargs)

            wrapper.__name__ = fn.__name__
            wrapper.__signature__ = inspect.signature(fn)
            return wrapper
    else:
        def receive(fn: Callable):
            def wrapper(*args, **kwargs):
                try:
                    with open(app.config['pickle'], "rb") as tokenf:
                        token = pickle.load(tokenf)
                        if not token:
                            raise AuthenticationException(
                                f"The provided token file '{app.config['pickle']}' was empty")
                        auth = build(service_name, version, credentials=token, cache_discovery=False)
                        args = list(args)
                        args.append(auth)
                        return fn(*args, **kwargs)
                except UnpicklingError:
                    raise AuthenticationException(
                        f"The provided token file '{app.config['pickle']}' is corrupted and could not be loaded")

            wrapper.__name__ = fn.__name__
            wrapper.__signature__ = inspect.signature(fn)
            return wrapper
    return receive


def get_views(auth):
    view_list = []
    accounts = auth.management().accounts().list().execute()
    for account in accounts["items"]:
        account_id = account["id"]
        properties = auth.management().webproperties().list(accountId=account_id).execute()
        for webp in properties["items"]:
            web_id = webp["id"]
            views = auth.management().profiles().list(
                accountId=account_id,
                webPropertyId=web_id).execute()
            for view in views["items"]:
                view_list.append({"id": view['id'], "url": view.get("websiteUrl", '')})

    return view_list


@app.route("/viewslist")
@require_access("analytics", "v3")
def showListofViews(auth):
    return render_template('viewsList.html', viewIDs=get_views(auth))


@app.route("/finalise", methods=['GET', 'POST'])
def finalise():
    viewID = request.form['viewIDPicker']
    errors = []

    if not os.path.exists('./configuration/token.pickle'):
        errors.append("Cannot find token.pickle!!!")
    if viewID not in viewIDs:
        errors.append("View ID does not exist!!!")
    if not os.path.exists('./configuration/config.yaml.secret'):
        errors.append("Cannot find config.yaml.secret!!!")
    if errors:
        return render_template("/errors.html", errors=errors)

    subdir = f"{os.path.abspath('./configuration') + '/token.pickle'}"
    new_yaml_data_dict = {
        'view_id': viewID,
        'path_to_credentials': subdir
    }
    with open('./configuration/config.yaml.secret') as f:
        doc = yaml.load(f)

    doc['analytics'] = new_yaml_data_dict

    with open('./configuration/config.yaml.secret', 'w') as f:
        yaml.dump(doc, f)
    directory = "mv " + os.path.abspath('./configuration/config.yaml.secret') + " " + os.path.abspath(
        '../nebula-background-worker/')
    subprocess.call(directory, shell=True)
    return render_template("successful.html")


@app.route("/oauth/callback/")
def oauth_callback():
    state = request.args.get("state", None)
    if not state:
        return render_template("error.html", errors=["No state provided to callback"])

    host = os.getenv("API_URL", request.host_url[:-1])
    try:
        authorization = {"web": session["google_cloud"]}

        flow = Flow.from_client_config(authorization, scopes, state=state)
        flow.redirect_uri = "{}{}".format(host, url_for("oauth_callback"))

        auth_url = request.url

        if auth_url.startswith("http://"):
            auth_url = "https" + auth_url[4:]

        flow.fetch_token(authorization_response=auth_url)

        sess_state = session["analytics"]
        sess_state.update({"token": pickle.dumps(flow.credentials)})
        session["analytics"] = sess_state

        with open(app.config["pickle"], "wb") as fin:
            pickle.dump(app.config["creds"], fin)
    except:
        tb.print_exc()
        return render_template("error.html", error=["An exception occured while attempting to complete the oauth flow"])
    return redirect(session["redirect"])


@app.route("/oauth/authorize/", methods=['GET', 'POST'])
def oauth_authorize():
    if "return_to" in request.args:
        session["redirect"] = request.args["return_to"]
    state = session.setdefault("analytics", {})

    credentials = None
    if "token" in state:
        credentials = pickle.loads(state["token"])

    if credentials and credentials.expired and credentials.refresh_token:
        credentials.refresh(Request())

    if credentials and credentials.valid:
        return redirect(session.get("redirect", "/"))

    authorization = {"web": session["google_cloud"]}
    print(json.dumps(authorization, indent=4))

    flow = Flow.from_client_config(authorization, scopes)
    host = os.getenv("API_URL", request.host_url[:-1])
    # flow.redirect_uri = "https://localhost:5000/oauth/callback/"
    flow.redirect_uri = "{}{}".format(host, url_for("oauth_callback"))

    auth_url, app.config["state"] = flow.authorization_url(
        prompt='consent',
        access_type='offline',
        include_granted_scopes='true'
    )
    # For some reason redirect_uri is not attached by the lib
    return redirect(auth_url)


@app.route("/logout")
def logout():
    session.clear()
    flash("The information you entered has been cleared")
    return redirect(url_for("about"))


@app.route("/analytics/")
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


@app.route("/realtime/")
@require_access("analytics", "v3")
def access_realtime(auth):
    ids = require_analytics_id()
    data = auth.data().realtime().get(
        ids=f"ga:{ids}",
        metrics='rt:pageviews',
        dimensions='rt:pagePath,rt:minutesAgo,rt:country,rt:city,rt:pageTitle',
        filters="ga:pagePath=~/primo-explore/fulldisplay?/*",
        sort="rt:minutesAgo"
    ).execute()
    return jsonify(data)


@app.route("/realtime/pages/")
@require_access("analytics", "v3")
def list_realtime_urls(auth):
    ids = require_analytics_id()
    data = auth.data().realtime().get(
        ids=f"ga:{ids}",
        metrics='rt:pageviews',
        dimensions='rt:pagePath,rt:minutesAgo,rt:country,rt:city,rt:pageTitle',
        sort="rt:minutesAgo"
    ).execute()
    columns = list(header["name"] for header in data["columnHeaders"])
    df = DataFrame(data=data["rows"][3:], columns=columns)
    queries_stripped = df["rt:pagePath"].replace([r"\?.+$"], [""], regex=True)
    return jsonify({"pages": list(queries_stripped.unique())})


@app.route("/analytics/views/")
@require_access("analytics", "v3")
def show_accounts(auth):
    accounts = auth.management().accounts().list().execute()
    results = []
    for account in accounts["items"]:
        account_id = account["id"]
        properties = auth.management().webproperties().list(accountId=account_id).execute()
        for webp in properties["items"]:
            web_id = webp["id"]
            views = auth.management().profiles().list(
                accountId=account_id,
                webPropertyId=web_id).execute()
            for view in views["items"]:
                results.append(view)
    return jsonify(
        {
            "user": accounts,
            "views": results
        }
    )


def require_analytics_id():
    if "ga" not in request.args:
        raise Exception("Google analytics required")
    ga_id = request.args.get("ga")
    if not re.match("^[0-9]+$", ga_id):
        raise Exception("Invalid GA ID")
    return ga_id


if __name__ == '__main__':
    app.run(threaded=False, debug=True, ssl_context='adhoc')
