import os
from flask import Flask, session, url_for
from flask import render_template
from flask import request
from flask import redirect
from flask_session import Session
from flask_cors import CORS
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFProtect
import user_management as dbHandler
from dotenv import load_dotenv
from helpers import login_required

# Code snippet for logging a message
# app.logger.critical("message")
load_dotenv()
app = Flask(__name__)
# Enable CORS to allow cross-origin requests (needed for CSRF demo in Codespaces)
CORS(app, resources={"/*": {
    "origins": ["http://127.0.0.1:5000", "http://localhost:5000/"],
    "methods": ["GET", "POST"],
    "allow_headers": ["Content-Type"]
}})

csrf = CSRFProtect(app)

@app.after_request
def remove_server_info(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers.pop("Server", None)
    return response

# Secure session management
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "dev-key-fallback-not-for-prod")

Session(app)
csp = {
    'default-src': '\'self\'',
    'script-src': '\'self\'',
    'style-src': '\'self\''
}

Talisman(app, content_security_policy=csp, force_https=False, frame_options='SAMEORIGIN')

@app.route("/success.html", methods=["POST", "GET"])
@login_required
def addFeedback():
    if request.method == "POST":
        feedback = request.form["feedback"]
        if feedback:
            dbHandler.insertFeedback(feedback)
        return redirect(url_for('addFeedback'))

    all_feedback = dbHandler.listFeedback()
    return render_template("/success.html", feedback=all_feedback, state=True, value="Back")


@app.route("/signup.html", methods=["POST", "GET"])
def signup():
    session.clear()
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        DoB = request.form["dob"]
        dbHandler.insertUser(username, password, DoB)
        return render_template("/index.html")
    else:
        return render_template("/signup.html")


@app.route("/index.html", methods=["POST", "GET"])
@app.route("/", methods=["POST", "GET"])
def home():
    # Log user out if logged in
    session.clear()
    # Pass message to front end
    if request.method == "GET":
        msg = request.args.get("msg", "")
        return render_template("/index.html", msg=msg)
    elif request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        isLoggedIn = dbHandler.retrieveUsers(username, password)
        if isLoggedIn:
            user_id = dbHandler.retrieveUserId(username)
            session["user_id"] = user_id
            all_feedback = dbHandler.listFeedback()
            return render_template("/success.html", feedback=all_feedback, value=username, state=isLoggedIn)
        else:
            return render_template("/index.html")
    else:
        return render_template("/index.html")

@app.route("/logout", methods=["POST", "GET"])
def logout():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    app.run(debug=True, host="127.0.0.1", port=5000)
