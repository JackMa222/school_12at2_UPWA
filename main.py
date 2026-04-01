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

import pyotp
import pyqrcode
import base64
from io import BytesIO

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
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
    response.headers['Cross-Origin-Embedder-Policy'] = 'require-corp'
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
    'style-src': '\'self\'',
    'img-src': ['\'self\'', 'data:']
}

Talisman(app, content_security_policy=csp, strict_transport_security=False, force_https=False, frame_options='SAMEORIGIN')

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
        if dbHandler.insertUser(username, password, DoB):
            user_id = dbHandler.retrieveUserId(username)
            session["onboarding_user_id"] = user_id
            return redirect(url_for('onboard_2fa'))
        else:
            return redirect(url_for('signup'))
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
            if dbHandler.check_2fa_status(user_id):
                session["pending_user_id"] = user_id
                return redirect(url_for('verify_2fa'))
            else:
                session["onboarding_user_id"] = user_id
                return redirect(url_for('onboard_2fa'))
        else:
            return render_template("/index.html")
    else:
        return render_template("/index.html")

@app.route("/logout", methods=["POST", "GET"])
def logout():
    session.clear()
    return redirect("/")

@app.route("/onboard_2fa", methods=["POST", "GET"])
def onboard_2fa():
    user_id = session.get("onboarding_user_id")
    
    secret = dbHandler.retrieve_2fa_secret(user_id)
    username = dbHandler.retrieveUsername(user_id)
    
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=username, issuer_name="Unsecure-PWA-Company")
    
    url = pyqrcode.create(uri)
    stream = BytesIO()
    url.png(stream, scale=5)
    qr_b64 = base64.b64encode(stream.getvalue()).decode("utf-8")
    
    return render_template("onboard_2fa.html", qr_code=qr_b64, secret=secret)
    
@app.route("/verify_2fa", methods=["POST", "GET"])
def verify_2fa():
    user_id = session.get("pending_user_id") or session.get("onboarding_user_id")
    if not user_id:
        return redirect(url_for("home"))
    
    if request.method == "POST":
        otp_token = request.form.get("otp_token")       
        secret = dbHandler.retrieve_2fa_secret(user_id)
        
        totp = pyotp.TOTP(secret)
        if totp.verify(otp_token):
            session["user_id"] = user_id
            
            if "onboarding_user_id" in session:
                dbHandler.complete_2fa_setup(user_id)
            
            session.pop("onboarding_user_id", None)
            session.pop("pending_user_id", None)
            
            return redirect(url_for("addFeedback"))
        else:
            return render_template("verify_2fa.html")
        
    return render_template("verify_2fa.html")
    

if __name__ == "__main__":
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    app.run(debug=False, host="127.0.0.1", port=5000)
