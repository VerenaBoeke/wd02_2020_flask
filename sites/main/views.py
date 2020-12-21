from flask import render_template, Blueprint, request
from flask_mail import Message

from extensions import mail
from sites import require_session_token, getPath, provide_user

blueprint = Blueprint("main", __name__, url_prefix="/", static_folder="../../static")


@blueprint.route("/test-mail")
def test_mail():
    try:
        msg = Message(
            subject="Flask WebDev Project Test Email",
            sender="vboeke.dev@gmail.com",
            recipients=["vboeke.dev@gmail.com"]
        )
        msg.body = "There is a new Blogpost!, Check this out!"
        mail.send(msg)
        return "Flask sent your mail!"
    except Exception as e:
        return str(e)


@blueprint.route('/', methods=["GET"])
@provide_user
def index():
    return render_template("index.html", user=request.user)


@blueprint.route('/about', methods=["GET"])
@require_session_token
def about():
    return render_template("about.html", redirectTo=getPath())


@blueprint.route('/faq', methods=["GET"])
@require_session_token
def faq():
    return render_template("faq.html", redirectTo=getPath())


@blueprint.route('/crypto', methods=["GET"])
@require_session_token
def crypto():
    return render_template("crypto.html", redirectTo=getPath())


@blueprint.route('/gallery', methods=["GET"])
@require_session_token
def gallery():
    return render_template("gallery.html", redirectTo=getPath())