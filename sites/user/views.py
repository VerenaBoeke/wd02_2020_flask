import base64
import datetime
import uuid
import logging

from flask import render_template, request, make_response, redirect, url_for, flash, Blueprint
from flask_mail import Message

from extensions import db, mail, bcrypt
from model import User
from sites import provide_user, WEBSITE_LOGIN_COOKIE_NAME, SENDER, HOST_ADDR, check_email, COOKIE_DURATION, \
    check_email_exists, getPath, require_session_token

blueprint = Blueprint("user", __name__, url_prefix="/users", static_folder="../../static")

@blueprint.route('/profiles/<username>', methods=["GET", "POST"])
@require_session_token
def profile(username):
    user = User.query.filter_by(username=username).one()
    if request.method=="POST":
        email = request.form.get("email")
        if email != user.email:
            user.email = email

        hobby = request.form.get("hobby")
        if hobby != user.hobby:
            user.hobby = hobby

        profilepic = request.files.get("profilepic")
        if profilepic:
            user.profilepic = profilepic.stream.read()


        db.session.add(user)
        db.session.commit()

        return redirect(url_for('user.profile', username=username))

    elif request.method=="GET":
        profilepic_base64 = base64.encodebytes(user.profilpic)
        return render_template("profile.html", user=user, profilepic_base64=profilepic_base64)

@blueprint.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")


        # right way to find user with correct password
        user = User.query\
             .filter(User.username == username) \
             .first()


        session_cookie = str(uuid.uuid4())
        expiry_time = datetime.datetime.now() + datetime.timedelta(seconds=COOKIE_DURATION)

        redirect_url = request.args.get('redirectTo', url_for('main.index'))

        if user is None:
            flash("Username or password is wrong", "warning")
            logging.info(f"User {username} failed to login with wrong username.")
            return redirect(url_for('user.login', redirectTo=redirect_url))
        elif not bcrypt.check_password_hash(user.password_hash, password):
            flash("Username or password is wrong", "warning")
            logging.info(f"User {username} failed to login with wrong password.")
            return redirect(url_for('user.login', redirectTo=redirect_url))
        else:
            user.session_cookie = session_cookie
            user.session_expiry_datetime = expiry_time
            db.session.add(user)
            db.session.commit()
            logging.info(f"User {username} is logged in")

        response = make_response(redirect(redirect_url))
        response.set_cookie(WEBSITE_LOGIN_COOKIE_NAME, session_cookie, httponly=True, samesite='Strict')
        return response

    elif request.method == "GET":
        cookie = request.cookies.get(WEBSITE_LOGIN_COOKIE_NAME)
        user = None

        if cookie is not None:
            user = User.query \
                .filter_by(session_cookie=cookie) \
                .filter(User.session_expiry_datetime >= datetime.datetime.now())\
                .first()

        if user is None:
            logged_in = False
        else:
            logged_in = True

        return render_template("login.html", logged_in=logged_in)

@blueprint.route('/registration', methods=["GET", "POST"])
def registration():
    default = "Admin"
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        repeat = request.form.get("repeat")
        role = default

        # check email valid
        is_valid = check_email(email)
        if not is_valid:
            flash("Email is not a valid email", "warning")
            return redirect(url_for("user.registration"))

        if password != repeat:
            flash("Password and repeat did not match!", "warning")
            return redirect(url_for("user.registration"))

        if check_email_exists(email):
            flash("This E-Mail already exist, please go to Login", "warning")
            return redirect(url_for("user.registration"))


        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        session_cookie = str(uuid.uuid4())

        expiry_time = datetime.datetime.now() + datetime.timedelta(seconds=COOKIE_DURATION)

        user = User(username=username,
                    email=email,
                    password_hash=password_hash,
                    session_cookie=session_cookie,
                    session_expiry_datetime=expiry_time,
                    role=default)
        db.session.add(user)
        db.session.commit()
        flash("Registration successful!", "success")

        msg = Message(
            subject="HelloWorld Blog - Registration successful",
            sender=SENDER,
            recipients=[email],
            bcc=[SENDER]
        )

        msg.body = f"Hi {username}!\n" \
            f"Welcome to our WebDev Flask site!\n" \
            f"Visit us: {HOST_ADDR}\n" \
            f"Enjoy!"

        mail.send(msg)

        redirect_url = "/"
        response = make_response(redirect(redirect_url))
        response.set_cookie(WEBSITE_LOGIN_COOKIE_NAME, session_cookie, httponly=True, samesite='Strict')
        return response

    elif request.method == "GET":
        return render_template("register.html")


@blueprint.route('/logout', methods=["GET"])
@provide_user
def logout():
    response = make_response(redirect(url_for('main.index')))
    response.set_cookie(WEBSITE_LOGIN_COOKIE_NAME, expires=0)

    user = User.query\
        .filter_by(username=request.user.username)\
        .first()

    if user is not None:
        # reset user
        user.session_expiry_datetime = None
        user.session_cookie = None
        db.session.add(user)
        db.session.commit()
        logging.info(f"{user.username} has logged out.")

    return response


@blueprint.route('/users', methods=["GET"])
@require_session_token
def usertabelle():
    users = db.query(User)
    return render_template("users.html", redirectTo=getPath(), users=users)