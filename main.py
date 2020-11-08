import datetime
import hashlib
import uuid

from flask import Flask, render_template, request, make_response, redirect, url_for
from model import db, User, Post, Comment

WEBSITE_LOGIN_COOKIE_NAME = "science/session_token"
COOKIE_DURATION = 900  # in seconds

app = Flask(__name__)

db.create_all()

def getUserByCookie():
    session_token = request.cookies.get(WEBSITE_LOGIN_COOKIE_NAME)
    user = None

    if session_token is not None:
        user = db.query(User) \
            .filter_by(session_cookie=session_token) \
            .filter(User.session_expiry_datetime >= datetime.datetime.now()) \
            .first()
    return user

def require_session_token(func):
    """Decorator to require authentication to access routes"""

    def wrapper(*args, **kwargs):
        session_token = request.cookies.get(WEBSITE_LOGIN_COOKIE_NAME)
        redirect_url = request.path or '/'

        if not session_token:
            app.logger.error('no token in request')
            return redirect(url_for('login', redirectTo=redirect_url))

        user = getUserByCookie()

        if not user:
            app.logger.error(f'token {session_token} not valid')
            return redirect(url_for('login', redirectTo=redirect_url))

        app.logger.info(
            f'authenticated user {user.username} with token {user.session_cookie} valid until {user.session_expiry_datetime.isoformat()}')
        request.user = user
        return func(*args, **kwargs)

    # Renaming the function name:
    wrapper.__name__ = func.__name__
    return wrapper

def getPath():
    return request.path or "/"

@app.route('/', methods=["GET"])
def index():
    user = getUserByCookie()
    return render_template("index.html", redirectTo=getPath(), user=user)


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        repeat = request.form.get("repeat")

        if password != repeat:
            return "Password and Repeat do not match! Please try again."

        # query, check if there is a user with this username in the DB
        # user = db.query(User).filter(User.username == username).one()  # -> needs to find one, otherwise raises Error
        # user = db.query(User).filter(User.username == username).first()  # -> find first entry, if no entry, return None
        # users = db.query(User).filter(User.username == username).all()  # -> find all, always returns list. if not entry found, empty list

        user = db.query(User).filter(User.username == username).first()
        session_cookie = str(uuid.uuid4())
        expiry_time = datetime.datetime.now() + datetime.timedelta(seconds=COOKIE_DURATION)
        if user is None:
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            user = User(username=username,
                        password_hash=password_hash,
                        session_cookie=session_cookie,
                        session_expiry_datetime=expiry_time)
            db.add(user)
            db.commit()
            app.logger.info(f"User {username} is registered")
        else:
            user.session_cookie = session_cookie
            user.session_expiry_datetime = expiry_time
            db.add(user)
            db.commit()
            app.logger.info(f"User {username} is logged in")

        redirect_url = request.args.get("redirectTo")
        response = make_response(redirect(redirect_url))
        response.set_cookie(WEBSITE_LOGIN_COOKIE_NAME, session_cookie, httponly=True, samesite='Strict')
        return response

    elif request.method == "GET":
        cookie = request.cookies.get(WEBSITE_LOGIN_COOKIE_NAME)
        user = None
        logged_in = False

        if cookie is not None:
            user = db.query(User) \
                .filter_by(session_cookie=cookie) \
                .filter(User.session_expiry_datetime >= datetime.datetime.now())\
                .first()

        if user is not None:
            logged_in = True

        return render_template("login.html", logged_in=logged_in)


@app.route('/about', methods=["GET"])
@require_session_token
def about():
    user = getUserByCookie()
    return render_template("about.html", user=user)


@app.route('/faq', methods=["GET"])
@require_session_token
def faq():
    user = getUserByCookie()
    return render_template("faq.html", user=user)


@app.route('/logout', methods=["GET"])
@require_session_token
def logout():
    user = request.user
    user.session_expiry_datetime = None
    user.session_cookie = None
    db.add(user)
    db.commit()
    app.logger.info(f"User {user.username} has logged out")
    return redirect(url_for('index'))


@app.route('/blog', methods=["GET", "POST"])
@require_session_token
def blog():
    user = getUserByCookie()
    current_user = request.user

    if request.method == "POST":
        title = request.form.get("title")
        content = request.form.get("content")
        post = Post(
            title=title, content=content,
            user=current_user,
            datetime=datetime.datetime.now()
        )
        db.add(post)
        db.commit()
        return redirect(url_for('blog'))

    if request.method == "GET":
        posts = db.query(Post).all()
        return render_template("blog.html", posts=posts, user=user)


@app.route('/posts/<post_id>', methods=["GET", "POST"])
@require_session_token
def posts(post_id):
    user = getUserByCookie()
    current_user = request.user
    post = db.query(Post).filter(Post.id == post_id).first()

    if request.method == "POST":
        content = request.form.get("content")
        comment = Comment(
            content=content,
            post=post,
            user=current_user,
            datetime=datetime.datetime.now()
        )
        db.add(comment)
        db.commit()
        return redirect('/posts/{}'.format(post_id))

    elif request.method == "GET":
        comments = db.query(Comment).filter(Comment.post_id == post_id).all()
        return render_template('posts.html', post=post, comments=comments, user=user)

if __name__ == '__main__':
    app.run(host='localhost', port=7890)