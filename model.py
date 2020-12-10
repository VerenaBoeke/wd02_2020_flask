import datetime
from extensions import db


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(255), unique=True)
    created = db.Column(db.DateTime, default=datetime.datetime.now)
    updated = db.Column(db.DateTime, default=datetime.datetime.now, onupdate=datetime.datetime.now)

    username = db.Column(db.String(255), nullable=False, unique=True)
    password_hash = db.Column(db.String(255), nullable=False)
    session_cookie = db.Column(db.String(255), nullable=True, unique=True)
    session_expiry_datetime = db.Column(db.DateTime)
    role = db.Column(db.String(255))

    posts = db.relationship('Post', backref='users')
    comments = db.relationship('Comment', backref='users')


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    created = db.Column(db.DateTime, default=datetime.datetime.now)
    updated = db.Column(db.DateTime, default=datetime.datetime.now, onupdate=datetime.datetime.now)

    title = db.Column(db.String)
    text = db.Column(db.String)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    user = db.relationship(User)

    comments = db.relationship('Comment', backref='posts')


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    created = db.Column(db.DateTime, default=datetime.datetime.now)
    updated = db.Column(db.DateTime, default=datetime.datetime.now, onupdate=datetime.datetime.now)

    text = db.Column(db.String)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    user = db.relationship(User)

    post_id = db.Column(db.Integer, db.ForeignKey("post.id"))
    post = db.relationship(Post)