import os
import logging
import sys


from flask import Flask, render_template
from flask_wtf.csrf import CSRFError

import email_config
from extensions import csrf_protect, db, mail
from sites import main, blog

app = Flask(__name__)


CONFIG = dict(
    DEBUG=True,
    # EMAIL SETTINGS
    MAIL_SERVER=os.getenv("MAIL_SERVER", email_config.MAIL_SERVER),
    MAIL_PORT=os.getenv("MAIL_PORT", email_config.MAIL_PORT),
    MAIL_USE_SSL=True,
    MAIL_USERNAME=os.getenv("MAIL_USERNAME", email_config.MAIL_USERNAME),
    MAIL_PASSWORD=os.getenv("MAIL_PASSWORD", email_config.MAIL_PASSWORD),
    SQLALCHEMY_DATABASE_URI=os.getenv("DATABASE_URL", "sqlite:///blog.sqlite")
)

def register_extensions(app):
    db.init_app(app)
    mail.init_app(app)
    csrf_protect.init_app(app)

def register_blueprints(app):
    app.register_blueprint(blog.views.blueprint)
    app.register_blueprint(main.views.blueprint)
    app.register_blueprint(main.views.blueprint)

def configure_logger(app):
    handler = logging.StreamHandler(sys.stdout)
    if not app.logger.handlers:
        app.logger.addHandler(handler)


def create_app():
    #name ist aktueller Modulname
    app = Flask(__name__.split(".")[0])
    app.config.update(CONFIG)
    app.secret_key = b'dfdfgdsfgs-<34'

    register_extensions(app)
    register_blueprints(app)

    configure_logger(app)

    with app.app_context():
        db.create_all()

    return app

app = create_app()


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html', reason=e.description), 404


@app.errorhandler(500)
def server_error(e):
    return render_template('500.html', reason=e.description), 500

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return render_template('csrf_error.html', reason=e.description), 300



if __name__ == '__main__':
    app.run(host="localhost", port=7890)