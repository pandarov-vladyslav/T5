"""Application factory for the authentication learning project."""
import os

from flask import Flask

from auth import auth_bp, init_auth_db


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY"),
        DATABASE=os.environ.get("DATABASE_PATH", "auth.sqlite3"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("FLASK_ENV") == "production",
    )

    if test_config:
        app.config.update(test_config)

    if not app.config.get("SECRET_KEY"):
        if app.config.get("TESTING"):
            app.config["SECRET_KEY"] = "test-only-secret"
        else:
            raise RuntimeError("Set the SECRET_KEY environment variable.")

    app.register_blueprint(auth_bp, url_prefix="/auth")

    with app.app_context():
        init_auth_db()

    @app.get("/")
    def index():
        return {"message": "Authentication API is running."}

    return app


if __name__ == "__main__":
    application = create_app()
    application.run(debug=False)
