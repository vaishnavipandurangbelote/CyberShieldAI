
import os
from flask import Flask
from routes.main_routes import main_bp

app = Flask(__name__)

app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    "dev-only-change-this-secret"
)

app.register_blueprint(main_bp)


if __name__ == "__main__":
    app.run(debug=True)
