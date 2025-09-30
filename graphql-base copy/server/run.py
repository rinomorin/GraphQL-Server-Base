from flask import Flask
from config import Config
from api.routes import graphql_bp

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    app.register_blueprint(graphql_bp)
    return app

if __name__ == "__main__":
    app = create_app()
    app.run(port=5000)  # You can change this to 5001 for venv312
