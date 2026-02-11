from flask import Flask, render_template
import os

def create_app():
    app = Flask(__name__)
    app.config['UPLOAD_FOLDER'] = 'uploads'
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    from app.core.database import init_database
    init_database()

    from app import routes
    app.register_blueprint(routes.bp)

    @app.route('/')
    def index():
        return render_template('index.html')

    return app
