"""
NetRunner OS - Application Factory
"""

import os
from flask import Flask, render_template


def create_app():
    app = Flask(__name__)

    # Config
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    app.config['UPLOAD_FOLDER'] = os.path.join(base_dir, 'uploads')
    app.config['LAST_PCAP'] = None

    # Ensure directories exist
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(os.path.join(base_dir, 'data', 'profiles'), exist_ok=True)

    # Register route blueprints
    from app.routes.pcap import bp as pcap_bp
    from app.routes.replay import bp as replay_bp
    from app.routes.generator import bp as generator_bp
    from app.routes.profiles import bp as profiles_bp

    app.register_blueprint(pcap_bp)
    app.register_blueprint(replay_bp)
    app.register_blueprint(generator_bp)
    app.register_blueprint(profiles_bp)

    @app.route('/')
    def index():
        return render_template('index.html')

    return app
