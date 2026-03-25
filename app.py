"""
AndroBlight — Enhanced API Server v3.0
=======================================
Flask application factory with modular architecture.
CNN-BiLSTM v3 model for Android malware detection.

Author: AndroBlight Group-47
"""

# Suppress TensorFlow warnings
import os
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
import warnings
warnings.filterwarnings('ignore', category=DeprecationWarning)
warnings.filterwarnings('ignore', category=FutureWarning)

import tensorflow as tf
from flask import Flask
from flask_cors import CORS

from config import UPLOAD_FOLDER, TEMP_EXTRACT_FOLDER, REPORTS_FOLDER, MAX_CONTENT_LENGTH, MODEL_PATH


def load_model():
    """Load the CNN-BiLSTM v3 model from the model/ directory"""
    if os.path.exists(MODEL_PATH):
        try:
            model = tf.keras.models.load_model(MODEL_PATH)
            print("✅ CNN-BiLSTM v3 model loaded successfully")
            return model
        except Exception as e:
            print(f"⚠️ Failed to load model: {e}")
            return None
    else:
        print("⚠️ Model directory not found - running in demo mode")
        return None


def create_app():
    """Flask application factory"""
    app = Flask(__name__)
    
    # Configuration
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
    
    # CORS — allow all origins for development
    CORS(app, resources={r"/*": {"origins": "*"}})
    
    # Load ML model and store in app config
    app.config['ML_MODEL'] = load_model()
    
    # Register blueprints
    from routes.scan import scan_bp
    from routes.admin import admin_bp
    
    app.register_blueprint(scan_bp)
    app.register_blueprint(admin_bp)
    
    return app


# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    # Create necessary directories
    for folder in [UPLOAD_FOLDER, TEMP_EXTRACT_FOLDER, REPORTS_FOLDER]:
        os.makedirs(folder, exist_ok=True)
    
    app = create_app()
    model = app.config.get('ML_MODEL')
    
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║   █████╗ ███╗   ██╗██████╗ ██████╗  ██████╗ ██████╗ ██╗      ║
    ║  ██╔══██╗████╗  ██║██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██║      ║
    ║  ███████║██╔██╗ ██║██║  ██║██████╔╝██║   ██║██████╔╝██║      ║
    ║  ██╔══██║██║╚██╗██║██║  ██║██╔══██╗██║   ██║██╔══██╗██║      ║
    ║  ██║  ██║██║ ╚████║██████╔╝██║  ██║╚██████╔╝██████╔╝███████╗ ║
    ║  ╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝ ║
    ║                                                               ║
    ║               Enhanced API Server v3.0                        ║
    ║               CNN-BiLSTM v3 Model (128×128)                   ║
    ╚═══════════════════════════════════════════════════════════════╝
    
    🚀 Server starting on http://0.0.0.0:5000
    
    📋 Available Endpoints:
       GET  /health           - Health check & feature list
       POST /predict          - Scan APK file (full analysis)
       POST /predict-playstore - Scan Play Store app
       POST /batch-predict    - Batch scan multiple APKs
       GET  /report/<hash>    - Download PDF report
       GET  /stats            - Get scan statistics
       POST /clear-cache      - Clear scan cache
    
    ⚙️  Configuration:
       • Model loaded: """ + ("✅ Yes (v3 - 128×128)" if model else "❌ No (Demo Mode)") + """
       • VirusTotal:   """ + ("✅ Enabled" if os.environ.get('VIRUSTOTAL_API_KEY') else "❌ Disabled") + """
       • Max file size: 100 MB
       • Cache enabled: ✅ Yes
    """)
    
    app.run(debug=True, host='0.0.0.0', port=5000)
