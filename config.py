"""
AndroBlight Configuration
=========================
All configuration constants, environment variables, and app settings.
"""

import os

# Folder paths
UPLOAD_FOLDER = 'uploads'
TEMP_EXTRACT_FOLDER = 'temp_extract'
REPORTS_FOLDER = 'reports'
CACHE_FILE = 'scan_cache.json'
MODEL_PATH = os.environ.get('MODEL_PATH', 'model/')

# VirusTotal API (optional - set your API key)
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')
VIRUSTOTAL_ENABLED = bool(VIRUSTOTAL_API_KEY)

# Max file upload size (100 MB)
MAX_CONTENT_LENGTH = 100 * 1024 * 1024
