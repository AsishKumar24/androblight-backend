"""
Scan Routes
============
API endpoints for APK scanning: /predict, /predict-playstore, /batch-predict
"""

import os
import hashlib
import shutil
import numpy as np
from datetime import datetime
from flask import Blueprint, request, jsonify
from werkzeug.utils import secure_filename

from config import UPLOAD_FOLDER, TEMP_EXTRACT_FOLDER, VIRUSTOTAL_ENABLED
from services.scanner import (
    extract_apk, apk_to_image, classify_malware_family,
    get_file_hash, get_apk_metadata, load_cache, save_cache
)
from services.permissions import parse_android_manifest, analyze_permissions
from services.certificate import extract_certificate_info
from services.virustotal import check_virustotal

import re

scan_bp = Blueprint('scan', __name__)


def _get_model():
    """Get the loaded ML model from the app context"""
    from flask import current_app
    return current_app.config.get('ML_MODEL')


def _generate_mock_response(filename="demo.apk"):
    """Generate mock response when model is not available"""
    import random
    
    is_malware = random.random() > 0.5
    confidence = random.uniform(0.7, 0.95)
    
    return {
        'status': 'success',
        'demo_mode': True,
        'metadata': {
            'file_name': filename,
            'file_size': random.randint(1000000, 50000000),
            'file_size_readable': f"{random.randint(1, 50)} MB",
            'sha256': hashlib.sha256(os.urandom(32)).hexdigest(),
            'md5': hashlib.md5(os.urandom(16)).hexdigest(),
            'scan_timestamp': datetime.now().isoformat(),
            'package_name': f"com.{filename.replace('.apk', '')}",
            'version_name': f"{random.randint(1, 5)}.{random.randint(0, 9)}.{random.randint(0, 9)}",
            'main_activity': f".{filename.replace('.apk', '').title()}MainActivity"
        },
        'ml_detection': {
            'label': 'Malware' if is_malware else 'Benign',
            'confidence': confidence,
            'malware_family': classify_malware_family(confidence) if is_malware else None
        },
        'permission_analysis': {
            'total_count': random.randint(5, 20),
            'critical': [{'permission': 'android.permission.READ_SMS', 'description': 'Read SMS', 'risk': 'Can access messages'}] if is_malware else [],
            'high': [{'permission': 'android.permission.CAMERA', 'description': 'Camera access', 'risk': 'Can take photos'}],
            'medium': [{'permission': 'android.permission.INTERNET', 'description': 'Internet', 'risk': 'Can send data'}],
            'low': [],
            'unknown': [],
            'suspicious_combos': [{'threat': 'SMS Stealer', 'description': 'Can intercept SMS'}] if is_malware else [],
            'risk_score': random.randint(60, 90) if is_malware else random.randint(10, 40)
        },
        'certificate': {
            'signed': True,
            'debug_signed': is_malware,
            'fingerprint_sha256': hashlib.sha256(os.urandom(32)).hexdigest()
        },
        'overall_score': random.randint(20, 40) if is_malware else random.randint(75, 95),
        'threat_level': 'high' if is_malware else 'low',
        'recommendation': 'Do not install this application' if is_malware else 'This application appears safe'
    }


def _get_recommendation(threat_level, ml_result, perm_analysis):
    """Generate recommendation based on analysis"""
    recommendations = []
    
    if threat_level == 'critical':
        recommendations.append("⚠️ DO NOT INSTALL - High malware probability detected")
    elif threat_level == 'high':
        recommendations.append("⚠️ Exercise extreme caution - Multiple risk indicators found")
    elif threat_level == 'medium':
        recommendations.append("⚠️ Review permissions carefully before installing")
    else:
        recommendations.append("✅ This application appears safe to install")
    
    if perm_analysis.get('suspicious_combos'):
        for combo in perm_analysis['suspicious_combos']:
            recommendations.append(f"🚨 {combo['threat']}: {combo['description']}")
    
    if len(perm_analysis.get('critical', [])) > 0:
        recommendations.append(f"🔴 {len(perm_analysis['critical'])} critical permissions requested")
    
    return recommendations


@scan_bp.route('/predict', methods=['POST'])
def predict():
    """
    Scan APK file for malware.
    
    Request: multipart/form-data with 'file' field
    Response: Comprehensive scan result with all analyses
    """
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided', 'status': 'error'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected', 'status': 'error'}), 400
        
        # Save uploaded file
        filename = secure_filename(file.filename)
        apk_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(apk_path)
        
        # Check cache
        file_hash = get_file_hash(apk_path)
        cache = load_cache()
        
        if file_hash in cache:
            os.remove(apk_path)
            cached = cache[file_hash]
            cached['cached'] = True
            return jsonify(cached)
        
        # Create extraction directory
        extract_dir = os.path.join(TEMP_EXTRACT_FOLDER, filename.split('.')[0])
        os.makedirs(extract_dir, exist_ok=True)
        
        # Extract APK
        if not extract_apk(apk_path, extract_dir):
            os.remove(apk_path)
            shutil.rmtree(extract_dir, ignore_errors=True)
            return jsonify({'error': 'Failed to extract APK', 'status': 'error'}), 400
        
        # Get metadata
        metadata = get_apk_metadata(apk_path, extract_dir)
        
        # Parse manifest and analyze permissions
        manifest = parse_android_manifest(extract_dir)
        perm_analysis = analyze_permissions(manifest['permissions'])
        
        # Get certificate info
        cert_info = extract_certificate_info(extract_dir)
        
        # ML Detection
        model = _get_model()
        if model is not None:
            image_array = apk_to_image(extract_dir)
            image_array = np.expand_dims(image_array, axis=0)
            prediction = model.predict(image_array)
            
            is_malware = prediction[0][0] > 0.5
            confidence = float(prediction[0][0]) if is_malware else float(1 - prediction[0][0])
            
            ml_result = {
                'label': 'Malware' if is_malware else 'Benign',
                'confidence': confidence,
                'raw_score': float(prediction[0][0]),
                'malware_family': classify_malware_family(confidence) if is_malware else None
            }
        else:
            # Demo mode
            import random
            is_malware = random.random() > 0.6
            confidence = random.uniform(0.75, 0.95)
            ml_result = {
                'label': 'Malware' if is_malware else 'Benign',
                'confidence': confidence,
                'demo_mode': True,
                'malware_family': classify_malware_family(confidence) if is_malware else None
            }
        
        # VirusTotal check
        vt_result = check_virustotal(file_hash) if VIRUSTOTAL_ENABLED else None
        
        # Calculate overall score (0-100, higher is safer)
        overall_score = 100
        overall_score -= perm_analysis['risk_score'] * 0.3
        if ml_result['label'] == 'Malware':
            overall_score -= ml_result['confidence'] * 40
        if cert_info.get('debug_signed'):
            overall_score -= 10
        if vt_result and vt_result.get('malicious', 0) > 0:
            overall_score -= vt_result['malicious'] * 2
        
        overall_score = max(0, min(100, overall_score))
        
        # Determine threat level
        if overall_score < 30:
            threat_level = 'critical'
        elif overall_score < 50:
            threat_level = 'high'
        elif overall_score < 70:
            threat_level = 'medium'
        else:
            threat_level = 'low'
        
        # Build response
        result = {
            'status': 'success',
            'metadata': {
                **metadata,
                'package_name': manifest['package_name'],
                'version_name': manifest['version_name']
            },
            'manifest': {
                'package_name': manifest['package_name'],
                'permissions_count': len(manifest['permissions'])
            },
            'ml_detection': ml_result,
            'permission_analysis': perm_analysis,
            'certificate': cert_info,
            'virustotal': vt_result,
            'overall_score': round(overall_score),
            'threat_level': threat_level,
            'recommendation': _get_recommendation(threat_level, ml_result, perm_analysis)
        }
        
        # Cache result
        cache[file_hash] = result
        save_cache(cache)
        
        # Cleanup
        os.remove(apk_path)
        shutil.rmtree(extract_dir, ignore_errors=True)
        
        return jsonify(result)
        
    except Exception as e:
        # Cleanup on error
        if 'apk_path' in locals() and os.path.exists(apk_path):
            os.remove(apk_path)
        if 'extract_dir' in locals() and os.path.exists(extract_dir):
            shutil.rmtree(extract_dir, ignore_errors=True)
        
        return jsonify({'error': str(e), 'status': 'error'}), 500


@scan_bp.route('/predict-playstore', methods=['POST'])
def predict_playstore():
    """
    Scan Play Store app by URL or package name.
    
    Request JSON: {"url": "..."} or {"package": "com.example.app"}
    Response: Same as /predict endpoint
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No JSON data provided', 'status': 'error'}), 400
        
        url = data.get('url')
        package = data.get('package')
        
        if not url and not package:
            return jsonify({'error': 'Provide either url or package name', 'status': 'error'}), 400
        
        # Extract package name from URL if needed
        if url:
            match = re.search(r'id=([a-zA-Z0-9_.]+)', url)
            if match:
                package = match.group(1)
            else:
                return jsonify({'error': 'Invalid Play Store URL', 'status': 'error'}), 400
        
        # For now, return a mock response
        mock_res = _generate_mock_response(f"{package}.apk")
        mock_res['metadata']['package_name'] = package
        
        # Save to cache so PDF can find it
        file_hash = mock_res['metadata']['sha256']
        cache = load_cache()
        cache[file_hash] = mock_res
        save_cache(cache)
        
        return jsonify({
            'status': 'success',
            'demo_mode': True,
            'message': 'Play Store scanning requires APK download integration',
            'package_name': package,
            **mock_res
        })
        
    except Exception as e:
        return jsonify({'error': str(e), 'status': 'error'}), 500


@scan_bp.route('/batch-predict', methods=['POST'])
def batch_predict():
    """
    Scan multiple APK files in one request.
    
    Request: multipart/form-data with multiple 'files' fields
    Response: Array of scan results
    """
    try:
        if 'files' not in request.files:
            return jsonify({'error': 'No files provided', 'status': 'error'}), 400
        
        files = request.files.getlist('files')
        
        if len(files) > 10:
            return jsonify({'error': 'Maximum 10 files per batch', 'status': 'error'}), 400
        
        results = []
        
        for file in files:
            if file.filename:
                mock_res = _generate_mock_response(file.filename)
                results.append({
                    'filename': file.filename,
                    **mock_res
                })
                
                # Save to cache
                file_hash = mock_res['metadata']['sha256']
                cache = load_cache()
                cache[file_hash] = mock_res
                save_cache(cache)
        
        return jsonify({
            'status': 'success',
            'total_files': len(results),
            'results': results
        })
        
    except Exception as e:
        return jsonify({'error': str(e), 'status': 'error'}), 500
