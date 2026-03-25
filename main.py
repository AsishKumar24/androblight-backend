# # app.py
# from flask import Flask, request, jsonify
# import tensorflow as tf
# import numpy as np
# from flask_cors import CORS
# import os
# import cv2
# from werkzeug.utils import secure_filename
# import shutil

# app = Flask(__name__)

# # Configuration
# UPLOAD_FOLDER = 'uploads'
# TEMP_EXTRACT_FOLDER = 'temp_extract'
# ALLOWED_EXTENSIONS = {'apk'}
# app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# CORS(app, resources={r"/*": {"origins": "http://localhost:5173"}})

# # Load the pre-trained model
# model = tf.keras.models.load_model('cnn-lstm_detection_model.h5')


# def allowed_file(filename):
#     return '.' in filename and \
#         filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# def apk_to_image(extracted_dir):
#     """
#     Converts the extracted APK files into a greyscale image array suitable for model prediction.
#     Returns: numpy array of shape (256, 256, 1)
#     """
#     # List of files to include in the image
#     files_to_include = ['classes.dex', 'AndroidManifest.xml', 'META-INF/CERT.RSA', 'resources.arsc']

#     # Read and concatenate the binary data from the files
#     binary_data = bytearray()
#     for file_name in files_to_include:
#         file_path = os.path.join(extracted_dir, file_name)
#         if os.path.exists(file_path):
#             with open(file_path, 'rb') as f:
#                 binary_data.extend(f.read())

#     # Convert binary data to a numpy array
#     data_array = np.frombuffer(binary_data, dtype=np.uint8)

#     # Calculate the size of the square image
#     size = int(np.ceil(np.sqrt(len(data_array))))

#     # Pad the data to fit into a square image
#     padded_data = np.zeros(size * size, dtype=np.uint8)
#     padded_data[:len(data_array)] = data_array

#     # Reshape the data into a 2D array (image)
#     image = padded_data.reshape((size, size))

#     # Resize the image to 256x256 using bilinear interpolation
#     resized_image = cv2.resize(image, (256, 256), interpolation=cv2.INTER_LINEAR)

#     # Normalize and add channel dimension
#     normalized_image = resized_image / 255.0
#     final_image = np.expand_dims(normalized_image, axis=-1)  # Shape: (256, 256, 1)

#     return final_image


# def extract_apk(apk_path, extract_dir):
#     """Extract APK to temporary directory"""
#     try:
#         shutil.unpack_archive(apk_path, extract_dir, 'zip')
#     except Exception as e:
#         raise Exception(f"Error extracting APK: {str(e)}")


# @app.route('/predict', methods=['POST'])
# def predict():
#     try:
#         # Check if file is present in request
#         if 'file' not in request.files:
#             return jsonify({'error': 'No file part'}), 400

#         file = request.files['file']

#         if file.filename == '':
#             return jsonify({'error': 'No selected file'}), 400

#         if file and allowed_file(file.filename):
#             # Save the uploaded APK
#             filename = secure_filename(file.filename)
#             apk_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
#             file.save(apk_path)

#             # Create temporary extraction directory
#             extract_dir = os.path.join(TEMP_EXTRACT_FOLDER, filename.split('.')[0])
#             os.makedirs(extract_dir, exist_ok=True)

#             # Extract APK
#             extract_apk(apk_path, extract_dir)

#             # Convert to image
#             image_array = apk_to_image(extract_dir)

#             # Add batch dimension for model prediction
#             image_array = np.expand_dims(image_array, axis=0)  # Shape: (1, 256, 256, 1)

#             # Make prediction
#             prediction = model.predict(image_array)

#             # Process prediction (assuming binary classification)
#             result = 'Malign' if prediction[0][0] > 0.5 else 'Benign'
#             confidence = float(prediction[0][0])

#             # Clean up
#             os.remove(apk_path)
#             shutil.rmtree(extract_dir)

#             return jsonify({
#                 'prediction': result,
#                 'confidence': confidence,
#                 'status': 'success'
#             })

#     except Exception as e:
#         # Clean up in case of error
#         if 'apk_path' in locals():
#             if os.path.exists(apk_path):
#                 os.remove(apk_path)
#         if 'extract_dir' in locals():
#             if os.path.exists(extract_dir):
#                 shutil.rmtree(extract_dir)

#         return jsonify({
#             'error': str(e),
#             'status': 'error'
#         }), 500


# @app.route('/health', methods=['GET'])
# def health():
#     return jsonify({'status': 'healthy'})


# if __name__ == '__main__':
#     # Create necessary directories
#     for folder in [UPLOAD_FOLDER, TEMP_EXTRACT_FOLDER]:
#         if not os.path.exists(folder):
#             os.makedirs(folder)

#     app.run(debug=True, host='0.0.0.0', port=5000)
# app.py
from flask import Flask, request, jsonify
import tensorflow as tf
import numpy as np
from flask_cors import CORS
import os
import cv2
from werkzeug.utils import secure_filename
import shutil

app = Flask(__name__)

# Configuration
UPLOAD_FOLDER = 'uploads'
TEMP_EXTRACT_FOLDER = 'temp_extract'
ALLOWED_EXTENSIONS = {'apk'}  # kept for reference; not used now
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

CORS(app, resources={r"/*": {"origins": "http://localhost:5173"}})

# Load the pre-trained model
model = tf.keras.models.load_model('cnn-lstm_detection_model.h5')


def allowed_file(filename):
    # Minimal edit: allow all file types
    return True


def apk_to_image(extracted_dir):
    """
    Converts the extracted APK files into a greyscale image array suitable for model prediction.
    Returns: numpy array of shape (256, 256, 1)
    """
    # List of files to include in the image
    files_to_include = ['classes.dex', 'AndroidManifest.xml', 'META-INF/CERT.RSA', 'resources.arsc']

    # Read and concatenate the binary data from the files
    binary_data = bytearray()
    for file_name in files_to_include:
        file_path = os.path.join(extracted_dir, file_name)
        if os.path.exists(file_path):
            with open(file_path, 'rb') as f:
                binary_data.extend(f.read())

    # Convert binary data to a numpy array
    data_array = np.frombuffer(binary_data, dtype=np.uint8)

    # Calculate the size of the square image
    size = int(np.ceil(np.sqrt(len(data_array)))) if len(data_array) > 0 else 1

    # Pad the data to fit into a square image
    padded_data = np.zeros(size * size, dtype=np.uint8)
    padded_data[:len(data_array)] = data_array

    # Reshape the data into a 2D array (image)
    image = padded_data.reshape((size, size))

    # Resize the image to 256x256 using bilinear interpolation
    resized_image = cv2.resize(image, (256, 256), interpolation=cv2.INTER_LINEAR)

    # Normalize and add channel dimension
    normalized_image = resized_image / 255.0
    final_image = np.expand_dims(normalized_image, axis=-1)  # Shape: (256, 256, 1)

    return final_image


def extract_apk(apk_path, extract_dir):
    """Extract APK to temporary directory"""
    try:
        shutil.unpack_archive(apk_path, extract_dir, 'zip')
    except Exception as e:
        raise Exception(f"Error extracting APK: {str(e)}")


@app.route('/predict', methods=['POST'])
def predict():
    try:
        # Check if file is present in request
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400

        file = request.files['file']

        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400

        if file and allowed_file(file.filename):
            # Save the uploaded file
            filename = secure_filename(file.filename)
            apk_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(apk_path)

            # Create temporary extraction directory
            extract_dir = os.path.join(TEMP_EXTRACT_FOLDER, filename.split('.')[0])
            os.makedirs(extract_dir, exist_ok=True)

            # Extract APK (note: if non-APK is uploaded, this may fail)
            extract_apk(apk_path, extract_dir)

            # Convert to image
            image_array = apk_to_image(extract_dir)

            # Add batch dimension for model prediction
            image_array = np.expand_dims(image_array, axis=0)  # Shape: (1, 256, 256, 1)

            # Make prediction
            prediction = model.predict(image_array)

            # Process prediction (assuming binary classification)
            result = 'Malign' if prediction[0][0] > 0.5 else 'Benign'
            confidence = float(prediction[0][0])

            # Clean up
            os.remove(apk_path)
            shutil.rmtree(extract_dir)

            return jsonify({
                'prediction': result,
                'confidence': confidence,
                'status': 'success'
            })

    except Exception as e:
        # Clean up in case of error
        if 'apk_path' in locals():
            if os.path.exists(apk_path):
                os.remove(apk_path)
        if 'extract_dir' in locals():
            if os.path.exists(extract_dir):
                shutil.rmtree(extract_dir)

        return jsonify({
            'error': str(e),
            'status': 'error'
        }), 500


@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy'})


if __name__ == '__main__':
    # Create necessary directories
    for folder in [UPLOAD_FOLDER, TEMP_EXTRACT_FOLDER]:
        if not os.path.exists(folder):
            os.makedirs(folder)

    app.run(debug=True, host='0.0.0.0', port=5000)
