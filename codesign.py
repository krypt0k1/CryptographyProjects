import pkcs11
import json
from flask import Flask, request, jsonify, Response
from flask_cors import CORS
from pkcs11 import KeyType, Mechanism, ObjectClass, KeyType
from hashlib import *
from hashlib import sha256

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Initialize PKCS#11 library (adjust path to your PKCS#11 library)
PKCS11_LIB_PATH = 'C:\\Program Files\\nCipher\\nfast\\toolkits\\pkcs11\\cknfast.dll'

lib = pkcs11.lib(PKCS11_LIB_PATH)

@app.route('/sign', methods=['POST'])
def sign_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    # Read the file data
    file_data = file.read()

    # Hash the file data
    hash_value = sha256(file_data).digest()

    # Sign the data using the HSM
   
    token = lib.get_token(token_label='loadshared accelerator')
        
    with token.open(rw=True, user_pin="1234") as session:       
            
        # Get the signing key from the HSM
        signing_key = session.get_key(object_class = ObjectClass.PRIVATE_KEY, label ="rsa_key")  # Use the correct key label
            
        
        # Sign the hash value
        signature = signing_key.sign(hash_value)

    response_data = {
        'Signature for file named': file.filename,
        'status': 'success',
        'hash': hash_value.hex(),  # Return hash in hex format
        'signature': signature.hex()  # Return signature in hex format
    }

    # Beautify the JSON output
    response_json = json.dumps(response_data, indent=4)
    return Response(response_json, mimetype='application/json')

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'API is running'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
