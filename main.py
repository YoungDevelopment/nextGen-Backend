import os
from flask import Flask, jsonify
from dotenv import load_dotenv
from supabase_utils import create_client, Client
from Generator import generate_otp_qr_code
from supabase_utils import check_otp_status
from flask import request
from flask_cors import CORS

# Load environment variables
load_dotenv()
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

# Initialize Supabase client
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Initialize Flask app
app = Flask(__name__)
CORS(app)

@app.route('/generate', methods=['POST'])
def generate_otp():
    try:
        data = request.get_json()
        machine_ip = data.get('machine_ip')
        uid = data.get('uid')

        if not machine_ip or not uid:
            return jsonify({'error': 'machine_ip and uid are required'}), 400

        fun_res = generate_otp_qr_code(machine_ip, uid)
        cipher_text = fun_res.get('cipher_text', 'No cipher text generated')

        return jsonify({'cipher_text': cipher_text}), 200
    except Exception as e:
        print("Error in /generate endpoint:", str(e))
        return jsonify({'error': str(e)}), 500

@app.route('/ping', methods=['GET'])
def otp_status():
    cipher_text = request.args.get('cipher_text')
    uid = request.args.get('uid')

    if not cipher_text or not uid:
        return jsonify({"error": "Missing cipher_text or uid parameter"}), 400

    status = check_otp_status(cipher_text, uid)
    if status is None:
        return jsonify({"status": "not found or error"}), 404

    return jsonify({"success": status}), 200

if __name__ == '__main__':
    app.run(debug=True)
