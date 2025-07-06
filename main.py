import os
from flask import Flask, jsonify
from dotenv import load_dotenv
from supabase_utils import create_client, Client
from Generator import generate_otp_qr_code, decrypt_otp_from_cipher_text
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

@app.route('/decrypt_otp', methods=['POST'])
def decrypt_otp():
    print("Starting decryption and verification endpoint...")
    try:
        data = request.get_json()
        cipher_text_b64 = data.get('cipher_text')
        uid = data.get('uid')
        mobile_ip = data.get('mobile_ip')  # new input

        print(f"Received data: cipher_text={cipher_text_b64}, uid={uid}, mobile_ip={mobile_ip}")

        if not cipher_text_b64 or not uid or not mobile_ip:
            return jsonify({"error": "Missing 'cipher_text', 'uid', or 'mobile_ip' in request body"}), 400

        # 1. Fetch the OTP record by uid and cipher_text
        resp = supabase.table('OTP_Handle') \
            .select('id, OTP') \
            .eq('UID', uid) \
            .eq('Cipher_Text', cipher_text_b64) \
            .execute()

        print(f"Supabase response: {resp}")

        records = resp.data
        if not records or len(records) == 0:
            return jsonify({"success": False, "error": "No matching OTP record found"}), 404

        record = records[0]
        record_id = record['id']
        stored_otp = record['OTP']

        # 2. Mark OTP unusable and update Cellular_IP
        update_resp = supabase.table('OTP_Handle') \
            .update({'Useable': False, 'Cellular_IP': mobile_ip}) \
            .eq('id', record_id) \
            .execute()

        
        # 3. Decrypt OTP from cipher_text
        decrypted_otp = decrypt_otp_from_cipher_text(cipher_text_b64, uid, supabase)

        # 4. Compare decrypted OTP with stored OTP
        if decrypted_otp != stored_otp:
            return jsonify({"success": False, "error": "OTP mismatch"}), 401

        # 5. Update success = True
        success_resp = supabase.table('OTP_Handle') \
            .update({'Success': True}) \
            .eq('id', record_id) \
            .execute()

        

        # 6. Return success response
        return jsonify({
            "success": True,
            "message": "OTP verified and consumed successfully",
            "decrypted_otp": decrypted_otp,
            "record_id": record_id
        })

    except Exception as e:
        print("Error in /decrypt_otp:", str(e))
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500




if __name__ == '__main__':
    app.run(debug=True)

