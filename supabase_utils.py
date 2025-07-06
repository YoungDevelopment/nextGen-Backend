from supabase import create_client, Client
from dotenv import load_dotenv
import os
from typing import Optional, Dict

load_dotenv()
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

# Initialize Supabase client
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# OTP Logging & Update
def log_otp_to_supabase(uid: str, machine_ip: str, cellular_ip: str, cipher_text: str, otp: str, iv: Optional[str] = None, tag: Optional[str] = None) -> Optional[Dict]:
    record = {
        "UID": uid,
        "Machine_IP": machine_ip,
        "Cellular_IP": cellular_ip,
        "Cipher_Text": cipher_text,
        "OTP": otp,
        "Useable": True,
        "Success": False,
    }

    # Add IV and tag if provided
    if iv:
        record["iv"] = iv
    if tag:
        record["tag"] = tag

    try:
        response = supabase.table("OTP_Handle").insert(record).execute()
        return response.data[0] if response.data else None
    except Exception as e:
        print(f"Error logging OTP: {str(e)}")
def mark_otp_unusable_by_uid(uid: str) -> bool:
    try:
        response = supabase.table("OTP_Handle") \
            .update({"Useable": False}) \
            .eq("UID", uid) \
            .execute()
        return response.status_code == 200 and response.data is not None
    except Exception as e:
        print(f"Error updating OTP_Handle for User {uid}: {str(e)}")
        return False

# Key Management Helpers
def save_keys_to_supabase(client: Client, uid: str, private_pem: str, public_pem: str) -> bool:
    key_data = {
        'UID': uid,
        'Private_Key': private_pem,
        'Public_Key': public_pem,
        'created_at': 'now()'
    }
    try:
        existing = client.table("Keys").select("*").eq("UID", uid).execute()
        if existing.data:
            response = client.table("Keys").update(key_data).eq("UID", uid).execute()
        else:
            response = client.table("Keys").insert(key_data).execute()
        return bool(response.data)
    except Exception as e:
        print(f"Error saving keys to Supabase: {str(e)}")
        return False

def load_keys_from_supabase(client: Client, uid: str) -> Optional[Dict]:
    try:
        response = client.table("Keys").select("*").eq("UID", uid).execute()
        if not response.data:
            return None
        return response.data[0]
    except Exception as e:
        print(f"Error loading keys from Supabase: {str(e)}")
        return None

def keys_exist_in_supabase(client: Client, uid: str) -> bool:
    try:
        response = client.table("Keys").select("UID").eq("UID", uid).execute()
        return bool(response.data)
    except Exception as e:
        print(f"Error checking key existence: {str(e)}")
        return False

def delete_keys_from_supabase(client: Client, uid: str) -> bool:
    try:
        client.table("Keys").delete().eq("UID", uid).execute()
        return True
    except Exception as e:
        print(f"Error deleting keys from Supabase: {str(e)}")
        return False

def get_public_key_from_supabase(client: Client, uid: str) -> Optional[str]:
    try:
        response = client.table("Keys").select("Public_Key").eq("UID", uid).execute()
        if not response.data:
            return None
        return response.data[0]['Public_Key']
    except Exception as e:
        print(f"Error fetching public key: {str(e)}")
        return None

def check_otp_status(cipher_text: str, uid: str) -> Optional[bool]:
    try:
        response = supabase.table("OTP_Handle") \
            .select("Success") \
            .eq("Cipher_Text", cipher_text) \
            .eq("UID", uid) \
            .execute()
        if response.data and len(response.data) > 0:
            success = response.data[0].get("Success")
            if success:
                # Mark OTP as unusable for this UID
                supabase.table("OTP_Handle") \
                    .update({"Useable": False}) \
                    .eq("UID", uid) \
                    .eq("Cipher_Text", cipher_text) \
                    .eq("Useable", True) \
                    .execute()
            return success
        return None
    except Exception as e:
        print(f"Error fetching OTP status: {str(e)}")
        return None
