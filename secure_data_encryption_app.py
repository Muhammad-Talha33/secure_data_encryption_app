import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

# Secure config values
DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"
LOCKOUT_DURATION = 60  # seconds

# Session states
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

# Data file functions
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

# Key & Hash functions
def generate_key(passkey):
    key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)

def hash_password(password):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()

# Encryption / Decryption
def encrypt_text(text, key):
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypted_text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

# Load existing data
stored_data = load_data()

# App UI
st.set_page_config(page_title="Secure Data Encryption System", page_icon="🔐", layout="centered")
st.title("🛡️ Secure Data Encryption System")

menu = ["🏠 Home", "📝 Register", "🔐 Login", "💾 Store Data", "📤 Retrieve Data"]
choice = st.sidebar.selectbox("📂 Navigate", menu)

# Home Page
if choice == "🏠 Home":
    st.subheader("Welcome to 🔐 Secure Data Encryption System!")
    st.markdown("""
    🔒 **Encrypt & Decrypt Your Sensitive Data Securely!**

    ✅ Store personal notes or secrets with encryption  
    🔑 Unlock them anytime using your private passkey  
    🚫 3 wrong login attempts? You're locked for 1 minute!  
    💾 All data is saved securely in memory (no external DB)

    **Start by registering or logging in from the sidebar.**
    """)


# Register Page
elif choice == "📝 Register":
    st.subheader("🆕 Create Your Account")
    username = st.text_input("👤 Choose a Username")
    password = st.text_input("🔑 Choose a Password", type="password")

    if st.button("📌 Register"):
        if username and password:
            if username in stored_data:
                st.warning("⚠️ Username already exists. Try another one.")
            else:
                stored_data[username] = {
                    "password": hash_password(password),
                    "data": []
                }
                save_data(stored_data)
                st.success("✅ Account created successfully! You can now log in.")
        else:
            st.error("❌ Both username and password are required.")

# Login Page
elif choice == "🔐 Login":
    st.subheader("🔐 User Login")

    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f"⏳ Too many failed attempts. Please wait {remaining} seconds.")
        st.stop()

    username = st.text_input("👤 Enter Username")
    password = st.text_input("🔑 Enter Password", type="password")

    if st.button("🔓 Login"):
        if username in stored_data and stored_data[username]["password"] == hash_password(password):
            st.session_state.authenticated_user = username
            st.session_state.failed_attempts = 0
            st.success(f"🎉 Welcome back, **{username}**!")
        else:
            st.session_state.failed_attempts += 1
            remaining = 3 - st.session_state.failed_attempts
            st.error(f"❌ Invalid credentials! Attempts left: {remaining}")

            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                st.error("🚫 Too many failed attempts. You are locked for 60 seconds.")
                st.stop()

# Store Encrypted Data
elif choice == "💾 Store Data":
    if not st.session_state.authenticated_user:
        st.warning("🔐 Please login first to store data.")
    else:
        st.subheader("🔒 Securely Store Your Data")
        data = st.text_area("✍️ Enter your secret message")
        passkey = st.text_input("🔑 Create an encryption key", type="password")

        if st.button("📦 Encrypt & Save"):
            if data and passkey:
                encrypted = encrypt_text(data, passkey)
                stored_data[st.session_state.authenticated_user]["data"].append(encrypted)
                save_data(stored_data)
                st.success("✅ Data encrypted and saved successfully!")
            else:
                st.error("❗ Both message and passkey are required.")

# Retrieve Data
elif choice == "📤 Retrieve Data":
    if not st.session_state.authenticated_user:
        st.warning("🔐 Please login to retrieve data.")
    else:
        st.subheader("🔓 Retrieve & Decrypt Your Data")
        user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])

        if not user_data:
            st.info("ℹ️ You have no encrypted data saved yet.")
        else:
            st.write("📄 Encrypted Data Entries:")
            for i, item in enumerate(user_data):
                st.code(item, language="text")

            encrypted_input = st.text_area("📋 Paste the encrypted message")
            passkey = st.text_input("🔑 Enter the passkey to decrypt", type="password")

            if st.button("🔍 Decrypt"):
                result = decrypt_text(encrypted_input, passkey)
                if result:
                    st.success("🟢 Decryption successful!")
                    st.info(f"🔓 **Decrypted Message:**\n\n{result}")
                else:
                    st.error("❌ Incorrect passkey or invalid/corrupted data.")
