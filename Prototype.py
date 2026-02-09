import streamlit as st
import base64
import os
import qrcode
import cv2
import numpy as np
from io import BytesIO
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend

# ---------- HELPER FUNCTIONS ----------

def generate_key(password: str, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# ---------- SESSION STATE ----------

if "page" not in st.session_state:
    st.session_state.page = "Landing"

if "qr_buffer" not in st.session_state:
    st.session_state.qr_buffer = None

# ---------- NAVIGATION ----------

def go_to(page_name):
    st.session_state.page = page_name

# ---------- APP ----------

st.set_page_config(page_title="Secure QR Vault", page_icon="🔐")
st.title("🔐 Secure QR Vault")

# ------------------- LANDING PAGE -------------------

if st.session_state.page == "Landing":
    st.subheader("Choose an option")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Encrypt & Generate QR"):
            go_to("EncryptForm")
    with col2:
        if st.button("Decrypt QR"):
            go_to("DecryptForm")

# ------------------- ENCRYPTION FORM -------------------

elif st.session_state.page == "EncryptForm":
    st.subheader("Encrypt your message")
    message = st.text_area("Message to encrypt")
    password = st.text_input("Set password", type="password")
    confirm_password = st.text_input("Confirm password", type="password")

    if st.button("Generate QR"):
        if not message or not password:
            st.warning("Please enter message and password.")
        elif password != confirm_password:
            st.error("Passwords do not match.")
        else:
            salt = os.urandom(16)
            key = generate_key(password, salt)
            cipher = Fernet(key)
            encrypted_data = cipher.encrypt(message.encode())
            payload = base64.urlsafe_b64encode(salt + encrypted_data).decode()

            # Generate QR
            qr_img = qrcode.make(payload)
            buf = BytesIO()
            qr_img.save(buf, format="PNG")
            buf.seek(0)

            st.session_state.qr_buffer = buf
            go_to("QRPreview")

    if st.button("⬅ Back "):
        go_to("Landing")

# ------------------- QR PREVIEW -------------------

elif st.session_state.page == "QRPreview":
    st.subheader("Your Encrypted QR Code")
    if st.session_state.qr_buffer:
        st.image(st.session_state.qr_buffer, caption="Encrypted QR")
        st.download_button(
            "Download QR Code",
            st.session_state.qr_buffer,
            file_name="secure_qr.png",
            mime="image/png"
        )
    else:
        st.info("No QR generated yet.")

    if st.button("⬅ Back "):
        go_to("EncryptForm")

# ------------------- DECRYPTION FORM -------------------

elif st.session_state.page == "DecryptForm":
    st.subheader("Decrypt QR Code")
    uploaded_file = st.file_uploader("Upload QR image", type=["png", "jpg", "jpeg"])
    password = st.text_input("Enter decryption password", type="password")

    if st.button("Decrypt QR"):
        if not uploaded_file or not password:
            st.warning("Please upload a QR image and enter the password.")
        else:
            file_bytes = np.asarray(bytearray(uploaded_file.read()), dtype=np.uint8)
            img = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)
            detector = cv2.QRCodeDetector()
            data, _, _ = detector.detectAndDecode(img)

            if not data:
                st.error("No QR code detected in the image.")
            else:
                try:
                    decoded_payload = base64.urlsafe_b64decode(data.encode())
                    salt = decoded_payload[:16]
                    encrypted_text = decoded_payload[16:]

                    key = generate_key(password, salt)
                    cipher = Fernet(key)
                    decrypted_message = cipher.decrypt(encrypted_text).decode()

                    st.success("Decryption successful!")
                    st.text_area("Decrypted message:", decrypted_message, height=150)
                except Exception:
                    st.error("Incorrect password or corrupted QR code.")

    if st.button("⬅ Back"):
        go_to("Landing")
