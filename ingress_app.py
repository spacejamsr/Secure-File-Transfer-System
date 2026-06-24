# =============================================================================
# SECURE FILE TRANSFER SYSTEM - INGRESS APP
# =============================================================================
# Purpose: Web application running on the connected network.
#          Allows authenticated users to upload files with metadata.
#          Files are saved to the staging folder for transfer
#          to the disconnected network.
#
# Spec Reference: Section 3.1 - Ingress WebApp (Connected Network)
# =============================================================================

import streamlit as st      # Web application framework
import os                   # File system operations
import uuid                 # Unique identifier generation
import hashlib              # SHA-256 hash calculation
import json                 # Reading/writing JSON files
import bcrypt               # Secure password hashing
import re                   # Regular expressions for input sanitization
from datetime import datetime, timezone  # Timestamp generation
from audit_log import write_log          # Audit logging module
from dotenv import load_dotenv           # Environment variable loading
import argparse             # handling command line arguments
import sys                  # accessing system information

# Load environment variables from .env file
# This keeps sensitive configuration out of the code (NFR-MAINT-002)
load_dotenv()

# =============================================================================
# COMMAND LINE ARGUMENT PARSING
# The staging path is passed as a command line argument to avoid hardcoding.
# This allows the app to be pointed at any folder without modifying the code.
#
# Usage: streamlit run ingress_app.py -- --staging-path /path/to/staging
# =============================================================================
parser = argparse.ArgumentParser()
parser.add_argument('--staging-path', type=str, default='staging', help='Path to the staging folder for transfer')
args, unknown = parser.parse_known_args()
STAGING_PATH = args.staging_path
INBOX_PATH = os.getenv("INBOX_PATH", "inbox")
MAX_LOGIN_ATTEMPTS = int(os.getenv("MAX_LOGIN_ATTEMPTS", 5))
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
USERS_FILE = os.path.join(SCRIPT_DIR, "users.json")

# Create staging folder automatically on startup if it doesn't exist
# Prevents crashes on first run (NFR-REL-001)
os.makedirs(STAGING_PATH, exist_ok=True)


# =============================================================================
# INPUT SANITIZATION FUNCTIONS
# Protects against injection attacks and directory traversal (NFR-REL-002,
# Section 8.3)
# =============================================================================

def sanitize_input(text, max_length=500):
    """
    Sanitizes free-text input fields by removing HTML tags, script injection
    attempts, and enforcing a maximum length.

    Args:
        text: The raw input string from the user
        max_length: Maximum allowed length (default 500 characters)

    Returns:
        A cleaned, safe string
    """
    if not text:
        return ""
    # Remove any HTML tags to prevent XSS attacks
    text = re.sub(r'<[^>]+>', '', text)
    # Remove javascript: protocol to prevent script injection
    text = re.sub(r'javascript:', '', text, flags=re.IGNORECASE)
    # Remove leading/trailing whitespace
    text = text.strip()
    # Enforce maximum length to prevent buffer overflow attempts
    if len(text) > max_length:
        text = text[:max_length]
    return text


def sanitize_filename(filename):
    """
    Sanitizes uploaded filenames to prevent directory traversal attacks.
    For example, a malicious filename like '../../etc/passwd' would be
    reduced to just 'etcpasswd'.

    Args:
        filename: The original filename from the uploaded file

    Returns:
        A safe filename with only allowed characters
    """
    # os.path.basename removes any path components (e.g. ../../)
    filename = os.path.basename(filename)
    # Only allow alphanumeric characters, spaces, hyphens, and dots
    filename = re.sub(r'[^\w\s\-\.]', '', filename)
    # Remove leading/trailing spaces and dots
    filename = filename.strip('. ')
    return filename


# =============================================================================
# USER MANAGEMENT FUNCTIONS
# Users are stored in users.json with bcrypt-hashed passwords.
# No plain text passwords are ever stored. (FR-ING-001, NFR-SEC-001)
# =============================================================================

def load_users():
    """
    Loads the user database from users.json.
    This file contains usernames mapped to bcrypt password hashes.
    It is created and managed by the create_users.py admin script.

    Returns:
        Dictionary of {username: password_hash}
    """
    with open(USERS_FILE, "r") as f:
        return json.load(f)


def check_login(username, password):
    """
    Verifies a username and password against the stored bcrypt hashes.
    bcrypt is used because it is deliberately slow, making brute force
    attacks computationally expensive. (NFR-SEC-001)

    Args:
        username: The username entered by the user
        password: The plain text password entered by the user

    Returns:
        True if credentials are valid, False otherwise
    """
    users = load_users()
    # Return False immediately if username doesn't exist
    # This prevents username enumeration
    if username not in users:
        return False
    # Encode stored hash back to bytes for bcrypt comparison
    stored_hash = users[username].encode()
    # bcrypt.checkpw hashes the input password and compares it to the stored hash
    return bcrypt.checkpw(password.encode(), stored_hash)


# =============================================================================
# SESSION STATE INITIALIZATION
# Streamlit reruns the entire script on every interaction, so we use
# session_state to persist login status across reruns.
# =============================================================================

# Track whether the user is currently logged in
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

# Track the username of the logged-in user
if "username" not in st.session_state:
    st.session_state.username = ""


# =============================================================================
# LOGIN PAGE
# Shown when the user is not authenticated. (FR-ING-001, FR-ING-013)
# =============================================================================

if not st.session_state.logged_in:
    st.title("Secure File Transfer System")
    st.subheader("Login")

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if check_login(username, password):
            # Successful login - update session state and log the event
            st.session_state.logged_in = True
            st.session_state.username = username
            write_log(
                "login_success",
                username=username,
                details={"app": "ingress"}
            )
            st.rerun()
        else:
            # Failed login - log the attempt for security monitoring
            # This helps detect brute force attacks (Section 8.1)
            write_log(
                "login_failure",
                username=username,
                details={"app": "ingress"},
                severity="warning"
            )
            st.error("Invalid username or password")


# =============================================================================
# MAIN APPLICATION
# Shown only when the user is authenticated. (FR-ING-013)
# =============================================================================

else:
    st.title("Secure File Transfer System")
    st.subheader("Ingress App - File Upload")
    st.write(f"Welcome, {st.session_state.username}!")

    # Logout button - clears session state and logs the event
    if st.button("Logout"):
        write_log(
            "logout",
            username=st.session_state.username,
            details={"app": "ingress"}
        )
        st.session_state.logged_in = False
        st.session_state.username = ""
        st.rerun()

    st.divider()

    # Load all users from users.json to populate the recipient dropdown.
    # The current user is excluded - you cannot send a file to yourself.
    # (FR-ING-006)
    all_users = load_users()
    valid_recipients = [u for u in all_users.keys() if u != st.session_state.username]

    # =============================================================================
    # UPLOAD FORM
    # Captures file and all required metadata fields. (FR-ING-005)
    # =============================================================================

    # Recipient dropdown - only valid users can be selected
    recipient = st.selectbox("Select Recipient", valid_recipients)

    # Optional metadata fields as per spec (FR-ING-005)
    description = st.text_area("File Description / Purpose")
    classification = st.selectbox("Classification Level", [
        "Unclassified",
        "Internal Use Only",
        "Confidential",
        "Secret",
        "Top Secret"
    ])
    handling_instructions = st.text_area("Handling Instructions")

    # Priority dropdown - Low, Normal, High (FR-ING-005)
    priority = st.selectbox("Priority", ["Low", "Normal", "High"])

    # File picker - no size or type restrictions (FR-ING-004)
    uploaded_file = st.file_uploader("Choose a file")

    if st.button("Upload File"):
        if not uploaded_file:
            st.error("Please select a file")
        else:
            # -----------------------------------------------------------------
            # STEP 1: Sanitize all inputs before processing (NFR-REL-002)
            # -----------------------------------------------------------------
            safe_description = sanitize_input(description)
            safe_handling = sanitize_input(handling_instructions)
            safe_filename = sanitize_filename(uploaded_file.name)

            # Reject upload if filename is invalid after sanitization
            if not safe_filename:
                st.error("Invalid filename detected. Please rename your file and try again.")
            else:
                # -------------------------------------------------------------
                # STEP 2: Generate a UUID for this upload (FR-ING-008)
                # UUID ensures each upload has a globally unique identifier
                # that can be used to track the file across both systems
                # -------------------------------------------------------------
                file_id = str(uuid.uuid4())

                # -------------------------------------------------------------
                # STEP 3: Create staging folder structure (FR-ING-009)
                # Structure: /staging/{UUID}/
                # In production, STAGING_PATH points to a network drive
                # accessible (FR-ING-012)
                # -------------------------------------------------------------
                folder_path = os.path.join(STAGING_PATH, file_id)
                os.makedirs(folder_path)

                # -------------------------------------------------------------
                # STEP 4: Save the uploaded file to the staging folder
                # getbuffer() reads the file contents into memory for writing
                # -------------------------------------------------------------
                file_path = os.path.join(folder_path, safe_filename)
                with open(file_path, "wb") as f:
                    f.write(uploaded_file.getbuffer())

                # -------------------------------------------------------------
                # STEP 5: Calculate SHA-256 hash for integrity verification
                # (FR-ING-011, NFR-SEC-005)
                # The hash is stored in metadata.json and verified by the
                # Egress app after transfer to detect any file corruption
                # or tampering during the transfer process
                # -------------------------------------------------------------
                sha256 = hashlib.sha256()
                with open(file_path, "rb") as f:
                    # Read file in 4096-byte chunks to handle large files
                    # without loading the entire file into memory
                    for chunk in iter(lambda: f.read(4096), b""):
                        sha256.update(chunk)
                file_hash = sha256.hexdigest()

                # -------------------------------------------------------------
                # STEP 6: Write metadata.json alongside the uploaded file
                # (FR-ING-008, FR-ING-010)
                # This file is the communication mechanism between the Ingress
                # and Egress apps. The Egress app reads this file to determine
                # who the file belongs to and verify its integrity.
                # -------------------------------------------------------------
                metadata = {
                    "file_id": file_id,                                         # Unique tracking identifier
                    "submitter": st.session_state.username,                     # Auto-captured from session
                    "recipient": recipient,                                      # Selected from dropdown
                    "original_filename": safe_filename,                         # Sanitized filename
                    "submission_timestamp": datetime.now(timezone.utc).isoformat(),  # UTC timestamp
                    "file_size_bytes": uploaded_file.size,                      # File size in bytes
                    "file_hash_sha256": file_hash,                              # Integrity fingerprint
                    "description": safe_description,                            # User provided description
                    "classification": classification,                       # Classification level
                    "handling_instructions": safe_handling,                     # Special instructions
                    "priority": priority,                                       # Low/Normal/High
                    "custom_fields": {}                                         # Reserved for future use
                }

                metadata_path = os.path.join(folder_path, "metadata.json")
                with open(metadata_path, "w") as f:
                    json.dump(metadata, f, indent=4)

                # -------------------------------------------------------------
                # STEP 7: Show confirmation and log the upload event
                # (FR-ING-007, FR-ING-015)
                # -------------------------------------------------------------
                st.success(f"File uploaded successfully! Tracking ID: {file_id}")
                write_log(
                    "file_upload",
                    username=st.session_state.username,
                    details={
                        "file_id": file_id,
                        "filename": safe_filename,
                        "recipient": recipient,
                        "file_size_bytes": uploaded_file.size,
                        "priority": priority
                    }
                )
                
                
