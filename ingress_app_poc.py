# =============================================================================
# SECURE FILE TRANSFER SYSTEM - INGRESS APP (PoC Version)
# =============================================================================
# Purpose: Web application running on the connected network.
#          For this PoC, transfers a fixed test.txt file to the staging folder.
#          The staging folder path is passed as a command line argument.
#
# Usage:
#   streamlit run ingress_app.py -- --staging-path /path/to/staging/folder
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
import argparse             # Command line argument parsing
import sys                  # System arguments
import shutil               # File copying
from datetime import datetime, timezone  # Timestamp generation
from audit_log import write_log          # Audit logging module
from dotenv import load_dotenv           # Environment variable loading

# Load environment variables from .env file
load_dotenv()

# =============================================================================
# COMMAND LINE ARGUMENT PARSING
# Staging path is passed as a command line argument to avoid hardcoding.
# Usage: streamlit run ingress_app.py -- --staging-path /path/to/staging
# =============================================================================
parser = argparse.ArgumentParser()
parser.add_argument('--staging-path', type=str, default='staging',
                    help='Path to the staging folder for the data diode transfer')
args = parser.parse_args(sys.argv[1:])

STAGING_PATH = args.staging_path
MAX_LOGIN_ATTEMPTS = int(os.getenv("MAX_LOGIN_ATTEMPTS", 5))

# Path to the fixed test file - must be in the same folder as this script
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_FILE_PATH = os.path.join(SCRIPT_DIR, "test.txt")
USERS_FILE = os.path.join(SCRIPT_DIR, "users.json")

# Create staging folder automatically on startup if it doesn't exist
os.makedirs(STAGING_PATH, exist_ok=True)


# =============================================================================
# INPUT SANITIZATION FUNCTIONS
# Protects against injection attacks and directory traversal (NFR-REL-002)
# =============================================================================

def sanitize_input(text, max_length=500):
    """
    Sanitizes free-text input fields by removing HTML tags, script injection
    attempts, and enforcing a maximum length.
    """
    if not text:
        return ""
    text = re.sub(r'<[^>]+>', '', text)
    text = re.sub(r'javascript:', '', text, flags=re.IGNORECASE)
    text = text.strip()
    if len(text) > max_length:
        text = text[:max_length]
    return text


# =============================================================================
# USER MANAGEMENT FUNCTIONS
# Users are stored in users.json with bcrypt-hashed passwords.
# No plain text passwords are ever stored. (FR-ING-001, NFR-SEC-001)
# =============================================================================

def load_users():
    """
    Loads the user database from users.json.
    """
    with open(USERS_FILE, "r") as f:
        return json.load(f)


def check_login(username, password):
    """
    Verifies a username and password against the stored bcrypt hashes.
    """
    users = load_users()
    if username not in users:
        return False
    stored_hash = users[username].encode()
    return bcrypt.checkpw(password.encode(), stored_hash)


# =============================================================================
# SESSION STATE INITIALIZATION
# =============================================================================

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "username" not in st.session_state:
    st.session_state.username = ""


# =============================================================================
# LOGIN PAGE (FR-ING-001, FR-ING-013)
# =============================================================================

if not st.session_state.logged_in:
    st.title("Secure File Transfer System")
    st.subheader("Ingress App - Login")

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if check_login(username, password):
            st.session_state.logged_in = True
            st.session_state.username = username
            write_log(
                "login_success",
                username=username,
                details={"app": "ingress"}
            )
            st.rerun()
        else:
            write_log(
                "login_failure",
                username=username,
                details={"app": "ingress"},
                severity="warning"
            )
            st.error("Invalid username or password")


# =============================================================================
# MAIN APPLICATION (FR-ING-013)
# =============================================================================

else:
    st.title("Secure File Transfer System")
    st.subheader("Ingress App - File Transfer")
    st.write(f"Welcome, {st.session_state.username}!")

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

    # Load valid recipients from users.json
    all_users = load_users()
    valid_recipients = [u for u in all_users.keys() if u != st.session_state.username]

    # =============================================================================
    # TRANSFER FORM
    # For this PoC, transfers a fixed test.txt file.
    # Full file upload functionality available in the full version.
    # =============================================================================

    st.info("PoC Mode: This version transfers a fixed test.txt file located in the same folder as the application.")

    recipient = st.selectbox("Select Recipient", valid_recipients)

    # Optional metadata fields (FR-ING-005)
    description = st.text_area("File Description / Purpose")
    classification = st.selectbox("Classification Level", [
        "Unclassified",
        "Internal Use Only",
        "Confidential",
        "Secret",
        "Top Secret"
    ])
    handling_instructions = st.text_area("Handling Instructions")
    priority = st.selectbox("Priority", ["Low", "Normal", "High"])

    if st.button("Transfer File"):
        # Check that test.txt exists
        if not os.path.exists(TEST_FILE_PATH):
            st.error(f"test.txt not found in {SCRIPT_DIR}. Please place test.txt in the same folder as the application.")
        else:
            # -----------------------------------------------------------------
            # STEP 1: Sanitize inputs (NFR-REL-002)
            # -----------------------------------------------------------------
            safe_description = sanitize_input(description)
            safe_handling = sanitize_input(handling_instructions)

            # -----------------------------------------------------------------
            # STEP 2: Generate UUID for this transfer (FR-ING-008)
            # -----------------------------------------------------------------
            file_id = str(uuid.uuid4())

            # -----------------------------------------------------------------
            # STEP 3: Create staging folder structure (FR-ING-009)
            # Structure: /staging/{UUID}/
            # Staging path is passed as command line argument to avoid
            # hardcoding — can point to real staging location
            # -----------------------------------------------------------------
            folder_path = os.path.join(STAGING_PATH, file_id)
            os.makedirs(folder_path)

            # -----------------------------------------------------------------
            # STEP 4: Copy test.txt into the UUID subfolder
            # shutil.copy2 preserves file metadata during copy
            # -----------------------------------------------------------------
            dest_file_path = os.path.join(folder_path, "test.txt")
            shutil.copy2(TEST_FILE_PATH, dest_file_path)

            # -----------------------------------------------------------------
            # STEP 5: Calculate SHA-256 hash for integrity verification
            # (FR-ING-011, NFR-SEC-005)
            # -----------------------------------------------------------------
            sha256 = hashlib.sha256()
            with open(dest_file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256.update(chunk)
            file_hash = sha256.hexdigest()

            # -----------------------------------------------------------------
            # STEP 6: Write metadata.json (FR-ING-008, FR-ING-010)
            # -----------------------------------------------------------------
            metadata = {
                "file_id": file_id,
                "submitter": st.session_state.username,
                "recipient": recipient,
                "original_filename": "test.txt",
                "submission_timestamp": datetime.now(timezone.utc).isoformat(),
                "file_size_bytes": os.path.getsize(dest_file_path),
                "file_hash_sha256": file_hash,
                "description": safe_description,
                "classification": classification,
                "handling_instructions": safe_handling,
                "priority": priority,
                "custom_fields": {}
            }

            metadata_path = os.path.join(folder_path, "metadata.json")
            with open(metadata_path, "w") as f:
                json.dump(metadata, f, indent=4)

            # -----------------------------------------------------------------
            # STEP 7: Show confirmation and log the event
            # (FR-ING-007, FR-ING-015)
            # -----------------------------------------------------------------
            st.success(f"File transferred successfully! Tracking ID: {file_id}")
            st.info(f"File saved to: {folder_path}")
            write_log(
                "file_transfer",
                username=st.session_state.username,
                details={
                    "file_id": file_id,
                    "filename": "test.txt",
                    "recipient": recipient,
                    "staging_path": folder_path,
                    "priority": priority
                }
            )
