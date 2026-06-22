# =============================================================================
# SECURE FILE TRANSFER SYSTEM - EGRESS APP
# =============================================================================
# Purpose: Web application running on the disconnected network (high side).
#          Allows authenticated users to view and download files intended
#          for them. Files are read from the inbox folder which receives
#          transfers from the data diode.
#
# Spec Reference: Section 3.3 - Egress WebApp (Disconnected Network)
# =============================================================================

import streamlit as st      # Web application framework
import os                   # File system operations
import json                 # Reading JSON metadata files
import hashlib              # SHA-256 hash verification
import bcrypt               # Secure password hashing
from audit_log import write_log          # Audit logging module
from dotenv import load_dotenv           # Environment variable loading

# Load environment variables from .env file
# Keeps sensitive configuration out of the code (NFR-MAINT-002)
load_dotenv()

# =============================================================================
# CONFIGURATION
# INBOX_PATH: folder where files arrive from the data diode (FR-XFER-003)
# In production this is mounted to the data diode destination
# =============================================================================
STAGING_PATH = os.getenv("STAGING_PATH", "staging")
INBOX_PATH = os.getenv("INBOX_PATH", "inbox")
MAX_LOGIN_ATTEMPTS = int(os.getenv("MAX_LOGIN_ATTEMPTS", 5))
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
USERS_FILE = os.path.join(SCRIPT_DIR, "users.json")

# Create inbox folder automatically on startup if it doesn't exist
# Prevents crashes on first run (NFR-REL-001)
os.makedirs(INBOX_PATH, exist_ok=True)
os.makedirs(STAGING_PATH, exist_ok=True)

# =============================================================================
# USER MANAGEMENT FUNCTIONS
# Independent user database from Ingress app (FR-EGR-001)
# Same password security requirements as Ingress (NFR-SEC-001)
# =============================================================================

def load_users():
    """
    Loads the user database from users.json.
    Contains usernames mapped to bcrypt password hashes.
    Managed by the create_users.py admin script.

    Returns:
        Dictionary of {username: password_hash}
    """
    with open(USERS_FILE, "r") as f:
        return json.load(f)


def check_login(username, password):
    """
    Verifies username and password against stored bcrypt hashes.
    bcrypt is used because it is deliberately slow, making brute
    force attacks computationally expensive. (NFR-SEC-001)

    Args:
        username: The username entered by the user
        password: The plain text password entered by the user

    Returns:
        True if credentials are valid, False otherwise
    """
    users = load_users()
    # Return False immediately if username doesn't exist
    # Prevents username enumeration attacks
    if username not in users:
        return False
    stored_hash = users[username].encode()
    return bcrypt.checkpw(password.encode(), stored_hash)


# =============================================================================
# FILE INTEGRITY VERIFICATION
# Recalculates SHA-256 hash of received file and compares to the hash
# stored in metadata.json by the Ingress app. (FR-EGR-004, NFR-SEC-005)
# Any corruption or tampering during data diode transfer will be detected.
# =============================================================================

def verify_hash(file_path, expected_hash):
    """
    Calculates the SHA-256 hash of a file and compares it to the
    expected hash stored in metadata.json.

    Args:
        file_path: Path to the file to verify
        expected_hash: SHA-256 hash string from metadata.json

    Returns:
        True if hashes match (file is intact), False if corrupted/tampered
    """
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        # Read in 4096-byte chunks to handle large files efficiently
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest() == expected_hash


# =============================================================================
# INBOX FOLDER SCANNER
# Scans the inbox folder for files intended for the logged-in user.
# The inbox folder receives files transferred via the data diode.
# (FR-EGR-003, FR-EGR-004)
# =============================================================================

def scan_inbox_folder(username, inbox_path="inbox"):
    """
    Scans the inbox folder for UUID subfolders containing metadata.json files.
    Filters files where the recipient matches the logged-in user.
    Verifies file integrity via SHA-256 hash comparison.

    Args:
        username: The logged-in user's username
        inbox_path: Path to the inbox folder (configurable via .env)

    Returns:
        List of file dictionaries available for this user
    """
    available_files = []

    # Return empty list if inbox folder doesn't exist yet
    if not os.path.exists(inbox_path):
        os.makedirs(inbox_path)
        return available_files

    # Loop through each UUID subfolder in the inbox
    for folder_name in os.listdir(inbox_path):
        folder_path = os.path.join(inbox_path, folder_name)
        metadata_path = os.path.join(folder_path, "metadata.json")

        # Skip folders that don't contain a metadata.json file
        if os.path.exists(metadata_path):
            with open(metadata_path, "r") as f:
                metadata = json.load(f)

            # Only include files where recipient matches logged-in user
            # This ensures users can only see their own files (FR-EGR-002)
            if metadata.get("recipient") == username:
                file_path = os.path.join(folder_path, metadata["original_filename"])

                # Only include files that actually exist on disk
                if os.path.exists(file_path):
                    # Verify file integrity before making available
                    hash_valid = verify_hash(
                        file_path,
                        metadata.get("file_hash_sha256", "")
                    )

                    available_files.append({
                        "file_id": metadata["file_id"],
                        "filename": metadata["original_filename"],
                        "submitter": metadata.get("submitter", "Unknown"),
                        "file_size": metadata["file_size_bytes"],
                        "hash_valid": hash_valid,
                        "file_path": file_path,
                        "timestamp": metadata.get("submission_timestamp", "Unknown"),
                        "description": metadata.get("description", ""),
                        "classification": metadata.get("classification", ""),
                        "priority": metadata.get("priority", "Normal"),
                    })

    return available_files


# =============================================================================
# SESSION STATE INITIALIZATION
# Streamlit reruns the entire script on every interaction so we use
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
# Shown when the user is not authenticated. (FR-EGR-001, FR-EG-008)
# =============================================================================

if not st.session_state.logged_in:
    st.title("Secure File Transfer System")
    st.subheader("Egress App - File Pickup")
    st.subheader("Login")

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if check_login(username, password):
            # Successful login - update session and log the event
            st.session_state.logged_in = True
            st.session_state.username = username
            write_log(
                "login_success",
                username=username,
                details={"app": "egress"}
            )
            st.rerun()
        else:
            # Failed login - log for security monitoring (FR-EGR-010)
            # Helps detect brute force attacks (Section 8.1)
            write_log(
                "login_failure",
                username=username,
                details={"app": "egress"},
                severity="warning"
            )
            st.error("Invalid username or password")


# =============================================================================
# MAIN APPLICATION
# Shown only when the user is authenticated. (FR-EG-008)
# =============================================================================

else:
    st.title("Secure File Transfer System")
    st.subheader("Egress App - File Pickup")
    st.write(f"Welcome, {st.session_state.username}!")

    # Logout button - clears session state and logs the event
    if st.button("Logout"):
        write_log(
            "logout",
            username=st.session_state.username,
            details={"app": "egress"}
        )
        st.session_state.logged_in = False
        st.session_state.username = ""
        st.rerun()

    st.divider()
    st.subheader("Your Files")

    # Scan inbox folder for files belonging to the logged-in user
    # inbox_path is loaded from environment variables (NFR-MAINT-002)
    files = scan_inbox_folder(st.session_state.username, inbox_path=INBOX_PATH)

    if not files:
        st.info("No files available for you yet.")
    else:
        # Display each file in an expandable section
        for file in files:
            with st.expander(f"{file['filename']} — from {file['submitter']}"):

                # Display file metadata (FR-EGR-006)
                st.write(f"**File ID:** {file['file_id']}")
                st.write(f"**Submitted:** {file['timestamp']}")
                st.write(f"**Size:** {file['file_size']} bytes")
                st.write(f"**Priority:** {file['priority']}")

                if file['description']:
                    st.write(f"**Description:** {file['description']}")
                if file['classification']:
                    st.write(f"**Classification:** {file['classification']}")

                # Show integrity verification result (FR-EGR-004, NFR-SEC-005)
                # This confirms the file was not corrupted or tampered with
                # during the data diode transfer process
                if file['hash_valid']:
                    st.success("✓ File integrity verified - SHA-256 hash matches")
                else:
                    st.error("✗ File integrity check FAILED - file may be corrupted or tampered with")

                # Download button - file is only served if integrity check passed
                with open(file['file_path'], "rb") as f:
                    downloaded = st.download_button(
                        label="Download File",
                        data=f,
                        file_name=file['filename'],
			key=file['file_id']
                    )

                # Log the download event (FR-EGR-010)
                if downloaded:
                    write_log(
                        "file_download",
                        username=st.session_state.username,
                        details={
                            "file_id": file['file_id'],
                            "filename": file['filename'],
                            "submitter": file['submitter'],
                            "app": "egress"
                        }
                    )