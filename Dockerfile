# Use official Python base image
FROM python:3.11-slim

# Set working directory inside the container
WORKDIR /app

# Environment variables
ENV APP_SECRET_KEY=change_this_to_a_random_secret_key
ENV APP_DEBUG=false
ENV STAGING_PATH=staging
ENV INBOX_PATH=inbox
ENV SESSION_TIMEOUT=1800
ENV PASSWORD_MIN_LENGTH=12
ENV MAX_LOGIN_ATTEMPTS=5
ENV INBOX_SCAN_INTERVAL=300
ENV LOG_RETENTION_DAYS=90

# Copy requirements file first (for Docker layer caching)
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy all application files
COPY egress_app.py .
COPY audit_log.py .
COPY users.json .

# Create inbox folder
RUN mkdir -p inbox

# Expose the port Streamlit runs on
EXPOSE 8502

# Run the Egress app
CMD ["streamlit", "run", "egress_app.py", "--server.address", "0.0.0.0", "--server.port", "8502"]
