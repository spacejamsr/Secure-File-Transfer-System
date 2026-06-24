# Use official Python base image
FROM python:3.11-slim

# Set working directory inside the container
WORKDIR /app

# Environment variables
ENV INBOX_PATH=inbox
ENV MAX_LOGIN_ATTEMPTS=5
ENV SESSION_TIMEOUT=1800
ENV LOG_RETENTION_DAYS=90
ENV INBOX_SCAN_INTERVAL=300

# Copy requirements file first (for Docker layer caching)
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy all application files
COPY egress_app.py .
COPY audit_log.py .


# Create inbox folder
RUN mkdir -p inbox



# Expose the port Streamlit runs on
EXPOSE 8502

# Run the Egress app
CMD ["streamlit", "run", "egress_app.py", "--server.address", "0.0.0.0", "--server.port", "8502"]
