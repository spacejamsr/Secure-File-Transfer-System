# Use official Python base image
FROM python:3.11-slim

# Set working directory inside the container
WORKDIR /app

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
