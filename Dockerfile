FROM python:3.9-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create data directory for GeoIP databases and logs
RUN mkdir -p /app/data

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV FLASK_APP=web_interface.py

# Expose port
EXPOSE 8080

# Create non-root user
RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser

# Run with Gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "1", "--timeout", "120", "web_interface:app"] 