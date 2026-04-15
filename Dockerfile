# Use Python 3.11 as base image
FROM python:3.11-slim

# Set working directory in container
WORKDIR /app

# Install system dependencies required for your app
RUN apt-get update && apt-get install -y \
    tesseract-ocr \
    tesseract-ocr-eng \
    tesseract-ocr-hin \
    tesseract-ocr-ben \
    tesseract-ocr-mar \
    libgl1-mesa-glx \
    libglib2.0-0 \
    libsm6 \
    libxext6 \
    libxrender-dev \
    libgomp1 \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Verify Tesseract installation
RUN tesseract --version && \
    tesseract --list-langs

# Copy requirements file first (for better caching)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire project
COPY . .

# Create necessary directories
RUN mkdir -p static/uploads static/languages

# Expose the port your app runs on
EXPOSE 8000

# Command to run the application
CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:8000"]