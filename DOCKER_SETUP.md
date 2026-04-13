# Docker Setup for AgriGuard (Optional)

This guide describes how to run AgriGuard inside Docker so your friend does not need to install MySQL and Tesseract separately.

## 1. Prerequisites
- Docker Desktop installed
- GitHub repo cloned or downloaded locally

## 2. Dockerfile example
Create a file named `Dockerfile` in the repository root with:
```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir -r requirements.txt

COPY . /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    tesseract-ocr \
    libgl1-mesa-glx \
    && rm -rf /var/lib/apt/lists/*

EXPOSE 5000

CMD ["python", "app.py"]
```

## 3. Build the Docker image
```bash
docker build -t agriguard .
```

## 4. Run the Docker container
```bash
docker run -it --rm -p 5000:5000 agriguard
```

## 5. Access the app
Open your browser at:

`http://127.0.0.1:5000/admin`

## 6. Notes
- Model files must be present in `models/` inside the repo.
- This container uses the internal SQLite database and should be fine for local testing.
- If you want MySQL in Docker too, add a separate `docker-compose.yml` with a MySQL service.

## Troubleshooting
- If Tesseract errors appear, confirm the container installed `tesseract-ocr` successfully.
- If the app cannot connect to MySQL, the Docker container must use local MySQL or a separate MySQL container.
- If `models` files are missing, rebuild after adding them.
