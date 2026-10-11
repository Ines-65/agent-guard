FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY canaries.py seed.py accounts.json ./
COPY templates ./templates
CMD ["python", "seed.py"]
