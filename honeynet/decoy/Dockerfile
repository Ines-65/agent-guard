FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY fakefs.py shell.py decoy.py ./
EXPOSE 22
CMD ["python", "decoy.py"]
