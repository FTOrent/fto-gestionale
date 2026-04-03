FROM python:3.11-slim

WORKDIR /app

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

ARG CACHE_BUST=1
COPY . .

CMD ["python", "start.py"]
 
