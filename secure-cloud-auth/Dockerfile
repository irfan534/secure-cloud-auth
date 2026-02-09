FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Expose port
EXPOSE 5000

# Initialize DB on first run, then start with gunicorn
ENV FLASK_APP=app.py
ENV PYTHONUNBUFFERED=1

CMD ["sh", "-c", "python -c \"from app import app, init_db; app.app_context().push(); init_db()\" 2>/dev/null || true && exec gunicorn -w 4 -b 0.0.0.0:5000 app:app"]
