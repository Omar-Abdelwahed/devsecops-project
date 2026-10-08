FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /code
RUN useradd --system --uid 10001 appuser && chown appuser /code
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ ./app/
USER appuser
EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=3s \
  CMD python -c "import urllib.request as u; u.urlopen('http://localhost:5000/health')"
CMD ["gunicorn", "-b", "0.0.0.0:5000", "app.app:app"]