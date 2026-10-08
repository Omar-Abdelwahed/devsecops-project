# Hardened image: maintained slim base, non-root user, minimal context (.dockerignore), healthcheck.
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /code
RUN useradd --system --uid 10001 --no-create-home appuser && chown appuser /code
COPY requirements.txt .
# Install pinned dependencies, then remove pip: it is not needed at runtime and its
# vendored libraries (urllib3, msgpack, setuptools) carry HIGH CVEs flagged by Trivy.
RUN pip install --no-cache-dir -r requirements.txt \
    && pip uninstall -y pip
COPY app/ ./app/
USER 10001
EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=3s \
  CMD ["python", "-c", "import urllib.request as u; u.urlopen('http://localhost:5000/health')"]
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "app.app:app"]
