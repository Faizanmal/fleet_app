FROM python:3.12-slim AS build
ENV VIRTUAL_ENV=/opt/venv PATH="/opt/venv/bin:$PATH" PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
RUN python -m venv "$VIRTUAL_ENV"
COPY pyproject.toml README.md ./
COPY apps/api/src ./apps/api/src
RUN pip install --no-cache-dir ".[observability]"

FROM python:3.12-slim AS runtime
ENV VIRTUAL_ENV=/opt/venv PATH="/opt/venv/bin:$PATH" PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
RUN groupadd --system --gid 10001 fleet && useradd --system --uid 10001 --gid fleet --home-dir /app fleet \
    && mkdir -p /app/reports && chown fleet:fleet /app/reports
COPY --from=build /opt/venv /opt/venv
COPY apps/api/src ./apps/api/src
COPY apps/api/alembic.ini ./apps/api/alembic.ini
COPY apps/api/migrations ./apps/api/migrations
USER fleet
EXPOSE 8000
HEALTHCHECK --interval=20s --timeout=5s --start-period=30s --retries=3 CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/v1/ready', timeout=3)"]
CMD ["uvicorn", "fleet.api.main:app", "--app-dir", "apps/api/src", "--host", "0.0.0.0", "--port", "8000"]
