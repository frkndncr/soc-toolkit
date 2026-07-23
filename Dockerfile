FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml requirements.txt README.md /app/
COPY soc_toolkit /app/soc_toolkit/

RUN pip install --no-cache-dir .

EXPOSE 8000 8080

CMD ["python", "-m", "soc_toolkit.cli", "server", "--port", "8000"]
