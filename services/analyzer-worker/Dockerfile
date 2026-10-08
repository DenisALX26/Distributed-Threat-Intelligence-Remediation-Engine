FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

WORKDIR /app

COPY requirements.txt .

RUN uv pip install --system -r requirements.txt

COPY main.py mcp_server.py ./

ENV PYTHONUNBUFFERED=1

CMD ["python", "main.py"]