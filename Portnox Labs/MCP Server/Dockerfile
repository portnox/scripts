FROM python:3.12-alpine AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    VIRTUAL_ENV=/opt/venv

WORKDIR /app

RUN python -m venv "$VIRTUAL_ENV"
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

RUN apk add --no-cache ca-certificates openssl

COPY requirements-portnox-mcp.txt /app/requirements-portnox-mcp.txt
RUN python -m pip install --upgrade pip \
    && python -m pip install -r /app/requirements-portnox-mcp.txt \
    && rm -f "$VIRTUAL_ENV"/bin/pip "$VIRTUAL_ENV"/bin/pip3 "$VIRTUAL_ENV"/bin/pip3.12 \
    && find "$VIRTUAL_ENV"/lib -path '*/site-packages/pip*' -exec rm -rf {} + \
    && find "$VIRTUAL_ENV"/lib -path '*/site-packages/setuptools*' -exec rm -rf {} +

FROM python:3.12-alpine

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:$PATH"

WORKDIR /app

RUN apk add --no-cache ca-certificates openssl

RUN rm -f /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.12 \
    && find /usr/local/lib -path '*/site-packages/pip*' -exec rm -rf {} + \
    && find /usr/local/lib -path '*/site-packages/setuptools*' -exec rm -rf {} + \
    && find /usr/local/lib -path '*/ensurepip*' -exec rm -rf {} +

COPY --from=builder /opt/venv /opt/venv

COPY ["MCP Server.py", "/app/server.py"]

RUN addgroup -S mcp \
    && adduser -S -D -h /home/mcp -G mcp -s /bin/false mcp \
    && chown -R mcp:mcp /app

USER mcp

EXPOSE 8765

CMD ["python", "/app/server.py", "--transport", "streamable-http", "--host", "0.0.0.0", "--port", "8765"]
