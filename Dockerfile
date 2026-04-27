FROM python:3.12-slim

LABEL org.opencontainers.image.title="threat-research-mcp" \
      org.opencontainers.image.description="Deterministic threat intel → hunt → detection MCP server" \
      org.opencontainers.image.source="https://github.com/harshthakur6293/threat-research-mcp"

WORKDIR /app

# Install only runtime deps first (cache layer)
COPY pyproject.toml README.md ./
COPY src/ ./src/
COPY playbook/ ./playbook/

RUN pip install --no-cache-dir -e . && \
    pip install --no-cache-dir "mcp>=1.8.0"

# Non-root user for security
RUN useradd -m -u 1000 analyst
USER analyst

EXPOSE 8000

ENV THREAT_MCP_OFFLINE=false
ENV PYTHONUNBUFFERED=1

CMD ["python", "-m", "threat_research_mcp"]
