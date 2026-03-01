FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /workspace

# minimal OS deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    ca-certificates \
    wget \
    curl \
 && rm -rf /var/lib/apt/lists/*

# Copy package manifest and source so pip install -e . can find src/
COPY pyproject.toml requirements.txt ./
COPY src/ ./src/

# Install python deps (src/ must exist for setuptools packages.find where = ["src"])
RUN pip install --upgrade pip && \
    if [ -f pyproject.toml ]; then pip install -e .; else pip install -r requirements.txt; fi

# Copy rest of code
COPY scripts/ ./scripts/
COPY configs/ ./configs/
COPY assets/ ./assets/
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Create mount points
RUN mkdir -p /workspace/data /workspace/runs

ENTRYPOINT ["/entrypoint.sh"]
CMD ["bash"]
