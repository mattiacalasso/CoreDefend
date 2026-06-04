# CoreDefend - Automated Vulnerability Scanner
# Docker Container

FROM python:3.12-slim

# Metadata
LABEL maintainer="CoreDefend Security Team"
LABEL description="Automated Vulnerability Scanner with Nmap and Streamlit"
LABEL version="1.0"

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV STREAMLIT_SERVER_PORT=8501
ENV STREAMLIT_SERVER_ADDRESS=0.0.0.0

# Install system dependencies and Nmap
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    libcap2-bin \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash scanner

# Set working directory
WORKDIR /app

# Copy requirements first (for Docker cache optimization)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY scanner.py .
COPY analyzer.py .
COPY reporter.py .
COPY app.py .

# Grant Nmap capabilities for non-root scanning
# This allows SYN scans and OS detection without full root
RUN setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)

# Change ownership to scanner user
RUN chown -R scanner:scanner /app

# Switch to non-root user
USER scanner

# Expose Streamlit port
EXPOSE 8501

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl --fail http://localhost:8501/_stcore/health || exit 1

# Run Streamlit
CMD ["streamlit", "run", "app.py", "--server.headless=true"]
