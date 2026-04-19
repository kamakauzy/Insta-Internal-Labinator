# Insta-Internal-Labinator — Dashboard Container
# INTERNAL ONLY. Never ships to clients.
#
# NOTE: vmrun.exe is a Windows PE binary. When running as a Linux container
# on Docker Desktop (Windows), vmrun calls will fail unless you run a
# host-side vmrun proxy (see scripts/vmrun-proxy.ps1) and set
# VMRUN_PROXY_URL=http://host.docker.internal:9876
# Alternatively, run natively with: python -m dashboard (run.ps1)

FROM python:3.12-slim

WORKDIR /app

# System packages needed for health checks and network ops
RUN apt-get update && apt-get install -y --no-install-recommends \
        iputils-ping \
        curl \
        nmap \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY dashboard/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY dashboard/ ./dashboard/

# Expose dashboard port
EXPOSE 8445

# Run the dashboard on port 8445
CMD ["python", "-m", "uvicorn", "dashboard.main:app", "--host", "0.0.0.0", "--port", "8445"]
