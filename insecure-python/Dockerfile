# --- Build Stage ---
FROM cgr.dev/chainguard/python:latest-dev@sha256:0ba7c37037fc1669dd600e3e5348ab0774fc07e504c714cb14bde02708d3290a AS build

ENV LANG=C.UTF-8
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Create a virtual environment in /app/venv
RUN python -m venv venv

# Update PATH so that subsequent commands use the virtual environment’s binaries
ENV PATH="/app/venv/bin:$PATH"

# Install application dependencies
COPY requirements.txt .
RUN pip install --upgrade pip && pip install --no-cache-dir -r requirements.txt

# --- Final Stage ---
FROM cgr.dev/chainguard/python:latest

WORKDIR /app

ENV PYTHONUNBUFFERED=1

# Ensure that the virtual environment is used at runtime
ENV PATH="/app/venv/bin:$PATH"

# Copy the virtual environment from the build stage
COPY --from=build /app/venv /app/venv

# Copy the rest of your application code
COPY . /app

ENTRYPOINT ["python", "main.py"]
