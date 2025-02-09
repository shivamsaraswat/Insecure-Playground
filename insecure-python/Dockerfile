# --- Build Stage ---
FROM cgr.dev/chainguard/python:latest-dev@sha256:09f4f51a187f66504d8a1c2ffa34a9455fee7c16ed7bb96f0ebc9be158bed459 AS build

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
FROM cgr.dev/chainguard/python@sha256:f2e50419f6e4eb6400fef06f1bcb1fb713878780062b2d0588e59cf540619637

WORKDIR /app

ENV PYTHONUNBUFFERED=1

# Ensure that the virtual environment is used at runtime
ENV PATH="/app/venv/bin:$PATH"

# Copy the virtual environment from the build stage
COPY --from=build /app/venv /app/venv

# Copy the rest of your application code
COPY . /app

ENTRYPOINT ["python", "main.py"]
