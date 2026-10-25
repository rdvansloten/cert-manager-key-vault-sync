FROM python:3.15.1-alpine3.24@sha256:54448f67d7c31c39e5cdd3ea2d6382395ce142806c284425f8e897d78a0465b3 AS builder

# Create a non-root user and group
RUN addgroup -S corgis && adduser -S haro -G corgis

WORKDIR /app
# Ensure the working directory has the correct permissions
RUN chown haro:corgis /app

COPY --from=ghcr.io/astral-sh/uv:0.13.5@sha256:32a7bb39b496babbd997b0a39a4d66c126bdaf5661b302bf6f06abda8deca6ff /uv /usr/local/bin/uv

# Switch to non-root user for the remaining steps
USER haro

# Install Python requirements as the non-root user
COPY ./app/requirements.txt ./app/build-constraints.txt ./
RUN uv venv --python=python3.15 /home/haro/.venv && \
    source /home/haro/.venv/bin/activate && \
    uv pip install --require-hashes --build-constraints build-constraints.txt --requirements requirements.txt

# Copy the installed packages to a final image
FROM python:3.15.1-alpine3.24@sha256:54448f67d7c31c39e5cdd3ea2d6382395ce142806c284425f8e897d78a0465b3

# Install openssl, required for certificate generation, and remove the unused system pip
RUN apk add --no-cache openssl=3.5.9-r0 && \
    python -m pip uninstall --yes --root-user-action=ignore pip

# Create a non-root user and group in the final image
RUN addgroup -S corgis && adduser -S haro -G corgis

WORKDIR /app
RUN chown haro:corgis /app

# Copy the installed dependencies from the builder stage
COPY --from=builder /home/haro/.venv /home/haro/.venv

# Copy the main entrypoint
COPY ./app/main.py main.py

# Switch to non-root user for execution
USER haro

RUN source /home/haro/.venv/bin/activate

ENTRYPOINT ["/home/haro/.venv/bin/python", "main.py"]

