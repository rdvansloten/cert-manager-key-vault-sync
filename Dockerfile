FROM python:3.13-alpine3.21 AS builder

# Create a non-root user and group
RUN addgroup -S corgis && adduser -S haro -G corgis

WORKDIR /app
# Ensure the working directory has the correct permissions
RUN chown haro:corgis /app

# Install openssl and build dependencies as root
RUN apk upgrade --update-cache --available && \
    apk add --no-cache openssl uv cargo gcc libc-dev openssl-dev libffi-dev && \
    rm -rf /var/cache/apk/*

# Switch to non-root user for the remaining steps
USER haro

# Install Python requirements as the non-root user
COPY ./app/requirements.txt requirements.txt
RUN uv pip install --system --requirements requirements.txt

# Revert to root to remove build dependencies
USER root
RUN apk del cargo gcc libc-dev libffi-dev && \
    rm -rf /var/cache/apk/*

# Copy the installed packages to a final image
FROM python:3.13-alpine3.21

# Install openssl, required for certificate generation
RUN apk upgrade --update-cache --available && \
    apk add openssl && \
    rm -rf /var/cache/apk/*

# Create a non-root user and group in the final image
RUN addgroup -S corgis && adduser -S haro -G corgis

WORKDIR /app
RUN chown haro:corgis /app

# Copy the installed dependencies from the builder stage
COPY --from=builder /home/haro/.local /home/haro/.local

# Copy the main entrypoint
COPY ./app/main.py main.py

# Switch to non-root user for execution
USER haro

ENTRYPOINT ["python", "main.py"]
