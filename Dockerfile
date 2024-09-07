FROM python:3.12.4-alpine

# Create a non-root user and group
RUN addgroup -S corgis && adduser -S haro -G corgis

WORKDIR /app
# Ensure the working directory has the correct permissions
RUN chown haro:corgis /app

# Install openssl and build dependencies
RUN apk upgrade --update-cache --available && \
    apk add --no-cache openssl cargo gcc libc-dev libffi-dev openssl-dev musl-dev && \
    rm -rf /var/cache/apk/*

# Switch to non-root user
USER haro

# Install requirements
COPY ./app/requirements.txt requirements.txt
RUN pip install --no-cache-dir --user -r requirements.txt && \
    apk del cargo gcc libc-dev libffi-dev musl-dev && \
    find ~/.local/ -name '*.pyc' -delete && \
    find ~/.local/ -name '*.pyo' -delete

# Copy the main entrypoint
COPY ./app/main.py main.py

ENTRYPOINT ["python", "main.py"]
