FROM python:3.12.4-alpine

# Create a non-root user and group
RUN addgroup -S palamute && adduser -S haro -G palamute

WORKDIR /app
# Ensure the working directory has the correct permissions
RUN chown haro:palamute /app

# Install openssl, required for certificate generation
RUN apk upgrade --update-cache --available && \
    apk add openssl && \
    rm -rf /var/cache/apk/*

# Switch to non-root user
USER haro

# Install requirements
COPY ./app/requirements.txt requirements.txt
RUN pip install --user -r requirements.txt

# Copy the main entrypoint
COPY ./app/main.py main.py

ENTRYPOINT ["python", "main.py"]