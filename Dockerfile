# vulnerable-javascript as a container: the same static files and serve.py,
# for running the demo offline or on a machine without the hosted copy.
#
#   docker run --rm -p 127.0.0.1:8000:8000 ghcr.io/eyalsec/vulnerable-javascript
#
# The app is deliberately insecure. Publish the port on 127.0.0.1 only, as
# above, and never serve it from a domain you care about.
FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928

WORKDIR /app
COPY . .
RUN useradd --create-home --uid 10001 demo
USER demo

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/', timeout=2)" || exit 1

# Inside the container serve.py has to listen on all interfaces for a
# published port to reach it; the -p 127.0.0.1:... above keeps it on your machine.
CMD ["python", "serve.py", "8000", "0.0.0.0"]
