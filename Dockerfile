# vulnerable-javascript as a container: the same static files and serve.py,
# for running the demo offline or on a machine without the hosted copy.
#
#   docker run --rm -p 127.0.0.1:8000:8000 ghcr.io/eyalsec/vulnerable-javascript
#
# The app is deliberately insecure. Publish the port on 127.0.0.1 only, as
# above, and never serve it from a domain you care about.
FROM python:3.13-slim@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f

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
