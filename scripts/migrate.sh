#!/bin/sh
# Aplica las migraciones de Django. Ejecutar en el mismo entorno donde corre el servidor.
# Uso con Docker Compose: docker compose exec espengler_web python manage.py migrate
# Uso local: desde la raíz del proyecto con venv activado: python manage.py migrate
set -e
cd "$(dirname "$0")/.."
if command -v docker >/dev/null 2>&1 && docker compose ps -q espengler_web 2>/dev/null | head -1 | grep -q .; then
  docker compose exec espengler_web python manage.py migrate "$@"
else
  python manage.py migrate "$@"
fi
