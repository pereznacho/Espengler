#!/bin/bash

echo "🔧 Aplicando migraciones..."
python manage.py migrate

echo "📦 Recolectando archivos estáticos..."
python manage.py collectstatic --noinput

echo "🚀 Iniciando servidor Django..."
exec python manage.py runserver 0.0.0.0:8000
