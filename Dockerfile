FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive

# Instalación de dependencias del sistema necesarias para Puppeteer, Pillow, etc.
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    libmagic1 \
    curl \
    gnupg \
    libjpeg-dev \
    zlib1g-dev \
    libpng-dev \
    libxslt1-dev \
    libxml2-dev \
    libglib2.0-0 \
    fonts-liberation \
    libnss3 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libxss1 \
    libasound2 \
    libxshmfence-dev \
    libgbm-dev \
    ca-certificates \
    chromium \
    && rm -rf /var/lib/apt/lists/*

# Instala Node.js (versión estable actual o LTS)
RUN apt-get update && apt-get install -y curl gnupg && \
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash - && \
    apt-get install -y nodejs && \
    apt-get clean

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt    

RUN apt-get update && apt-get install -y locales && \
    echo "en_US.UTF-8 UTF-8" > /etc/locale.gen && \
    echo "es_ES.UTF-8 UTF-8" >> /etc/locale.gen && \
    locale-gen && \
    update-locale LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8

ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8



ENV PATH="/usr/lib/chromium:${PATH}"

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

# Generar automáticamente una SECRET_KEY segura si no viene del exterior
ENV DJANGO_SECRET_KEY="${DJANGO_SECRET_KEY:-$(python3 -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())')}"


# Copiar el entrypoint con permisos correctos
COPY entrypoint.sh /app/entrypoint.sh

# Ejecutar usando bash para evitar problemas de permisos
ENTRYPOINT ["bash", "/app/entrypoint.sh"]

# Copiar el resto del proyecto
COPY . .
