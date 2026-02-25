FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive

# Liberar espacio en la imagen base para que apt no falle por disco lleno
RUN rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/* 2>/dev/null; \
    find /usr/share -type d -name doc -exec rm -rf {} + 2>/dev/null; \
    find /usr/share -type d -name man -exec rm -rf {} + 2>/dev/null; \
    find /usr/share -type d -name info -exec rm -rf {} + 2>/dev/null; true

# Usar /tmp como caché de apt (apt exige que exista el subdir partial)
RUN echo 'Dir::Cache::archives "/tmp/apt-archives";' > /etc/apt/apt.conf.d/99-docker-cache \
    && mkdir -p /tmp/apt-archives/partial

# Dependencias: varias tandas pequeñas + limpieza para no saturar disco
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libpq5 libpq-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/* && rm -f /tmp/apt-archives/*.deb
RUN apt-get update && apt-get install -y --no-install-recommends \
    libmagic1 curl gnupg \
    && apt-get clean && rm -rf /var/lib/apt/lists/* && rm -f /tmp/apt-archives/*.deb
RUN apt-get update && apt-get install -y --no-install-recommends \
    libjpeg-dev zlib1g-dev libpng-dev libffi-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/* && rm -f /tmp/apt-archives/*.deb
RUN apt-get update && apt-get install -y --no-install-recommends \
    libxslt1-dev libxml2-dev libglib2.0-0 fonts-liberation \
    && apt-get clean && rm -rf /var/lib/apt/lists/* && rm -f /tmp/apt-archives/*.deb
RUN apt-get update && apt-get install -y --no-install-recommends build-essential \
    && apt-get clean && rm -rf /var/lib/apt/lists/* && rm -f /tmp/apt-archives/*.deb
RUN apt-get update && apt-get install -y --no-install-recommends \
    libcairo2-dev libpango1.0-dev libgdk-pixbuf-2.0-dev \
    libnss3 libatk1.0-0 libatk-bridge2.0-0 libxss1 libasound2 \
    libxshmfence-dev libgbm-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/* && rm -f /tmp/apt-archives/*.deb

# Node.js (opcional, para scripts GraphMap)
RUN apt-get update && apt-get install -y --no-install-recommends curl gnupg && \
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash - && \
    apt-get install -y nodejs && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

RUN apt-get update && apt-get install -y --no-install-recommends locales && \
    echo "en_US.UTF-8 UTF-8" > /etc/locale.gen && \
    echo "es_ES.UTF-8 UTF-8" >> /etc/locale.gen && \
    locale-gen && \
    update-locale LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8 && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8

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
