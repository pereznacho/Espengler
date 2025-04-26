Desarrollado para facilitar y acelerar la generación de reportes profesionales de pentesting.
# Espengler

Espengler es una herramienta profesional para la **generación automatizada de reportes de seguridad ofensiva**. Permite gestionar proyectos de auditoría, documentar vulnerabilidades, adjuntar evidencias, visualizar rutas de ataque y exportar reportes personalizados en español o inglés.

## Características principales

- **Gestión de proyectos y objetivos:** Organiza múltiples auditorías, define sus objetivos y haz seguimiento de su estado.
- **Documentación de vulnerabilidades:** Registra cada hallazgo con descripciones, soluciones, referencias y permite adjuntar imágenes como evidencias mediante los Writeups.
- **Soporte multilenguaje:** Genera reportes en **español** o **inglés**. El idioma se selecciona al crear o configurar cada proyecto.
- **Visualización de rutas de ataque:** Incluye un Attack Graph interactivo que ayuda a visualizar las cadenas de explotación.
- **Generación profesional de reportes:** Exporta reportes automatizados en formato `.docx` con toda la información del proyecto, vulnerabilidades y evidencias.
- **Plantillas personalizables:** Modifica portadas y estructura de los reportes según tus necesidades.
- **Adjunto de evidencias:** Los Writeups permiten agregar imágenes para evidenciar hallazgos.
- **Backup y restauración:** Funcionalidad para respaldar y recuperar proyectos completos.

## Instalación

Clona el repositorio y configura el entorno virtual en la raíz:

```bash
git clone <URL-del-repositorio>
cd VulnerabilityManager
python -m venv ../venv
source ../venv/bin/activate
pip install -r requirements.txt
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
```

> **Nota:** Node.js solo es necesario si planeas generar imágenes automáticas del Attack Graph con GraphMap.

---

## Instalación alternativa usando Docker

Si prefieres no configurar el entorno manualmente, puedes utilizar Docker para levantar todo automáticamente:

1. Construye la imagen de Docker:

```bash
docker build -t espengler .
```

2. Ejecuta el contenedor:

```bash
docker run -d -p 8000:8000 --name espengler_container espengler
```

3. Accede a la aplicación:

Visita [http://localhost:8000/](http://localhost:8000/) en tu navegador.

> **Importante:** El contenedor creará automáticamente un superusuario con usuario `Espengler` y contraseña `Demo2025$` que deberías cambiar por seguridad.

---

## Uso básico

1. **Inicia el servidor de Django:**
   ```bash
   python manage.py runserver
   ```
2. **Accede a la aplicación:**  
   Abre tu navegador y visita [http://localhost:8000/](http://localhost:8000/)
3. **Crea un nuevo proyecto:**  
   Desde el panel de administración, define nombre, fechas, idioma del reporte y plantillas de portada/contenido.
4. **Agrega objetivos (Targets):**  
   Registra los sistemas o IPs a auditar y su estado.
5. **Documenta vulnerabilidades:**  
   Asocia hallazgos a los objetivos, describe el impacto y adjunta evidencias en imágenes mediante los Writeups.
6. **Visualiza el mapa de ataques:**  
   Usa el Attack Graph para comprender rutas de explotación.
7. **Genera el reporte:**  
   Selecciona el idioma (español o inglés) y exporta el reporte `.docx` profesional con toda la información y evidencias.

## Requisitos

- Python 3.11.10
- Django 5.1.7
- Node.js (solo si se requiere generación de imágenes de GraphMap)
- Dependencias listadas en `requirements.txt`
- Crear cuenta en https://www.tiny.cloud para obtener una API KEY y pegarla en settings.py en TINYMCE_JS_URL = 'URL + API_KEY' (es gratis)

## Estructura principal del proyecto

- `VulnerabilityManager/`: Núcleo de gestión de proyectos, objetivos y vulnerabilidades.
- `attack_narrative/`: Redacción e importación de narrativas de ataque.
- `BackupRestore/`: Respaldo y restauración de proyectos.
- `templates/`: Plantillas HTML para administración y generación de reportes.
- `static/`: Archivos estáticos (CSS, imágenes, JS).

## Contribuciones

¡Las contribuciones son bienvenidas!  
Crea un fork del repositorio, desarrolla tus mejoras en una rama y abre un pull request detallando los cambios propuestos.

## Licencia

Espengler se distribuye bajo la licencia MIT.

---

Desarrollado para facilitar y acelerar la generación profesional de reportes de seguridad ofensiva.