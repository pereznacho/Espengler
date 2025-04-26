from django.db import models
from django_ckeditor_5.fields import CKEditor5Field
from django.utils.safestring import mark_safe
from markdown import markdown
import os
import requests
from bs4 import BeautifulSoup
from django.conf import settings


class Writeup(models.Model):
    title = models.CharField(max_length=255)

    # ✅ Almacena el contenido en formato Markdown
    content_markdown = models.TextField(blank=True, null=True)

    # ✅ CKEditor5Field para almacenar el HTML generado
    content_html = CKEditor5Field("Content HTML", config_name="default", blank=True, null=True)

    # ✅ Relación con el modelo de Proyecto
    project = models.ForeignKey(
        "ProjectManager.Project",
        on_delete=models.CASCADE,
        related_name="attack_narratives_attack_narrative",
        null=True,
        blank=True,
    )

    # ✅ Relación ManyToMany para tags
    tags = models.ManyToManyField("Tag", related_name="writeups", blank=True)

    # ✅ Fecha de creación automática
    created_at = models.DateTimeField(auto_now_add=True)

    def get_project_model():
        from ProjectManager.models import Project  # ✅ Importación dentro de la función para evitar circularidad
        return Project

    def save(self, *args, **kwargs):
        """Convierte Markdown a HTML y descarga imágenes externas al guardar"""
        if self.content_markdown:
            raw_html = markdown(
                self.content_markdown,
                extensions=[
                    "extra", "codehilite", "fenced_code",
                    "tables", "abbr", "sane_lists", "smarty", "nl2br"
                ]
            )
            self.content_html = mark_safe(raw_html)

        # Procesar imágenes externas en el HTML (ya sea desde Markdown o CKEditor)
        if self.content_html:
            soup = BeautifulSoup(self.content_html, "html.parser")
            for img in soup.find_all("img"):
                src = img.get("src", "")
                if src.startswith("http://") or src.startswith("https://"):
                    local_url = self.download_and_store_image(src)
                    img["src"] = local_url
            self.content_html = str(soup)

        super().save(*args, **kwargs)

    def download_and_store_image(self, url):
        """Descarga una imagen externa y la guarda como WriteupImage en /protected_media"""
        try:
            response = requests.get(url, stream=True, timeout=10)
            if response.status_code == 200:
                ext = os.path.splitext(url)[-1].split("?")[0] or ".jpg"
                filename = os.path.basename(url.split("/")[-1]).split("?")[0]

                writeup_folder = self.title.replace(" ", "_")
                local_dir = os.path.join(settings.PROTECTED_MEDIA_ROOT, writeup_folder)
                os.makedirs(local_dir, exist_ok=True)

                local_path = os.path.join(local_dir, filename)

                with open(local_path, "wb") as out_file:
                    out_file.write(response.content)

                relative_path = f'protected_media/{writeup_folder}/{filename}'
                WriteupImage.objects.create(writeup=self, image=relative_path)

                return f"/{relative_path}"  # Para que lo muestre en CKEditor y reporte
        except Exception as e:
            print(f"[ERROR] No se pudo descargar {url}: {e}")
        return url

    def __str__(self):
        return self.title


def writeup_image_path(instance, filename):
    """Define la ruta donde se guardarán las imágenes del writeup en protected_media/{writeup_name}/"""
    writeup_folder = instance.writeup.title.replace(" ", "_")
    return f'protected_media/{writeup_folder}/{filename}'


class WriteupImage(models.Model):
    writeup = models.ForeignKey('attack_narrative.Writeup', on_delete=models.CASCADE)
    image = models.ImageField(upload_to=writeup_image_path)

    def save(self, *args, **kwargs):
        """ Crea automáticamente el directorio en protected_media antes de guardar la imagen """
        writeup_folder = self.writeup.title.replace(" ", "_")
        protected_path = os.path.join(settings.PROTECTED_MEDIA_ROOT, writeup_folder)

        if not os.path.exists(protected_path):
            os.makedirs(protected_path)
            print(f"📂 Directorio creado: {protected_path}")

        super().save(*args, **kwargs)


class Tag(models.Model):
    """ Modelo para los tags de los writeups """
    name = models.CharField(max_length=100, unique=True)

    def __str__(self):
        return self.name