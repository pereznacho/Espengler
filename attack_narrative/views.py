import os
import requests
from bs4 import BeautifulSoup
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from django.utils.text import slugify

from .models import Writeup, Tag
from .utils import import_obsidian_note


def download_image_from_url(url, writeup_title):
    """
    Descarga una imagen desde una URL y la guarda en /protected_media/<writeup_title>/
    """
    try:
        response = requests.get(url, stream=True, timeout=10)
        if response.status_code == 200:
            writeup_slug = slugify(writeup_title)
            ext = os.path.splitext(url)[-1].split("?")[0] or ".jpg"
            filename = os.path.basename(url.split("/")[-1]).split("?")[0]
            local_dir = os.path.join(settings.PROTECTED_MEDIA_ROOT, writeup_slug)
            os.makedirs(local_dir, exist_ok=True)

            file_path = os.path.join(local_dir, filename)
            with open(file_path, "wb") as out_file:
                out_file.write(response.content)

            return f"/protected_media/{writeup_slug}/{filename}"
    except Exception as e:
        print(f"[ERROR] Al descargar imagen desde {url}: {e}")
    return url  # fallback


@login_required
def import_attack_narrative(request):
    """
    Vista protegida para importar archivos Markdown de Obsidian
    """
    if request.method == "POST":
        file = request.FILES["file"]

        os.makedirs("media/uploads", exist_ok=True)
        file_path = os.path.join("media/uploads", file.name)

        with open(file_path, "wb+") as destination:
            for chunk in file.chunks():
                destination.write(chunk)

        try:
            attack_narrative_data = import_obsidian_note(file_path)

            for data in attack_narrative_data:
                writeup_data = {key: value for key, value in data.items() if key != "tags"}
                writeup = Writeup.objects.create(**writeup_data)

                # Procesar imágenes externas en el HTML
                soup = BeautifulSoup(writeup.content_html, "html.parser")
                for img in soup.find_all("img"):
                    src = img.get("src", "")
                    if src.startswith("http://") or src.startswith("https://"):
                        local_url = download_image_from_url(src, writeup.title)
                        img["src"] = local_url
                writeup.content_html = str(soup)
                writeup.save()

                if "tags" in data:
                    tag_instances = Tag.objects.filter(name__in=data["tags"])
                    writeup.tags.set(tag_instances)

                messages.success(request, f"Writeup '{writeup.title}' importado con éxito.")

        except Exception as e:
            messages.error(request, f"Error al importar los datos de Obsidian: {e}")
            return redirect("attack_narrative_list")

        return redirect("attack_narrative_list")

    return render(request, "attack_narrative/import_attack_narrative.html")


@login_required
def attack_narrative_list(request):
    """
    Vista protegida para listar los Writeups
    """
    attack_narratives = Writeup.objects.all()
    return render(request, "attack_narrative/attack_narrative_list.html", {"attack_narratives": attack_narratives})


@csrf_exempt
def upload_writeup_image(request):
    """
    Subida de imágenes desde el editor CKEditor (manual upload)
    """
    if request.method == "POST" and request.FILES.get("upload"):
        writeup_title = request.POST.get("writeup_title", "temp").replace(" ", "_")
        image = request.FILES["upload"]

        upload_dir = os.path.join(settings.PROTECTED_MEDIA_ROOT, writeup_title)
        os.makedirs(upload_dir, exist_ok=True)

        file_path = os.path.join(upload_dir, image.name)
        with open(file_path, "wb+") as destination:
            for chunk in image.chunks():
                destination.write(chunk)

        image_url = f"/protected_media/{writeup_title}/{image.name}"
        return JsonResponse({ "url": image_url })

    return JsonResponse({ "error": "Invalid request" }, status=400)