import os
import requests
from bs4 import BeautifulSoup
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse
from django.conf import settings
from django.utils.text import slugify

from .models import Writeup, Tag
from .utils import import_obsidian_note
from .forms import WriteupForm


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
        # Prevent path traversal: use basename and allow only .md
        safe_name = os.path.basename(file.name).strip()
        if not safe_name.endswith(".md") or ".." in safe_name:
            messages.error(request, "Only .md files are allowed.")
            return redirect("attack_narrative_list")

        os.makedirs("media/uploads", exist_ok=True)
        file_path = os.path.join("media/uploads", safe_name)

        with open(file_path, "wb+") as destination:
            for chunk in file.chunks():
                destination.write(chunk)

        try:
            attack_narrative_data = import_obsidian_note(file_path)

            if not attack_narrative_data or not isinstance(attack_narrative_data, dict):
                messages.error(request, "The file did not contain valid data.")
                return redirect("attack_narrative_list")

            writeup = Writeup.objects.create(
                title=attack_narrative_data.get("title", file.name.replace(".md", "")),
                content_html=attack_narrative_data.get("content_html", "")
            )

            if writeup.content_html:
                soup = BeautifulSoup(writeup.content_html, "html.parser")
                for img in soup.find_all("img"):
                    src = img.get("src", "")
                    if src.startswith("http://") or src.startswith("https://"):
                        local_url = download_image_from_url(src, writeup.title)
                        img["src"] = local_url
                writeup.content_html = str(soup)
                writeup.save()

            messages.success(request, f"Writeup '{writeup.title}' imported successfully.")

        except Exception as e:
            messages.error(request, f"Error importing Obsidian data: {e}")
            return redirect("attack_narrative_list")

        return redirect("attack_narrative_list")

    return render(request, "attack_narrative/import_attack_narrative.html")


@login_required
def attack_narrative_list(request):
    """
    List Writeups (new app style).
    """
    attack_narratives = Writeup.objects.all().order_by("-created_at")
    return render(request, "attack_narrative/attack_narrative_list.html", {"attack_narratives": attack_narratives})


@login_required
def writeup_create(request):
    """Create a new Writeup (title + content_html with CKEditor)."""
    if request.method == "POST":
        form = WriteupForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "Writeup created.")
            return redirect("attack_narrative_list")
    else:
        form = WriteupForm()
    return render(request, "attack_narrative/writeup_form.html", {"form": form})


@login_required
def writeup_edit(request, pk):
    """Edit an existing Writeup."""
    writeup = get_object_or_404(Writeup, pk=pk)
    if request.method == "POST":
        form = WriteupForm(request.POST, instance=writeup)
        if form.is_valid():
            form.save()
            messages.success(request, "Writeup updated.")
            return redirect("attack_narrative_list")
    else:
        form = WriteupForm(instance=writeup)
    return render(request, "attack_narrative/writeup_form.html", {"form": form, "writeup": writeup})


@login_required
def writeup_delete(request, pk):
    """Delete a Writeup."""
    writeup = get_object_or_404(Writeup, pk=pk)
    title = writeup.title
    writeup.delete()
    messages.success(request, f"Writeup '{title}' deleted.")
    return redirect("attack_narrative_list")


# Allowed image extensions and max size (5MB) for upload
ALLOWED_IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".webp"}
MAX_UPLOAD_IMAGE_SIZE = 5 * 1024 * 1024


def _safe_upload_filename(name):
    """Return a safe filename (no path traversal, alphanumeric + safe ext)."""
    base = os.path.basename(name).strip()
    if not base or ".." in base or base.startswith("/"):
        return None
    ext = os.path.splitext(base)[1].lower()
    if ext not in ALLOWED_IMAGE_EXTENSIONS:
        return None
    # Keep a short safe base (alphanumeric + hyphen) + original ext
    safe_base = "".join(c for c in os.path.splitext(base)[0] if c.isalnum() or c in "-_")[:80] or "image"
    return safe_base + ext


@login_required
def upload_writeup_image(request):
    """
    Image upload from editor (e.g. CKEditor). Requires auth; validates type and size.
    """
    if request.method != "POST" or not request.FILES.get("upload"):
        return JsonResponse({"error": "Invalid request"}, status=400)

    image = request.FILES["upload"]
    if image.size > MAX_UPLOAD_IMAGE_SIZE:
        return JsonResponse({"error": "File too large"}, status=400)

    safe_name = _safe_upload_filename(image.name)
    if not safe_name:
        return JsonResponse({"error": "Invalid or disallowed file type"}, status=400)

    writeup_title = request.POST.get("writeup_title", "temp").replace(" ", "_")[:80]
    writeup_title = "".join(c for c in writeup_title if c.isalnum() or c in "-_") or "temp"

    upload_dir = os.path.join(settings.PROTECTED_MEDIA_ROOT, writeup_title)
    os.makedirs(upload_dir, exist_ok=True)

    file_path = os.path.join(upload_dir, safe_name)
    with open(file_path, "wb+") as destination:
        for chunk in image.chunks():
            destination.write(chunk)

    image_url = f"/protected_media/{writeup_title}/{safe_name}"
    return JsonResponse({"url": image_url})