import os
import shutil
import tempfile
import json
from zipfile import ZipFile

from django.conf import settings
from django.http import FileResponse, HttpResponse
from django.shortcuts import render, redirect
from django.contrib import messages
from django.utils.timezone import now
from django.views.decorators.csrf import csrf_exempt
from django.core.files.storage import default_storage
from django.core.management import call_command
from django.contrib.auth.decorators import login_required
from django.contrib.admin.views.decorators import staff_member_required


@login_required
@staff_member_required
def export_data(request):
    """
    Exporta todos los datos de la base de datos + archivos en un archivo .zip
    """
    temp_dir = tempfile.mkdtemp()
    json_path = os.path.join(temp_dir, "backup_data.json")
    zip_path = os.path.join(temp_dir, f"full_backup_{now().strftime('%Y%m%d_%H%M%S')}.zip")

    # 1. Exportar JSON
    with open(json_path, "w", encoding="utf-8") as f:
        call_command("dumpdata", "--natural-primary", "--natural-foreign", "--exclude=contenttypes", "--exclude=sessions", stdout=f)

    # 2. Copiar carpetas de medios
    protected_src = getattr(settings, "PROTECTED_MEDIA_ROOT", os.path.join(settings.BASE_DIR, "protected_media"))
    media_src = getattr(settings, "MEDIA_ROOT", os.path.join(settings.BASE_DIR, "media"))
    protected_dst = os.path.join(temp_dir, "protected_media")
    media_dst = os.path.join(temp_dir, "media")

    if os.path.exists(protected_src):
        shutil.copytree(protected_src, protected_dst)
    if os.path.exists(media_src):
        shutil.copytree(media_src, media_dst)

    # 3. Crear ZIP
    with ZipFile(zip_path, "w") as backup_zip:
        backup_zip.write(json_path, arcname="backup_data.json")
        for folder in ["protected_media", "media"]:
            folder_path = os.path.join(temp_dir, folder)
            for root, _, files in os.walk(folder_path):
                for file in files:
                    abs_path = os.path.join(root, file)
                    rel_path = os.path.relpath(abs_path, temp_dir)
                    backup_zip.write(abs_path, arcname=rel_path)

    messages.success(request, "Backup creado correctamente.")
    return FileResponse(open(zip_path, "rb"), as_attachment=True, filename=os.path.basename(zip_path))


@login_required
@staff_member_required
def import_data(request):
    """
    Importa datos y archivos desde un backup en ZIP
    """
    if request.method == "POST" and request.FILES.get("backup_file"):
        zip_file = request.FILES["backup_file"]

        if not zip_file.name.endswith(".zip"):
            messages.error(request, "El archivo debe ser un .zip válido.")
            return redirect("import_data")

        temp_dir = tempfile.mkdtemp()
        zip_path = os.path.join(temp_dir, "imported_backup.zip")

        with open(zip_path, "wb+") as f:
            for chunk in zip_file.chunks():
                f.write(chunk)

        try:
            with ZipFile(zip_path, "r") as zip_ref:
                zip_ref.extractall(temp_dir)

            # Restaurar medios
            for folder in ["media", "protected_media"]:
                extracted = os.path.join(temp_dir, folder)
                dest = getattr(settings, f"{folder.upper()}_ROOT", os.path.join(settings.BASE_DIR, folder))

                if os.path.exists(extracted):
                    if os.path.exists(dest):
                        shutil.rmtree(dest)
                    shutil.copytree(extracted, dest)

            # Restaurar datos
            data_path = os.path.join(temp_dir, "backup_data.json")
            if os.path.exists(data_path):
                call_command("loaddata", data_path)

            messages.success(request, "Backup restaurado correctamente.")
            return redirect("import_data")

        except Exception as e:
            messages.error(request, f"Ocurrió un error al importar el backup: {e}")
            return redirect("import_data")

    return render(request, "BackupRestore/import.html")