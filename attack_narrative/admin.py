import os
import logging
from django.urls import path
from django.shortcuts import render, redirect
from django.contrib import admin, messages
from .models import Writeup, Tag, WriteupImage
from .utils import import_obsidian_note
from .forms import WriteupAdminForm

logger = logging.getLogger(__name__)



class WriteupAdmin(admin.ModelAdmin):
    form = WriteupAdminForm
    list_display = ("title", "created_at")
    search_fields = ("title",)
    ordering = ("-created_at",)
    fields = ("title", "content_html")

    class Media:
        js = (
            "js/ckeditor-fix.js",)  # ✅ Carga el JS que activa la subida personalizada a /protected_media/

    def get_urls(self):
        """
        Agrega una URL personalizada para la importación de archivos Obsidian en el admin.
        """
        urls = super().get_urls()
        custom_urls = [
            path(
                'import-obsidian/',
                self.admin_site.admin_view(self.import_obsidian),
                name="attack_narrative_import_obsidian"
            ),
        ]
        return custom_urls + urls

    def import_obsidian(self, request):
        """
        Vista para importar archivos Markdown de Obsidian.
        """
        if request.method == "POST":
            file = request.FILES.get("file")

            if not file:
                messages.error(request, "No se subió ningún archivo.")
                return redirect("admin:attack_narrative_writeup_changelist")

            file_path = os.path.join("media/uploads", file.name)
            os.makedirs("media/uploads", exist_ok=True)

            with open(file_path, "wb+") as destination:
                for chunk in file.chunks():
                    destination.write(chunk)

            logger.info(f"Archivo {file.name} guardado en {file_path}")

            try:
                attack_narrative_data = import_obsidian_note(file_path)

                if not isinstance(attack_narrative_data, dict):
                    messages.error(request, "Error en el formato del archivo: la conversión a diccionario falló.")
                    return redirect("admin:attack_narrative_writeup_changelist")

                if not attack_narrative_data:
                    messages.error(request, "El archivo no contiene datos válidos.")
                    return redirect("admin:attack_narrative_writeup_changelist")

                # Crear el Writeup
                writeup = Writeup.objects.create(
                    title=attack_narrative_data["title"],
                    content_html=attack_narrative_data["content_html"]
                )

                messages.success(request, f"Writeup '{writeup.title}' importado correctamente.")

            except Exception as e:
                logger.error(f"Error al importar: {e}")
                messages.error(request, f"Error al importar los datos de Obsidian: {e}")
                return redirect("admin:attack_narrative_writeup_changelist")

            return redirect("admin:attack_narrative_writeup_changelist")

        return render(request, "admin/import_obsidian.html")


# ✅ Registro de modelos secundarios
admin.site.register(Writeup, WriteupAdmin)