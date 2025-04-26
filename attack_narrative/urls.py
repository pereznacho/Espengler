from django.urls import path
from .views import import_attack_narrative, attack_narrative_list  # Importamos las vistas correctamente
from django_ckeditor_5.views import upload_file


urlpatterns = [
    path("import/", import_attack_narrative, name="import_attack_narrative"),
    path("ckeditor/upload/", upload_file, name="ck_editor_5_upload_file"),
    path("", attack_narrative_list, name="attack_narrative_list"),
]