from django.urls import path
from .views import import_attack_narrative, attack_narrative_list, writeup_create, writeup_edit, writeup_delete
from django_ckeditor_5.views import upload_file


urlpatterns = [
    path("", attack_narrative_list, name="attack_narrative_list"),
    path("import/", import_attack_narrative, name="import_attack_narrative"),
    path("create/", writeup_create, name="writeup_create"),
    path("<int:pk>/edit/", writeup_edit, name="writeup_edit"),
    path("<int:pk>/delete/", writeup_delete, name="writeup_delete"),
    path("ckeditor/upload/", upload_file, name="ck_editor_5_upload_file"),
]