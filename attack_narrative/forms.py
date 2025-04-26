from django import forms
from .models import Writeup
from django_ckeditor_5.widgets import CKEditor5Widget

class WriteupAdminForm(forms.ModelForm):
    content_html = forms.CharField(
        widget=CKEditor5Widget(config_name="default"),  # ✅ Usamos el widget oficial
        required=False
    )

    class Meta:
        model = Writeup
        fields = "__all__"