from django.conf import settings
import os

def generate_report(project):
    # ...existing code...
    writeup = project.assigned_writeup
    writeup_dir = os.path.join(settings.RESTRICTED_MEDIA_ROOT, writeup.name)
    
    # Buscar imágenes en el directorio del writeup
    images = []
    if os.path.exists(writeup_dir):
        images = [os.path.join(writeup_dir, img) for img in os.listdir(writeup_dir) if img.endswith(('.png', '.jpg', '.jpeg'))]
    
    # Usar las imágenes en el reporte
    # ...existing code...
