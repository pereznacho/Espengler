from django.db import models
from deep_translator import GoogleTranslator 
from deep_translator.exceptions import NotValidLength
from attack_narrative.models import Writeup



class Project(models.Model):
    name = models.CharField(max_length=255, null=True, blank=True)
    description = models.TextField(null=True, blank=True)
    start_date = models.DateField(null=True, blank=True)
    end_date = models.DateField(null=True, blank=True)
    language = models.CharField(max_length=2, choices=[('EN', 'English'), ('ES', 'Español')])
    report_template = models.ForeignKey('ReportTemplate', on_delete=models.SET_NULL, null=True, blank=True)
    scope = models.TextField(null=True, blank=True)  # Nuevo campo de alcance
    cover_template = models.ForeignKey('ReportCoverTemplate', on_delete=models.SET_NULL, null=True, blank=True)  # Aquí está el campo
    attack_narratives = models.ManyToManyField(Writeup, related_name='projects', blank=True)



    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        # Lógica de traducción aquí
        super().save(*args, **kwargs)


class Target(models.Model):
    project = models.ForeignKey(Project, on_delete=models.CASCADE)
    ip_address = models.GenericIPAddressField(null=True, blank=True)  # Permitir NULL
    fqdn = models.CharField(max_length=255, blank=True, null=True)
    urlAddress = models.URLField(max_length=1024, blank=True, null=True)
    os = models.CharField(max_length=255, blank=True, null=True)  # Sistema Operativo    
    owned = models.BooleanField(default=False)
    jumped_from = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True, related_name='jump_targets')
    x_position = models.FloatField(null=True, blank=True)
    y_position = models.FloatField(null=True, blank=True)

    class Meta:
        unique_together = ('ip_address', 'fqdn', 'urlAddress')

    def __str__(self):
        return self.urlAddress or self.fqdn or str(self.ip_address)

    @classmethod
    def get_owned_targets(cls):
        return cls.objects.filter(owned=True).select_related('jumped_from')


class Port(models.Model):
    port_number = models.IntegerField()
    protocol = models.CharField(max_length=50)
    state = models.CharField(max_length=50)
    service_name = models.CharField(max_length=255, blank=True, null=True)
    product = models.CharField(max_length=255, blank=True, null=True)
    version = models.CharField(max_length=255, blank=True, null=True)
    banner = models.TextField(blank=True, null=True)  # Add this line
    target = models.ForeignKey(Target, on_delete=models.CASCADE, related_name='ports', null=True)
    vulnerabilities = models.ManyToManyField('Vulnerability', through='PortVulnerabilityProject', related_name='associated_ports')

    def __str__(self):
        return f"{self.port_number}/{self.protocol}"



class Vulnerability(models.Model):
    project = models.ForeignKey(Project, on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    description = models.TextField(null=True, blank=True)
    solution = models.TextField(null=True, blank=True)
    hosts_affected = models.TextField(blank=True, null=True)
    protocol = models.CharField(max_length=50, null=True, blank=True)
    evidence = models.TextField()
    description_es = models.TextField(null=True, blank=True)
    solution_es = models.TextField(null=True, blank=True)
    risk_factor = models.CharField(max_length=50, blank=True, null=True)
    cvss_temporal_score = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    evidence_images = models.ManyToManyField('EvidenceImage', blank=True)
    see_also = models.TextField(null=True, blank=True)
    target_host = models.ForeignKey(Target, on_delete=models.CASCADE, null=True, blank=True)
    port = models.ForeignKey(Port, on_delete=models.CASCADE, null=True, default=None, related_name='associated_vulnerabilities')  

    class Meta:
        verbose_name_plural = "vulnerabilities"

    def save(self, *args, **kwargs):
        if self.project.language == 'ES':
            if self.description:
                self.description_es = self.translate_text(self.description)
            if self.solution:
                self.solution_es = self.translate_text(self.solution)
        super().save(*args, **kwargs)

    def translate_text(self, text):
        max_chars = 5000
        max_block_chars = 4000

        if len(text) <= max_chars:
            # Si el texto es menor o igual al límite, traducir directamente
            return GoogleTranslator(source='en', target='es').translate(text)
        else:
            # Si el texto excede el límite, dividir en segmentos y traducir cada uno
            segments = [text[i:i+max_block_chars] for i in range(0, len(text), max_block_chars)]
            translated_segments = []
            for segment in segments:
                if len(segment) <= max_chars:
                    translated_segments.append(GoogleTranslator(source='en', target='es').translate(segment))
                else:
                    # Si el segmento todavía excede los 5000 caracteres después de dividirlo,
                    # dividirlo nuevamente en bloques de 4000 caracteres
                    sub_segments = [segment[j:j+max_block_chars] for j in range(0, len(segment), max_block_chars)]
                    translated_sub_segments = [GoogleTranslator(source='en', target='es').translate(sub_segment) for sub_segment in sub_segments]
                    translated_segments.append(' '.join(translated_sub_segments))
            return ' '.join(translated_segments)

    def __str__(self):
        return self.name


class PortVulnerabilityProject(models.Model):
    port = models.ForeignKey(Port, on_delete=models.CASCADE)
    vulnerability = models.ForeignKey(Vulnerability, on_delete=models.CASCADE)
    project = models.ForeignKey(Project, on_delete=models.CASCADE)

    class Meta:
        unique_together = ('port', 'vulnerability', 'project')

    def __str__(self):
        return f"Port: {self.port}, Vulnerability: {self.vulnerability}, Project: {self.project}"



class EvidenceImage(models.Model):
    image = models.ImageField(upload_to='evidence_images/')
    description = models.CharField(max_length=255, default='', blank=True)
    project = models.ForeignKey('Project', on_delete=models.CASCADE)  # Hacer que sea obligatorio

    def __str__(self):
        return self.description if self.description else 'No Description'


class ReportTemplate(models.Model):
    name = models.CharField(max_length=100, unique=True)
    content = models.TextField()

    def __str__(self):
        return self.name


class ReportCoverTemplate(models.Model):
    name = models.CharField(max_length=255, unique=True)
    analisys_type = models.CharField(max_length=255)
    customer_name = models.CharField(max_length=255)
    start_date = models.DateField()
    end_date = models.DateField()
    customer_image = models.ImageField(upload_to='imagenes/')
    header_image = models.ImageField(upload_to='imagenes/', null=True, blank=True)
    customer_header_image = models.ImageField(upload_to='imagenes/', null=True, blank=True)  # Cliente    

    def __str__(self):
        return self.name



