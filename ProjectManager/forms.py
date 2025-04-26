from django import forms
from .models import Project, Vulnerability, EvidenceImage, PortVulnerabilityProject, ReportCoverTemplate, ReportTemplate, Target
from tinymce.widgets import TinyMCE
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User

# En tu formulario Django
class ReportTemplateForm(forms.ModelForm):
    content = forms.CharField(widget=TinyMCE(
        attrs={'cols': 80, 'rows': 30},
        mce_attrs={'toolbar': 'undo redo | image | formatselect | bold italic | alignleft aligncenter alignright alignjustify | bullist numlist outdent indent | link image'}
    ))

    class Meta:
        model = ReportTemplate
        fields = ['name', 'content']

class TinyMCEForm(forms.Form):
    content = forms.CharField(widget=forms.Textarea(attrs={'cols': 80, 'rows': 20}))



class ProjectForm(forms.ModelForm):
    LANGUAGE_CHOICES = [
        ('EN', 'English'),
        ('ES', 'Español'),
    ]

    report_template = forms.ModelChoiceField(
        queryset=ReportTemplate.objects.all(),
        empty_label="Select a Report Template",
        required=False
    )
    
    cover_template = forms.ModelChoiceField(
        queryset=ReportCoverTemplate.objects.all(),
        empty_label="Select a Cover Template",
        required=False
    )

    class Meta:
        model = Project
        fields = ['name', 'description', 'start_date', 'end_date', 'language', 'report_template', 'cover_template', 'scope']




class PortVulnerabilityProjectForm(forms.ModelForm):
    class Meta:
        model = PortVulnerabilityProject
        fields = ['port', 'vulnerability', 'project']  # Asegúrate de incluir el campo 'project'

class VulnerabilityUploadForm(forms.Form):
    # Agrega aquí los campos necesarios para la importación de archivos Nessus
    nessus_file = forms.FileField(label='Selecciona un archivo Nessus')

class PortsUploadForm(forms.Form):
    # Agrega aquí los campos necesarios para la importación de archivos XML de Nmap
    nmap_file = forms.FileField(label='Selecciona un archivo XML de Nmap')

class NessusFileUploadForm(forms.Form):
    nessus_file = forms.FileField(label='Select a Nessus File')

class NmapFileUploadForm(forms.Form):
    nmap_file = forms.FileField(label='Selecciona un archivo XML de Nmap')

class ChangeProjectForm(forms.ModelForm):
    class Meta:
        model = Project
        fields = ['name', 'description', 'start_date', 'end_date', 'language']

class VulnerabilityForm(forms.ModelForm):
    class Meta:
        model = Vulnerability
        fields = ['name', 'description', 'solution', 'hosts_affected', 'evidence_images']  # Añade 'evidence_images'

# Para múltiples imágenes, si usas un modelo separado
class EvidenceImageForm(forms.ModelForm):
    class Meta:
        model = EvidenceImage
        fields = ['image']

class NetsparkerFileUploadForm(forms.Form):
    netsparker_file = forms.FileField(label='Select an XML Netsparker file')

class AssignTargetsAndPortsForm(forms.ModelForm):
    class Meta:
        model = Vulnerability
        fields = ['hosts_affected', 'port']

class CustomUserCreationForm(UserCreationForm):
    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']

class AcunetixUploadForm(forms.Form):
    acunetix_file = forms.FileField(label='Select a Acunetix XML file')        

class BurpUploadForm(forms.Form):
    burp_file = forms.FileField(label='Select a Burp XML file')

class ReportCoverForm(forms.ModelForm):
    class Meta:
        model = ReportCoverTemplate
        fields = ['name', 'analisys_type', 'customer_name', 'start_date', 'end_date', 'customer_image', 'header_image']

class ProjectAdminForm(forms.ModelForm):
    class Meta:
        model = Project
        fields = '__all__'  # O especifica los campos necesarios


class TargetAdminForm(forms.ModelForm):
    class Meta:
        model = Target
        fields = '__all__'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance and self.instance.project:
            self.fields['jumped_from'].queryset = Target.objects.filter(project=self.instance.project)