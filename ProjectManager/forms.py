from django import forms
from .models import Project, Vulnerability, EvidenceImage, PortVulnerabilityProject, ReportCoverTemplate, ReportTemplate, Target, Port
from attack_narrative.models import Writeup
from tinymce.widgets import TinyMCE
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import UserCreationForm, PasswordChangeForm
from django.contrib.auth.models import User


class AppPasswordChangeForm(PasswordChangeForm):
    """Cambio de contraseña con estilos de la app."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for name, field in self.fields.items():
            field.widget.attrs['class'] = 'form-control'


class UserProfileForm(forms.ModelForm):
    """Formulario para editar perfil (nombre, apellido, email)."""
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email']
        widgets = {
            'first_name': forms.TextInput(attrs={'class': 'form-control'}),
            'last_name': forms.TextInput(attrs={'class': 'form-control'}),
            'email': forms.EmailInput(attrs={'class': 'form-control'}),
        }

# Usa TINYMCE_DEFAULT_CONFIG de settings (todas las funciones free + placeholders)
class ReportTemplateForm(forms.ModelForm):
    content = forms.CharField(widget=TinyMCE(
        attrs={'cols': 80, 'rows': 30, 'class': 'form-control'}
    ))

    class Meta:
        model = ReportTemplate
        fields = ['name', 'content', 'background_color', 'main_color']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'background_color': forms.TextInput(attrs={'class': 'form-control', 'type': 'color'}),
            'main_color': forms.TextInput(attrs={'class': 'form-control', 'type': 'color'}),
        }

class TinyMCEForm(forms.Form):
    content = forms.CharField(widget=forms.Textarea(attrs={'cols': 80, 'rows': 20}))



class ProjectForm(forms.ModelForm):
    LANGUAGE_CHOICES = [
        ('EN', 'English'),
        ('ES', 'Spanish'),
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
    attack_narratives = forms.ModelMultipleChoiceField(
        queryset=Writeup.objects.all().order_by('title'),
        widget=forms.CheckboxSelectMultiple,
        required=False,
        label='Writeups'
    )

    class Meta:
        model = Project
        fields = ['name', 'description', 'start_date', 'end_date', 'language', 'report_template', 'cover_template', 'scope', 'attack_narratives']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
            'scope': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
            'start_date': forms.DateInput(attrs={'type': 'date', 'class': 'form-control'}),
            'end_date': forms.DateInput(attrs={'type': 'date', 'class': 'form-control'}),
            'language': forms.Select(attrs={'class': 'form-control'}),
            'report_template': forms.Select(attrs={'class': 'form-control'}),
            'cover_template': forms.Select(attrs={'class': 'form-control'}),
        }


class PortVulnerabilityProjectForm(forms.ModelForm):
    class Meta:
        model = PortVulnerabilityProject
        fields = ['port', 'vulnerability', 'project']  # Asegúrate de incluir el campo 'project'

class VulnerabilityUploadForm(forms.Form):
    # Agrega aquí los campos necesarios para la importación de archivos Nessus
    nessus_file = forms.FileField(label='Select a Nessus file')

class PortsUploadForm(forms.Form):
    # Agrega aquí los campos necesarios para la importación de archivos XML de Nmap
    nmap_file = forms.FileField(label='Select an Nmap XML file')

class NessusFileUploadForm(forms.Form):
    nessus_file = forms.FileField(label='Select a Nessus File')

class NmapFileUploadForm(forms.Form):
    nmap_file = forms.FileField(label='Select an Nmap XML file')

class ChangeProjectForm(forms.ModelForm):
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
    attack_narratives = forms.ModelMultipleChoiceField(
        queryset=Writeup.objects.all().order_by('title'),
        widget=forms.CheckboxSelectMultiple,
        required=False,
        label='Writeups'
    )

    class Meta:
        model = Project
        fields = ['name', 'description', 'start_date', 'end_date', 'language', 'report_template', 'cover_template', 'scope', 'attack_narratives']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
            'scope': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
            'start_date': forms.DateInput(attrs={'type': 'date', 'class': 'form-control'}),
            'end_date': forms.DateInput(attrs={'type': 'date', 'class': 'form-control'}),
            'language': forms.Select(attrs={'class': 'form-control'}),
            'report_template': forms.Select(attrs={'class': 'form-control'}),
            'cover_template': forms.Select(attrs={'class': 'form-control'}),
        }

class VulnerabilityForm(forms.ModelForm):
    class Meta:
        model = Vulnerability
        fields = [
            'name', 'description', 'solution', 'hosts_affected', 'protocol', 'evidence',
            'risk_factor', 'cvss_temporal_score', 'see_also', 'target_host', 'port', 'evidence_images'
        ]
        widgets = {
            'description': forms.Textarea(attrs={'rows': 4}),
            'solution': forms.Textarea(attrs={'rows': 4}),
            'evidence': forms.Textarea(attrs={'rows': 4}),
            'see_also': forms.Textarea(attrs={'rows': 2}),
        }

    def __init__(self, *args, project=None, **kwargs):
        super().__init__(*args, **kwargs)
        if project:
            self.fields['target_host'].queryset = Target.objects.filter(project=project)
            self.fields['port'].queryset = Port.objects.filter(target__project=project).distinct()
            self.fields['evidence_images'].queryset = EvidenceImage.objects.filter(project=project)
            if 'evidence_images' in self.fields:
                self.fields['evidence_images'].widget = forms.CheckboxSelectMultiple()
            if not self.instance.pk:
                self.initial.setdefault('project', project)


class VulnerabilityFullForm(forms.ModelForm):
    """Full vulnerability form for new-version UI (all fields like admin)."""
    class Meta:
        model = Vulnerability
        fields = [
            'name', 'description', 'solution', 'hosts_affected', 'protocol', 'evidence',
            'risk_factor', 'cvss_temporal_score', 'see_also', 'target_host', 'port', 'evidence_images'
        ]
        widgets = {
            'description': forms.Textarea(attrs={'rows': 5, 'class': 'form-control'}),
            'solution': forms.Textarea(attrs={'rows': 5, 'class': 'form-control'}),
            'evidence': forms.Textarea(attrs={'rows': 5, 'class': 'form-control'}),
            'see_also': forms.Textarea(attrs={'rows': 2, 'class': 'form-control'}),
        }

    def __init__(self, *args, project=None, **kwargs):
        super().__init__(*args, **kwargs)
        if project:
            self.fields['target_host'].queryset = Target.objects.filter(project=project)
            self.fields['port'].queryset = Port.objects.filter(target__project=project).distinct()
            self.fields['evidence_images'].queryset = EvidenceImage.objects.filter(project=project)
            if 'evidence_images' in self.fields:
                self.fields['evidence_images'].widget = forms.CheckboxSelectMultiple()


# Para múltiples imágenes; opcionalmente asigna la evidencia a una vulnerabilidad del proyecto
class EvidenceImageForm(forms.ModelForm):
    vulnerability = forms.ModelChoiceField(
        queryset=Vulnerability.objects.none(),
        required=False,
        empty_label='— Select vulnerability to attach this evidence to',
        label='Attach to vulnerability',
        widget=forms.Select(attrs={'class': 'form-control'})
    )

    class Meta:
        model = EvidenceImage
        fields = ['image', 'description']

    def __init__(self, *args, project=None, **kwargs):
        super().__init__(*args, **kwargs)
        if project:
            self.fields['vulnerability'].queryset = Vulnerability.objects.filter(project=project).order_by('name')

class NetsparkerFileUploadForm(forms.Form):
    netsparker_file = forms.FileField(label='Select an XML Netsparker file')

class AssignTargetsAndPortsForm(forms.ModelForm):
    class Meta:
        model = Vulnerability
        fields = ['hosts_affected', 'port']

class CustomUserCreationForm(UserCreationForm):
    """Crear usuario con rol: Admin (ve todo) o Consultant (solo proyectos asignados)."""
    ROLE_CHOICES = [
        ('consultant', 'Consultant — Sees only assigned projects'),
        ('admin', 'Admin — Sees and manages all projects'),
    ]
    role = forms.ChoiceField(
        choices=ROLE_CHOICES,
        widget=forms.RadioSelect(attrs={'class': 'form-check-input'}),
        label='User type',
        initial='consultant',
    )

    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']
        widgets = {
            'username': forms.TextInput(attrs={'class': 'form-control'}),
            'email': forms.EmailInput(attrs={'class': 'form-control'}),
            'password1': forms.PasswordInput(attrs={'class': 'form-control'}),
            'password2': forms.PasswordInput(attrs={'class': 'form-control'}),
        }

    def save(self, commit=True):
        user = super().save(commit=False)
        user.is_staff = (self.cleaned_data.get('role') == 'admin')
        if commit:
            user.save()
        return user

class AcunetixUploadForm(forms.Form):
    acunetix_file = forms.FileField(label='Select a Acunetix XML file')        

class BurpUploadForm(forms.Form):
    burp_file = forms.FileField(label='Select a Burp XML file')

class ReportCoverForm(forms.ModelForm):
    class Meta:
        model = ReportCoverTemplate
        fields = [
            'name', 'analisys_type', 'customer_name', 'subtitle', 'consultant_name',
            'start_date', 'end_date', 'customer_image', 'customer_image_scale',
            'header_image', 'customer_header_image', 'background_image',
            'cover_background_color',
        ]
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'analisys_type': forms.TextInput(attrs={'class': 'form-control'}),
            'customer_name': forms.TextInput(attrs={'class': 'form-control'}),
            'subtitle': forms.TextInput(attrs={'class': 'form-control'}),
            'consultant_name': forms.TextInput(attrs={'class': 'form-control'}),
            'start_date': forms.DateInput(attrs={'type': 'date', 'class': 'form-control'}),
            'end_date': forms.DateInput(attrs={'type': 'date', 'class': 'form-control'}),
            'customer_image_scale': forms.NumberInput(attrs={'class': 'form-control'}),
            'cover_background_color': forms.TextInput(attrs={'class': 'form-control'}),
        }

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


class TargetEditForm(forms.ModelForm):
    """Formulario para ver/editar un target desde la app (como en Admin)."""
    class Meta:
        model = Target
        fields = ['ip_address', 'fqdn', 'urlAddress', 'os', 'owned', 'jumped_from']
        labels = {
            'ip_address': 'IP address',
            'fqdn': 'FQDN',
            'urlAddress': 'URL',
            'os': 'Operating system',
            'owned': 'Compromised (owned)',
            'jumped_from': 'Jumped from (pivot)',
        }
        widgets = {
            'ip_address': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'e.g. 192.168.1.1'}),
            'fqdn': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'host.example.com'}),
            'urlAddress': forms.URLInput(attrs={'class': 'form-control', 'placeholder': 'https://...'}),
            'os': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'e.g. Linux, Windows 10, Ubuntu'}),
            'owned': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'jumped_from': forms.Select(attrs={'class': 'form-control'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance and self.instance.pk and self.instance.project_id:
            self.fields['jumped_from'].queryset = Target.objects.filter(project=self.instance.project).exclude(pk=self.instance.pk)
            self.fields['jumped_from'].required = False
            self.fields['jumped_from'].empty_label = '— None (entry point)'


class AddProjectMemberForm(forms.Form):
    """Añadir un usuario al proyecto."""
    user = forms.ModelChoiceField(
        queryset=User.objects.none(),
        label='User',
        widget=forms.Select(attrs={'class': 'form-control'}),
    )

    def __init__(self, project, *args, **kwargs):
        self.project = project
        super().__init__(*args, **kwargs)
        User = get_user_model()
        already = list(project.members.values_list('pk', flat=True))
        self.fields['user'].queryset = User.objects.exclude(pk__in=already).order_by('username')
        if not self.fields['user'].queryset.exists():
            self.fields['user'].empty_label = '— No more users'
        else:
            self.fields['user'].empty_label = '— Select user'