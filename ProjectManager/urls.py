# ProjectManager/urls.py
from django.urls import path, include
from . import views
from .views import serve_protected_media, protected_media_view
from ProjectManager.views import save_node_position


urlpatterns = [
    path('', views.home, name='home'),  # Ruta principal
    path('projects/create/', views.create_project, name='create_project'),
    path('projects/<int:pk>/', views.project_detail, name='project_detail'),
    path('project/change/<int:pk>/', views.change_project, name='change_project'),
    path('projects/', views.project_list, name='project_list'),
    path('import_nessus/<int:pk>/', views.import_nessus_file, name='import_nessus_file'),
    path('project/<int:pk>/import_nmap_xml/', views.import_nmap_xml, name='import_nmap_xml'),
#    path('project/generate_report/<int:project_id>/', views.generate_report, name='generate_report'),
    path('add_vulnerability/', views.add_vulnerability, name='add_vulnerability'),
    path('__debug__/', include('debug_toolbar.urls')),
    path('targets/', views.targets_view, name='targets'),
    path('report-templates/', views.report_template_list, name='report_template_list'),
    path('report-templates/create/', views.report_template_create, name='report_template_create'),
    path('report-templates/edit/<int:pk>/', views.report_template_edit, name='report_template_edit'),
    path('report-templates/delete/<int:pk>/', views.report_template_delete, name='report_template_delete'),
    path('import_netsparker/<int:pk>/', views.import_netsparker_file, name='import_netsparker_file'),
    path('login/', views.login_view, name='login'),
    path('register/', views.register_view, name='register'),
    path('import_acunetix/<int:pk>/', views.import_acunetix_xml, name='import_acunetix_file'),
    path('import_burp/<int:pk>/', views.import_burp_xml, name='import_burp_file'),
    path('configurar-tapa-reporte/<int:project_id>/', views.configurar_tapa_reporte, name='configurar_tapa_reporte'),
    path('generate-report/<int:project_id>/', views.generate_report, name='generate_report'),
    path('attack_narrative/', include('attack_narrative.urls')),    
    path('project/<int:project_id>/graph_map/', views.graph_map_view, name='graph_map'),
    path('admin/media/<int:writeup_id>/<str:filename>/', serve_protected_media, name="protected_media"),
    path('protected_media/<str:writeup_name>/<str:filename>/', serve_protected_media, name='serve_protected_media'),
    path("project/save_node_position/<int:target_id>/", views.save_node_position, name="save_node_position"),



]

# Añade otras configuraciones de vistas o rutas adicionales si es necesario.