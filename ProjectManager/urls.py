# ProjectManager/urls.py

from django.urls import path, include
from . import views
from .views import generate_report, change_project, targets_view, register, login_view, register_view, configurar_tapa_reporte, generate_report, graph_view





urlpatterns = [
  
    path('projects/create/', views.create_project, name='create_project'),
    path('projects/<int:pk>/', views.project_detail, name='project_detail'),
    path('project/change/<int:pk>/', views.change_project, name='change_project'),
    path('projects/', views.project_list, name='project_list'),
    path('import_nessus/<int:pk>/', views.import_nessus_file, name='import_nessus_file'),
    path('project/<int:pk>/import_nmap_xml/', views.import_nmap_xml, name='import_nmap_xml'),
    path('project/generate_report/<int:project_id>/', generate_report, name='generate_report'),
    path('add_vulnerability/', views.add_vulnerability, name='add_vulnerability'),   
    path("__debug__/", include("debug_toolbar.urls")),
    path('targets/', targets_view, name='targets'),
    path('report-templates/', views.report_template_list, name='report_template_list'),
    path('report-templates/create/', views.report_template_create, name='report_template_create'),
    path('report-templates/edit/<int:pk>/', views.report_template_edit, name='report_template_edit'),
    path('report-templates/delete/<int:pk>/', views.report_template_delete, name='report_template_delete'),
    path('import_netsparker/<int:pk>/', views.import_netsparker_file, name='import_netsparker_file'),
    path('login/', login_view, name='login'),
    path('register/', register_view, name='register'),
    path('import_acunetix/<int:pk>/', views.import_acunetix_xml, name='import_acunetix_file'),   
    path('import_burp/<int:pk>/', views.import_burp_xml, name='import_burp_file'), 
    path('configurar-tapa-reporte/<int:project_id>/', configurar_tapa_reporte, name='configurar_tapa_reporte'),
    path('generate-report/<int:project_id>/', generate_report, name='generate_report'),
    path('project/<int:pk>/graph/', graph_view, name='graph_view'),

]
