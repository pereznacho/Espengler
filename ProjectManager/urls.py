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
    path('projects/<int:project_id>/delete/', views.project_delete, name='project_delete'),
    path('import_nessus/<int:pk>/', views.import_nessus_file, name='import_nessus_file'),
    path('project/<int:pk>/import_nmap_xml/', views.import_nmap_xml, name='import_nmap_xml'),
#    path('project/generate_report/<int:project_id>/', views.generate_report, name='generate_report'),
    path('add_vulnerability/', views.add_vulnerability, name='add_vulnerability'),
    path('projects/<int:project_id>/add_vulnerability/', views.add_vulnerability, name='add_vulnerability_to_project'),
    path('projects/<int:project_id>/vulnerability/<int:vuln_id>/edit/', views.vulnerability_edit, name='vulnerability_edit'),
    path('projects/<int:project_id>/add_evidence/', views.add_evidence_image, name='add_evidence_image'),
    path('targets/', views.targets_view, name='targets'),
    path('report-templates/', views.report_template_list, name='report_template_list'),
    path('report-templates/create/', views.report_template_create, name='report_template_create'),
    path('report-templates/edit/<int:pk>/', views.report_template_edit, name='report_template_edit'),
    path('report-templates/delete/<int:pk>/', views.report_template_delete, name='report_template_delete'),
    path('import_netsparker/<int:pk>/', views.import_netsparker_file, name='import_netsparker_file'),
    path('login/', views.app_login, name='app_login'),
    path('logout/', views.app_logout, name='app_logout'),
    path('register/', views.register_view, name='register'),
    path('import_acunetix/<int:pk>/', views.import_acunetix_xml, name='import_acunetix_file'),
    path('import_burp/<int:pk>/', views.import_burp_xml, name='import_burp_file'),
    path('configurar-tapa-reporte/<int:project_id>/', views.configurar_tapa_reporte, name='configurar_tapa_reporte'),
    path('cover-designer/template/<int:template_id>/', views.visual_cover_designer_template, name='visual_cover_designer_template'),
    path('cover-templates/', views.cover_template_list, name='cover_template_list'),
    path('cover-templates/create/', views.cover_template_create, name='cover_template_create'),
    path('cover-templates/delete/<int:pk>/', views.cover_template_delete, name='cover_template_delete'),
    path('generate-report/<int:project_id>/', views.generate_report, name='generate_report'),
    path('attack_narrative/', include('attack_narrative.urls')),    
    path('project/<int:project_id>/graph_map/', views.graph_map_view, name='graph_map'),
    path('graph-icon-proxy/', views.graph_icon_proxy, name='graph_icon_proxy'),
    path('graph-node-image/', views.graph_node_image, name='graph_node_image'),
    path('admin/media/<int:writeup_id>/<str:filename>/', serve_protected_media, name="protected_media"),
    path('protected_media/<str:writeup_name>/<str:filename>/', serve_protected_media, name='serve_protected_media'),
    path("project/save_node_position/<int:target_id>/", views.save_node_position, name="save_node_position"),
    path("project/target/<int:target_id>/toggle_owned/", views.toggle_target_owned, name="toggle_target_owned"),
    path("projects/<int:project_id>/target/<int:target_id>/", views.target_edit, name="target_edit"),
    path("profile/", views.profile_edit, name="profile_edit"),
    path("profile/password/", views.app_password_change, name="app_password_change"),
    path("profile/password/done/", views.app_password_change_done, name="app_password_change_done"),
    path("project-members/", views.project_member_list, name="project_member_list"),
    path("project-members/add-user/", views.user_create, name="user_create"),
    path("projects/<int:project_id>/members/", views.project_members_manage, name="project_members_manage"),
    path("projects/<int:project_id>/members/remove/<int:user_id>/", views.project_member_remove, name="project_member_remove"),
]

# Añade otras configuraciones de vistas o rutas adicionales si es necesario.