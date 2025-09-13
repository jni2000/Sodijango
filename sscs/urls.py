from django.urls import path, include
from rest_framework import routers, serializers, viewsets
from .views import SoftwareSecurityScanViewSet
from .views import SoftwareSecuritySignViewSet

# from . import views

# router = routers.DefaultRouter()
# router.register(r'softwareScan', SoftwareSecurityScanViewSet)
app_name = 'sscs'

urlpatterns = [
    # path('', views.list, name='list'),
    path('scan', SoftwareSecurityScanViewSet.as_view({'post': 'create'})),
    path('', SoftwareSecurityScanViewSet.as_view({'get': 'list'})),
    path('viewall', SoftwareSecurityScanViewSet.as_view({'get': 'list'})),
    path('index', SoftwareSecurityScanViewSet.as_view({'get': 'list'})),
    path('list', SoftwareSecurityScanViewSet.as_view({'get': 'list'})),
    path('all', SoftwareSecurityScanViewSet.as_view({'get': 'list'})),
    path('get/<str:ref_id>', SoftwareSecurityScanViewSet.as_view({'get': 'retrieve'})),
    path('stopScan/<str:ref_id>', SoftwareSecurityScanViewSet.as_view({'get': 'stopScan'})),
    path('download/<str:ref_id>', SoftwareSecurityScanViewSet.as_view({'get': 'download'})),
    path('get/pdf/<str:ref_id>', SoftwareSecurityScanViewSet.as_view({'get': 'retrieve_pdf'})),
    path('download/pdf/<str:ref_id>', SoftwareSecurityScanViewSet.as_view({'get': 'download_pdf'})),
    path('sbom', SoftwareSecurityScanViewSet.as_view({'post': 'generate_sbom'})),
    path('vex', SoftwareSecurityScanViewSet.as_view({'post': 'generate_vex'})),
    path('license', SoftwareSecurityScanViewSet.as_view({'post': 'generate_license'})),

    path('sign', SoftwareSecuritySignViewSet.as_view({'post': 'sign'})),
    path('signStatus/<str:ref_id>', SoftwareSecuritySignViewSet.as_view({'get': 'retrieve'})),
    path('signHistory', SoftwareSecuritySignViewSet.as_view({'get': 'list'})),
    path('cleanupSignHistory', SoftwareSecuritySignViewSet.as_view({'get': 'cleanup_database'})),

    path('cleanupDatabase', SoftwareSecurityScanViewSet.as_view({'get': 'cleanup_database'}))
    # path("<string:ref_id>/", views.retrieve_rec, name="result"),
]
