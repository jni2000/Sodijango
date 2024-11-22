from rest_framework import serializers
from .models import SoftwareSecurityScan

class SoftwareSecurityScanSerializer(serializers.ModelSerializer):
    class Meta:
        model = SoftwareSecurityScan
        fields = ['id', 'date', 'type', 'name', 'location', 'note']
