from rest_framework import serializers
from .models import SoftwareSecurityScan
from .models import SoftwareSecuritySign

class SoftwareSecurityScanSerializer(serializers.ModelSerializer):
    class Meta:
        model = SoftwareSecurityScan
        fields = ['id', 'date', 'type', 'name', 'location', 'level', 'note', 'status', 'ref_id', 'handler', 'product', 'release', 'vendor', 'revision_reason']

class SoftwareSecuritySignSerializer(serializers.ModelSerializer):
    class Meta:
        model = SoftwareSecuritySign
        fields = ['id', 'date', 'type', 'name', 'data', 'note', 'status', 'ref_id', 'sha', 'sha_type', 'signature']

