from django.shortcuts import render
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from .models import SoftwareSecurityScan
from .serializers import SoftwareSecurityScanSerializer
import uuid
from django.http import QueryDict
# from django.http import FileResponse
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
import os

class SoftwareSecurityScanViewSet(viewsets.ModelViewSet):
	queryset = SoftwareSecurityScan.objects.all()
	serializer_class = SoftwareSecurityScanSerializer

	def list(self, request):
	    queryset = SoftwareSecurityScan.objects.all()
	    serializer = SoftwareSecurityScanSerializer(queryset, many=True)
	    return Response(serializer.data)

	def create(self, request):
	    print("Software scan request recived")
	    serializer = self.get_serializer(data=request.data)
	    serializer.is_valid(raise_exception=True)
	    self.perform_create(serializer)
	    pk = serializer.data['id']
	    queryset = SoftwareSecurityScan.objects.all()
	    scan_rec = get_object_or_404(queryset, pk=pk)

	    ref_id = request.data.__getitem__('type') + "_" + request.data.__getitem__('name') + "_" + str(uuid.uuid4())
	    scan_rec.note = ref_id
	    scan_rec.save()
	    # invoke the scan

	    return Response({'status': 'in progress', 'ref_id' : ref_id})

	def retrieve(self, request, pk=None):
	    print("Software scan get recived")
	    path_info = f"{request.META['PATH_INFO']}"
	    path_segs = path_info.split("/")
	    ref_id = path_segs[-2]
	    print(ref_id)
	    # find file path by ref_id, return the result files if scan is complete
	    file_path = '/home/nijames-local/workspace/sodiacs-api/sscs/static/cve_scan/cve-scan.html'
	    try:
	        with open(file_path, 'rb') as f:
	            response = HttpResponse(f, content_type='application/force-download')
	            response['Content-Disposition'] = 'attachment; filename="%s"' % os.path.basename(file_path)
	            # response = FileResponse(f)
	            # response['Content-Type'] = 'application/force-download'
	            # response['Content-Disposition'] = 'attachment; filename="%s"' % os.path.basename(file_path)
	            return response
	    except FileNotFoundError:
	        return Response({'error': 'Invalid reference ID'}, status=404)

	def retrieve1(self, request, pk=None):
	    print("Software scan get recived")
	    queryset = SoftwareSecurityScan.objects.all()
	    scan_rec = get_object_or_404(queryset, pk=pk)
	    serializer = SoftwareSecurityScanSerializer(scan_rec)
	    return Response(serializer.data)

	def update(self, request, pk=None):
	    pass

	def partial_update(self, request, pk=None):
	    pass

	def destroy(self, request, pk=None):
	    pass


