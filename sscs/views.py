from django.shortcuts import render
from rest_framework import viewsets
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.response import Response
from virtualenv.util.subprocess import run_cmd

from .models import SoftwareSecurityScan
from .serializers import SoftwareSecurityScanSerializer
import uuid
from django.http import QueryDict
# from django.http import FileResponse
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
import os
import subprocess
import multiprocessing


def runcmd(cmd):
    subprocess.call(cmd, shell=True)

class SoftwareSecurityScanViewSet(viewsets.ModelViewSet):
    queryset = SoftwareSecurityScan.objects.all()
    serializer_class = SoftwareSecurityScanSerializer

    def list(self, request):
        queryset = SoftwareSecurityScan.objects.all()
        serializer = SoftwareSecurityScanSerializer(queryset, many=True)
        return Response(serializer.data)

    def create(self, request):
        print("Software scan post request recived")
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        pk = serializer.data['id']
        queryset = SoftwareSecurityScan.objects.all()
        scan_rec = get_object_or_404(queryset, pk=pk)

        ref_id = request.data.__getitem__('type') + "_" + request.data.__getitem__('name') + "_" + str(uuid.uuid4())
        scan_rec.ref_id = ref_id
        scan_rec.save()
        # invoke the scan
        scan_type = request.data.__getitem__('type')
        file_name = request.data.__getitem__('name')
        file_path = request.data.__getitem__('location').replace("\\", "/")
        scan_level = request.data.__getitem__('level')
        file_location = (file_path + "/" + file_name).replace("//", "/")
        match scan_type:
            case "binary":
                # invoke emba firmware/binary scanning
                print("Invoke binary scanning: " + file_location)
                emba_home = "/home/nijames-local/workspace/software-scanning/emba"
                cmd = "sudo ./emba"
                result_root = "/home/nijames-local/workspace/sodiacs-api/sscs/Scan/"
                result_dir = result_root + ref_id
                scan_profile = "/home/nijames-local/workspace/software-scanning/emba/scan-profiles/" + scan_level + "-scan.emba"
                full_cmd = "cd " + emba_home + "; " + cmd + " -l " + result_dir + " -f " + file_location + " -p " + scan_profile + " > " + result_root + ref_id + ".log; echo done > " + result_root + ref_id + ".done &"
                print("executing " + full_cmd)
                child_proc = multiprocessing.Process(target=runcmd, args=(full_cmd,))
                child_proc.start()
                # subprocess.call(full_cmd, shell=True)
                # subprocess.run(full_cmd)
                # os.system(full_cmd)
                return Response({'status': 'in progress', 'ref_id': ref_id})
            case "package":
                # invoke cve-bin-tool software package scanning
                print("Invoke package scanning: " + file_location)
                cmd = "cve-bin-tool"
                result_root = "/home/nijames-local/workspace/sodiacs-api/sscs/Scan/"
                result_dir = result_root
                scan_cmd = cmd + " " + file_location + " > " + result_dir + ref_id + ".txt"
                convert_cmd = "cat " + result_dir + "/" + ref_id + ".txt | terminal-to-html -preview > " + result_dir + ref_id + ".html"
                full_cmd = scan_cmd + "; " + convert_cmd + "; echo done > " + result_dir + ref_id + ".done &"
                print(full_cmd)
                child_proc = multiprocessing.Process(target=runcmd, args=(full_cmd,))
                child_proc.start()
                # subprocess.call(full_cmd, shell=True)
                return Response({'status': 'in progress', 'ref_id': ref_id})
            case _:
                return Response({'error': 'Invalid type, enter binary or package'}, status=404)

    def download(self, request, ref_id=None):
        print("Software scan result download request recived: ref_id = " + ref_id)
        # find file path by ref_id, return the result files if scan is complete
        scan_rec = SoftwareSecurityScan.objects.filter(ref_id=ref_id).first()
        scan_rec = SoftwareSecurityScan.objects.filter(ref_id=ref_id).first()
        if scan_rec is None:
            return Response({'Status': 'Not found'}, status=status.HTTP_400_BAD_REQUEST)
        elif  scan_rec.status != "done":
            print(scan_rec.status)
            return Response({'Status': 'In-progress'})
        else:
            result_root = "/home/nijames-local/workspace/sodiacs-api/sscs/Scan/"
            if scan_rec.type == "binary":
                result_file = ref_id + ".tar.gz"
            else:  #"package":
                result_file = ref_id + ".html"
            file_path = result_root + result_file
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

    def retrieve(self, request, ref_id=None):
        print("Software scan get request recived: ref_id = " + ref_id)
        # path_info = f"{request.META['PATH_INFO']}"
        # path_segs = path_info.split("/")
        # ref_id = path_segs[-2]
        scan_rec = SoftwareSecurityScan.objects.filter(ref_id=ref_id).first()
        if scan_rec is None:
            return Response({'Status': 'Not found'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            # update the scanning status
            result_root = "/home/nijames-local/workspace/sodiacs-api/sscs/Scan/"
            progress = ref_id + ".done"
            if os.path.exists(result_root + "/" + progress):
                scan_rec.status = "done"
                scan_rec.save()
                if scan_rec.type == "binary":
                    # create the gzipped tar file for download
                    if os.path.exists(result_root + "/" + ref_id + ".tar.gz"):
                        print("Zipped scan results " + result_root + "/" + ref_id + ".tar.gz exist.")
                    else:
                        zip_cmd = "tar -czvf " + result_root + ref_id + ".tar.gz " + result_root + ref_id + "/html-report"
                        child_proc = multiprocessing.Process(target=runcmd, args=(zip_cmd,))
                        child_proc.start()
                        # subprocess.call(zip_cmd, shell=True)
                        print("Zipped scan results " + result_root + "/" + ref_id + ".tar.gz created.")
                else:  # "package":
                    print("Package scan result is ready.")
            serializer = SoftwareSecurityScanSerializer(scan_rec)
            return Response(serializer.data)

    def update(self, request, pk=None):
        pass

    def partial_update(self, request, pk=None):
        pass

    def destroy(self, request, pk=None):
        pass
