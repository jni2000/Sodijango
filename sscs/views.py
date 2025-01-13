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

# html to PDF conversion packages
# import pdfkit
# import aspose.words as aw
# from xhtml2pdf import pisa
from PyPDF2 import PdfMerger

def runcmd(cmd):
    subprocess.call(cmd, shell=True)


class SoftwareSecurityScanViewSet(viewsets.ModelViewSet):
    queryset = SoftwareSecurityScan.objects.all()
    serializer_class = SoftwareSecurityScanSerializer
    home_directory = os.environ['HOME']
    file_root = home_directory + "/workspace/sodiacs-api/sscs/Scan/Repository/"
    emba_home = home_directory + "/workspace/software-scanning/emba/"
    emba_profile_home = emba_home + "scan-profiles/"
    result_root = home_directory + "/workspace/sodiacs-api/sscs/Scan/Results/"

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
        if file_path == "" and file_name == "":
            return Response({'error': 'Invalid file name or path'}, status=404)
        elif file_path == "":
            file_location = (self.file_root + file_name + "/softwarefiles").replace("//", "/")
        elif file_name == "":
            file_location = (self.file_root + file_path + "/softwarefiles").replace("//", "/")
        else:
            file_location = (self.file_root + file_path + "/" + file_name + "/softwarefiles").replace("//", "/")
        result_file_location = self.result_root + file_name
        # result_dir = result_file_location + "/" + ref_id
        match scan_type:
            case "binary":
                result_dir = result_file_location + "/binaryscan"
            case "package":
                result_dir = result_file_location + "/packagescan"
            case _:
                result_dir = result_file_location + "/" + ref_id

        if not os.path.exists(result_file_location):
            full_cmd = "mkdir " + result_file_location
            subprocess.call(full_cmd, shell=True)
        if not os.path.exists(result_dir):
            full_cmd = "mkdir " + result_dir
            subprocess.call(full_cmd, shell=True)
        match scan_type:
            case "binary":
                # invoke emba firmware/binary scanning
                print("Invoke binary scanning: " + file_location)
                cmd = "sudo ./emba"
                emba_profile = self.emba_profile_home + scan_level + "-scan.emba"
                full_cmd = "cd " + self.emba_home + "; " + cmd + " -l " + result_dir + " -f " + file_location + " -p " + emba_profile + " > " + result_file_location + "/" + ref_id + ".log; echo done > " + result_file_location + "/" + ref_id + ".done &"
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
                cmd = "cve-bin-tool --offline -f html -o "
                scan_cmd = cmd + result_dir + "/html-report/index.html " + file_location
                prepare_cmd = "mkdir " + result_dir + "/html-report; "
                # convert_cmd = "cat " + result_file_location + "/" + ref_id + ".log | terminal-to-html -preview > " + result_dir + "/html-report" + "/index.html"
                full_cmd = prepare_cmd + scan_cmd + "; echo done > " + result_file_location + "/" + ref_id + ".done &"
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
        if scan_rec is None:
            print("Scan record not found!!")
            return Response({'Status': 'Not found'}, status=status.HTTP_400_BAD_REQUEST)
        elif scan_rec.status != "done":
            print(scan_rec.status)
            return Response({'Status': 'In-progress'})
        else:
            result_file_location = self.result_root + scan_rec.name
            match scan_rec.type:
                case "binary":
                    result_dir = result_file_location + "/binaryscan"
                case "package":
                    result_dir = result_file_location + "/packagescan"
                case _:
                    result_dir = result_file_location + "/" + ref_id
            
            zip_dir = result_dir + "/download-zip"
            result_file = ref_id + ".7z"
            file_path = zip_dir + "/" + result_file
            print("Download " + file_path)
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
            result_file_location = self.result_root + scan_rec.name 
            match scan_rec.type:
                case "binary":
                    result_dir = result_file_location + "/binaryscan"
                case "package":
                    result_dir = result_file_location + "/packagescan"
                case _:
                    result_dir = result_file_location + "/" + ref_id
            zip_dir = result_dir + "/download-zip"

            # update the scanning status
            result_file_location = self.result_root + scan_rec.name
            progress = ref_id + ".done"
            if os.path.exists(result_file_location + "/" + progress):
                scan_rec.status = "done"
                scan_rec.save()
                # create the gzipped tar file for download
                if os.path.exists(zip_dir + "/" + ref_id + ".7z"):
                    print("Zipped scan results " + zip_dir + "/" + ref_id + ".7z exist.")
                else:
                    # zip_cmd = "tar -czvf " + result_root + ref_id + ".tar.gz " + result_root + ref_id + "/html-report"
                    prepare_cmd = "mkdir " + zip_dir + "; "
                    zip_cmd = "7z a " + zip_dir + "/" + ref_id + ".7z " + result_dir + "/html-report"
                    full_cmd = prepare_cmd + zip_cmd
                    child_proc = multiprocessing.Process(target=runcmd, args=(full_cmd,))
                    child_proc.start()
                    print("Zipped scan results " + result_dir + "/" + ref_id + ".7z created.")

            serializer = SoftwareSecurityScanSerializer(scan_rec)
            return Response(serializer.data)

    def retrieve_pdf(self, request, ref_id=None):
        print("Software scan get PDF request recived: ref_id = " + ref_id)
        # path_info = f"{request.META['PATH_INFO']}"
        # path_segs = path_info.split("/")
        # ref_id = path_segs[-2]
        scan_rec = SoftwareSecurityScan.objects.filter(ref_id=ref_id).first()
        if scan_rec is None:
            return Response({'Status': 'Not found'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            # update the scanning status
            result_file_location = self.result_root + scan_rec.name
            match scan_rec.type:
                case "binary":
                    result_dir = result_file_location + "/binaryscan"
                case "package":
                    result_dir = result_file_location + "/packagescan"
                case _:
                    result_dir = result_file_location + "/" + ref_id
            progress = ref_id + ".done"
            if os.path.exists(result_file_location + "/" + progress):
                scan_rec.status = "done"
                scan_rec.save()
                if os.path.exists(result_dir + "/" + ref_id + ".pdf"):
                    print("PDF of results " + result_dir + "/" + ref_id + ".pdf exist.")
                    return Response({'Status': 'done'}, status=status.HTTP_200_OK)
                else:
                    html_count = 0
                    pdf_count = 0
                    result_path = result_dir + "/html-report/"
                    for x in os.listdir(result_path):
                        if x.endswith(".html"):
                            html_count +=1
                        if x.endswith(".pdf"):
                            pdf_count +=1
                    if html_count == pdf_count:
                        return Response({'Status': 'done'}, status=status.HTTP_200_OK)
                    else:
                        for x in os.listdir(result_path):
                            if x.endswith(".html"):
                                y = x.split('.')
                                pdf = result_path + y[0] + ".pdf"
                                convert_cmd = "weasyprint " + result_path + x + " " + pdf
                                print("Executing: " + convert_cmd)
                                child_proc = multiprocessing.Process(target=runcmd, args=(convert_cmd,))
                                child_proc.start()
                        return Response({'Status': 'in-progress'}, status=status.HTTP_200_OK)
            serializer = SoftwareSecurityScanSerializer(scan_rec)
            return Response(serializer.data)

    def download_pdf(self, request, ref_id=None):
        print("Software scan download PDF request recived: ref_id = " + ref_id)
        # path_info = f"{request.META['PATH_INFO']}"
        # path_segs = path_info.split("/")
        # ref_id = path_segs[-2]
        scan_rec = SoftwareSecurityScan.objects.filter(ref_id=ref_id).first()
        if scan_rec is None:
            return Response({'Status': 'Not found'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            result_file_location = self.result_root + scan_rec.name
            match scan_rec.type:
                case "binary":
                    result_dir = result_file_location + "/binaryscan"
                case "package":
                    result_dir = result_file_location + "/packagescan"
                case _:
                    result_dir = result_file_location + "/" + ref_id
            # update the scanning status
            progress = ref_id + ".done"
            if os.path.exists(result_file_location + "/" + progress):
                scan_rec.status = "done"
                scan_rec.save()
                result_pdf = result_dir + "/" + ref_id + ".pdf"
                if os.path.exists(result_pdf):
                    print("PDF of results " + result_dir + "/" + ref_id + ".pdf exist.")
                    # down load logic
                    print("Download " + result_pdf)
                    try:
                        with open(result_pdf, 'rb') as f:
                            response = HttpResponse(f, content_type='application/force-download')
                            response['Content-Disposition'] = 'attachment; filename="%s"' % os.path.basename(
                                result_pdf)
                            # response = FileResponse(f)
                            # response['Content-Type'] = 'application/force-download'
                            # response['Content-Disposition'] = 'attachment; filename="%s"' % os.path.basename(file_path)
                            return response
                    except:
                        return Response({'Status': 'in-progress'}, status=status.HTTP_200_OK)
                else:
                    html_count = 0
                    pdf_count = 0
                    result_path = result_dir + "/html-report/"
                    for x in os.listdir(result_path):
                        if x.endswith(".html"):
                            html_count +=1
                        if x.endswith(".pdf"):
                            pdf_count +=1
                    if html_count == pdf_count:
                        result_files = []
                        if scan_rec.type == "binary":
                            result_files.append(result_path + "emba.pdf")
                        result_files.append(result_path + "index.pdf")
                        for x in os.listdir(result_path):
                            if x.endswith(".pdf"):
                                pdf = result_path + x
                                if (x != "emba.pdf") and (x != "index.pdf"):
                                    result_files.append(pdf)
                        if result_files:
                            # build the final PDF
                            # print(result_files)
                            merger = PdfMerger()
                            for pdf_file in result_files:
                                merger.append(open(pdf_file, 'rb'))
                            with open(result_pdf, 'wb') as fout:
                                merger.write(fout)
                            # down load logic
                            print("Download " + result_pdf)
                            try:
                                with open(result_pdf, 'rb') as f:
                                    response = HttpResponse(f, content_type='application/force-download')
                                    response['Content-Disposition'] = 'attachment; filename="%s"' % os.path.basename(
                                        result_pdf)
                                    # response = FileResponse(f)
                                    # response['Content-Type'] = 'application/force-download'
                                    # response['Content-Disposition'] = 'attachment; filename="%s"' % os.path.basename(file_path)
                                    return response
                            except:
                                return Response({'Status': 'in-progress'}, status=status.HTTP_200_OK)
                        else:
                            return Response({'Status': 'not-available'}, status=status.HTTP_204_NO_CONTENT)
                    else:
                        return Response({'Status': 'in-progress'}, status=status.HTTP_200_OK)
            serializer = SoftwareSecurityScanSerializer(scan_rec)
            return Response(serializer.data)

    def update(self, request, pk=None):
        pass

    def partial_update(self, request, pk=None):
        pass

    def destroy(self, request, pk=None):
        pass
