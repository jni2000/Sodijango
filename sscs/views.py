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
import signal
import shutil

# html to PDF conversion packages
# import pdfkit
# import aspose.words as aw
# from xhtml2pdf import pisa
from PyPDF2 import PdfMerger

def runcmd(cmd, scan_rec=None):
    p = subprocess.Popen(cmd, preexec_fn=os.setsid, shell=True)
    if scan_rec is not None:
        scan_rec.handler = os.getpgid(p.pid)
        scan_rec.save()
    p.wait()

def stopcmd(pid):
    print("Stop scanning: ", pid, os.getpgid(pid))
    os.killpg(os.getpgid(pid), signal.SIGTERM)


class SoftwareSecurityScanViewSet(viewsets.ModelViewSet):
    queryset = SoftwareSecurityScan.objects.all()
    serializer_class = SoftwareSecurityScanSerializer
    home_directory = os.environ['HOME']
    file_root = home_directory + "/workspace/sodiacs-api/sscs/Scan/Repository/"
    emba_home = home_directory + "/workspace/software-scanning/emba/"
    emba_profile_home = emba_home + "scan-profiles/"
    scancode_home = home_directory + "/workspace/software-scanning/scancode/"
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
        if scan_level == "" or scan_level is None:
            scan_level = "default"
        if file_path == "" and file_name == "":
            return Response({'error': 'Invalid file name or path'}, status=404)
        elif file_path == "":
            file_location = (self.file_root + file_name + "/softwarefiles").replace("//", "/")
            result_file_location = self.result_root + file_name
        elif file_name == "":
            file_location = (self.file_root + file_path + "/softwarefiles").replace("//", "/")
            result_file_location = self.result_root + file_path
        else:
            file_location = (self.file_root + file_path + "/" + file_name + "/softwarefiles").replace("//", "/")
            result_file_location = self.result_root + file_path + "/" + file_name
        # result_dir = result_file_location + "/" + ref_id
        match scan_type:
            case "binary":
                result_dir = result_file_location + "/binaryscan"
                for done_root, done_dirs, done_files in os.walk(result_file_location):
                    for done_file in done_files:
                        if done_file.endswith('.bin'):
                            old_scan = str(done_file).removesuffix('.bin')
                            # rename the existing scan result
                            rename_cmd = "mv " + result_file_location + "/" + scan_type + "scan " + result_file_location + "/" + old_scan
                            full_cmd = rename_cmd + "; rm " + result_file_location + "/" + done_file
                            subprocess.call(full_cmd, shell=True)
                            break
            case "package":
                result_dir = result_file_location + "/packagescan"
                for done_root, done_dirs, done_files in os.walk(result_file_location):
                    for done_file in done_files:
                        if done_file.endswith('.pkg'):
                            old_scan = str(done_file).removesuffix('.pkg')
                            # rename the existing scan result
                            rename_cmd = "mv " + result_file_location + "/" + scan_type + "scan " + result_file_location + "/" + old_scan
                            full_cmd = rename_cmd + "; rm " + result_file_location + "/" + done_file
                            subprocess.call(full_cmd, shell=True)
                            break
            case _:
                result_dir = result_file_location + "/" + ref_id
        '''
        if not os.path.exists(result_file_location):
            full_cmd = "mkdir " + result_file_location
            subprocess.call(full_cmd, shell=True)
        if not os.path.exists(result_dir):
            full_cmd = "mkdir " + result_dir
            subprocess.call(full_cmd, shell=True)
        else:
        '''
        if os.path.exists(result_dir):
            shutil.rmtree(result_dir)
        os.makedirs(result_dir, exist_ok=True)
        match scan_type:
            case "binary":
                # invoke emba firmware/binary scanning
                print("Invoke binary scanning: " + file_location)
                cmd = "sudo ./emba"
                emba_profile = self.emba_profile_home + scan_level + "-scan.emba"
                full_cmd = "cd " + self.emba_home + "; " + cmd + " -l " + result_dir + " -f " + file_location + " -p " + emba_profile + " > " + result_file_location + "/" + ref_id + ".log; echo done > " + result_file_location + "/" + ref_id + ".bin"
                print("executing " + full_cmd)
                child_proc = multiprocessing.Process(target=runcmd, args=(full_cmd,scan_rec))
                child_proc.start()
                return Response({'status': 'in-progress', 'ref_id': ref_id})
            case "package":
                # invoke cve-bin-tool software package scanning
                print("Invoke package scanning: " + file_location + " " + scan_level)
                match scan_level:
                    case "quick":
                        offline = "--offline "
                    case "full":
                        offline = ""
                    case "default":
                        offline = ""
                    case _:
                        offline = ""
                # cmd = "cve-bin-tool --offline -f json,html -o "
                cmd = "cve-bin-tool " + offline + "-f json,html -o "
                scan_cmd = cmd + result_dir + "/html-report/index " + file_location
                prepare_cmd = "mkdir " + result_dir + "/html-report; "
                # convert_cmd = "cat " + result_file_location + "/" + ref_id + ".log | terminal-to-html -preview > " + result_dir + "/html-report" + "/index.html"
                full_cmd = prepare_cmd + scan_cmd + "; echo done > " + result_file_location + "/" + ref_id + ".pkg"
                print(full_cmd)
                child_proc = multiprocessing.Process(target=runcmd, args=(full_cmd,scan_rec))
                child_proc.start()

                # subprocess.call(full_cmd, shell=True)
                return Response({'status': 'in-progress', 'ref_id': ref_id})
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
            return Response({'Status': 'in-progress'})
        else:
            if scan_rec.location == "" and scan_rec.name == "":
                return Response({'Status': 'Not found'}, status=status.HTTP_400_BAD_REQUEST)
            elif scan_rec.location == "":
                result_file_location = self.result_root + scan_rec.name
            elif scan_rec.name == "":
                result_file_location = self.result_root + scan_rec.location
            else:
                result_file_location = self.result_root + scan_rec.location + "/" + scan_rec.name
            match scan_rec.type:
                case "binary":
                    result_dir = result_file_location + "/binaryscan"
                    zip_dir = result_dir + "/download-zip"
                    result_file = "html-report.zip"
                    file_path = zip_dir + "/" + result_file
                case "package":
                    result_dir = result_file_location + "/packagescan"
                    zip_dir = result_dir + "/download-zip"
                    result_file = "html-report.zip"
                    file_path = zip_dir + "/" + result_file
                case "sbom_spdx":
                    result_dir = result_file_location + "/sbom_spdx/sbom-report"
                    result_file = "sbom_spdx.json"
                    file_path = result_dir + "/" + result_file
                case "sbom_cyclonedx":
                    result_dir = result_file_location + "/sbom_cyclonedx/sbom-report"
                    result_file = "sbom_cyclonedx.json"
                    file_path = result_dir + "/" + result_file
                case "vex_csaf":
                    result_dir = result_file_location + "/vex_csaf/vex-report"
                    result_file = "vex_csaf.json"
                    file_path = result_dir + "/" + result_file
                case "vex_cyclonedx":
                    result_dir = result_file_location + "/vex_cyclonedx/vex-report"
                    result_file = "vex_cyclonedx.json"
                    file_path = result_dir + "/" + result_file
                case "vex_openvex":
                    result_dir = result_file_location + "/vex_openvex/vex-report"
                    result_file = "vex_openvex.json"
                    file_path = result_dir + "/" + result_file
                case "license_json":
                    result_dir = result_file_location + "/license_json/license-report"
                    result_file = "licenses.json"
                    file_path = result_dir + "/" + result_file
                case _:
                    result_dir = result_file_location + "/" + ref_id
            
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
            if scan_rec.location == "" and scan_rec.name == "":
                return Response({'Status': 'Not found'}, status=status.HTTP_400_BAD_REQUEST)
            elif scan_rec.location == "":
                result_file_location = self.result_root + scan_rec.name
            elif scan_rec.name == "":
                result_file_location = self.result_root + scan_rec.location
            else:
                result_file_location = self.result_root + scan_rec.location + "/" + scan_rec.name
            match scan_rec.type:
                case "binary":
                    result_dir = result_file_location + "/binaryscan"
                    result_to_zip = "/clean-text"
                    progress = ref_id + ".bin"
                case "package":
                    result_dir = result_file_location + "/packagescan"
                    result_to_zip = "/html-report"
                    progress = ref_id + ".pkg"
                case "sbom_spdx":
                    result_dir = result_file_location + "/sbom_spdx"
                    progress = ref_id + ".sbom_spdx"
                case "sbom_cyclonedx":
                    result_dir = result_file_location + "/sbom_cyclonedx"
                    progress = ref_id + ".sbom_cyclonedx"
                case "vex_csaf":
                    result_dir = result_file_location + "/vex_csaf"
                    progress = ref_id + ".vex_csaf"
                case "vex_cyclonedx":
                    result_dir = result_file_location + "/vex_cyclonedx"
                    progress = ref_id + ".vex_cyclonedx"
                case "vex_openvex":
                    result_dir = result_file_location + "/vex_openvex"
                    progress = ref_id + ".vex_openvex"
                case "license_json":
                    result_dir = result_file_location + "/license_json"
                    progress = ref_id + ".license_json"
                case _:
                    result_dir = result_file_location + "/" + ref_id

            zip_dir = result_dir + "/download-zip"
            text_dir = result_dir + "/clean-text"

            if os.path.exists(result_file_location + "/" + progress):
                scan_rec.status = "done"
                scan_rec.save()
                if scan_rec.type == "binary" or scan_rec.type == "package":
                    # create the gzipped tar file for download
                    if os.path.exists(zip_dir + "/html-report.zip"):
                        print("Zipped scan results " + zip_dir + "/html-report.zip exist.")
                    else:
                        if scan_rec.type == "binary":
                            process_text_file_cmd = "cd " + result_dir + "; proc-emba-text; cd " + text_dir + "; emba-text2json.py > scan-results.json; "
                        else:
                            process_text_file_cmd = ""
                        # zip_cmd = "tar -czvf " + result_root + ref_id + ".tar.gz " + result_root + ref_id + "/html-report"
                        prepare_cmd = "mkdir " + zip_dir + "; "
                        # zip_cmd = "zip -r " + zip_dir + "/html-report.zip " + result_dir + "/html-report"
                        zip_cmd = "zip -r -j " + zip_dir + "/html-report.zip " + result_dir + result_to_zip
                        # zip_cmd = "zip -r -j " + zip_dir + "/html-report.zip " + result_dir + "/clean-text"
                        full_cmd = process_text_file_cmd + prepare_cmd + zip_cmd
                        print(full_cmd)
                        child_proc = multiprocessing.Process(target=runcmd, args=(full_cmd,))
                        child_proc.start()
                        print("Zipped scan results " + result_dir + "/html-report.zip created.")
            serializer = SoftwareSecurityScanSerializer(scan_rec)
            return Response(serializer.data)

    def stopScan(self, request, ref_id=None):
        print("Software scan stop request recived: ref_id = " + ref_id)
        return Response({'error': 'Not available'}, status=404)
        '''
        scan_rec = SoftwareSecurityScan.objects.filter(ref_id=ref_id).first()
        if scan_rec is None:
            return Response({'Status': 'Not found'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            # stop the scanning
            result_file_location = self.result_root + scan_rec.name
            #match scan_rec.type:
            #    case "binary":
            #        stop_cmd = "sudo emba-stop-scan; "
            #    case "package":
            #        stop_cmd = "sudo cve-bin-tool-stop-scan; "
            #    case _:
            #        stop_cmd =""
            #full_cmd = stop_cmd + "echo aborted > " + result_file_location + "/" + ref_id + ".aborted &"
            stopcmd(scan_rec.handler)
            full_cmd = "echo aborted > " + result_file_location + "/" + ref_id + ".done &"
            print(full_cmd)
            child_proc = multiprocessing.Process(target=runcmd, args=(full_cmd,))
            child_proc.start()
            print("Scan " + ref_id + " stopped!")
            scan_rec.status = "aborted"
            scan_rec.save()
            serializer = SoftwareSecurityScanSerializer(scan_rec)
            return Response(serializer.data)
        '''

    def retrieve_pdf(self, request, ref_id=None):
        print("Software scan get PDF request recived: ref_id = " + ref_id)
        return Response({'error': 'Not available'}, status=404)
        '''    
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
        '''

    def download_pdf(self, request, ref_id=None):
        print("Software scan download PDF request recived: ref_id = " + ref_id)
        return Response({'error': 'Not available'}, status=404)
        '''
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
        '''
    def generate_sbom(self, request, pk=None):
        print("Software SBOM generation request recived")
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        pk = serializer.data['id']
        queryset = SoftwareSecurityScan.objects.all()
        scan_rec = get_object_or_404(queryset, pk=pk)

        ref_id = request.data.__getitem__('type') + "_" + request.data.__getitem__('name') + "_sbom_" + str(uuid.uuid4())
        scan_rec.ref_id = ref_id
        # invoke the scan
        scan_type = request.data.__getitem__('type')
        file_name = request.data.__getitem__('name')
        file_path = request.data.__getitem__('location').replace("\\", "/")
        scan_level = request.data.__getitem__('level')
        if file_path == "" and file_name == "":
            return Response({'error': 'Invalid file name or path'}, status=404)
        elif file_path == "":
            file_location = (self.file_root + file_name + "/softwarefiles").replace("//", "/")
            result_file_location = self.result_root + file_name
        elif file_name == "":
            file_location = (self.file_root + file_path + "/softwarefiles").replace("//", "/")
            result_file_location = self.result_root + file_path
        else:
            file_location = (self.file_root + file_path + "/" + file_name + "/softwarefiles").replace("//", "/")
            result_file_location = self.result_root + file_path + "/" + file_name
        # result_dir = result_file_location + "/" + ref_id
        match scan_type:
            case "cyclonedx":
                result_dir = result_file_location + "/sbom_cyclonedx"
                for done_root, done_dirs, done_files in os.walk(result_file_location):
                    for done_file in done_files:
                        if done_file.endswith('.sbom_cyclonedx'):
                            old_scan = str(done_file).removesuffix('.sbom_cyclonedx')
                            # rename the existing scan result
                            rename_cmd = "mv " + result_file_location + "/sbom_" + scan_type + " " + result_file_location + "/" + old_scan
                            full_cmd = rename_cmd + "; rm " + result_file_location + "/" + done_file
                            subprocess.call(full_cmd, shell=True)
                            break
            case "spdx":
                result_dir = result_file_location + "/sbom_spdx"
                for done_root, done_dirs, done_files in os.walk(result_file_location):
                    for done_file in done_files:
                        if done_file.endswith('.sbom_spdx'):
                            old_scan = str(done_file).removesuffix('.sbom_spdx')
                            # rename the existing scan result
                            rename_cmd = "mv " + result_file_location + "/sbom_" + scan_type + " " + result_file_location + "/" + old_scan
                            full_cmd = rename_cmd + "; rm " + result_file_location + "/" + done_file
                            subprocess.call(full_cmd, shell=True)
                            break
            case _:
                scan_type = "cyclonedx"
                result_dir = result_file_location + "/sbom_cyclonedx"
                for done_root, done_dirs, done_files in os.walk(result_file_location):
                    for done_file in done_files:
                        if done_file.endswith('.sbom_cyclonedx'):
                            old_scan = str(done_file).removesuffix('.sbom_cyclonedx')
                            # rename the existing scan result
                            rename_cmd = "mv " + result_file_location + "/sbom_" + scan_type + " " + result_file_location + "/" + old_scan
                            full_cmd = rename_cmd + "; rm " + result_file_location + "/" + done_file
                            subprocess.call(full_cmd, shell=True)
                            break
        scan_rec.type = "sbom_" + scan_type
        scan_rec.save()

        '''
        if not os.path.exists(result_file_location):
            full_cmd = "mkdir " + result_file_location
            subprocess.call(full_cmd, shell=True)
        if not os.path.exists(result_dir):
            full_cmd = "mkdir " + result_dir
            subprocess.call(full_cmd, shell=True)
        else:
        '''
        if os.path.exists(result_dir):
            shutil.rmtree(result_dir)
        os.makedirs(result_dir, exist_ok=True)
        match scan_type:
            case "cyclonedx":
                # invoke emba firmware/binary scanning
                print("Build CycloneDX SBOM: " + file_location)
                # cmd = "cve-bin-tool --offline --sbom-type cyclonedx --sbom-format json --sbom-output " + result_dir + "/sbom-report/sbom_cyclonedx.json "
                cmd = "cve-bin-tool --sbom-type cyclonedx --sbom-format json --sbom-output " + result_dir + "/sbom-report/sbom_cyclonedx.json "
                scan_cmd = cmd + file_location
                prepare_cmd = "mkdir " + result_dir + "/sbom-report; "
                full_cmd = prepare_cmd + scan_cmd + "; echo done > " + result_file_location + "/" + ref_id + ".sbom_cyclonedx"
                print(full_cmd)
                child_proc = multiprocessing.Process(target=runcmd, args=(full_cmd, scan_rec))
                child_proc.start()

                # subprocess.call(full_cmd, shell=True)
                return Response({'status': 'in-progress', 'ref_id': ref_id})
            case "spdx":
                print("Build SPDX SBOM: " + file_location)
                # cmd = "cve-bin-tool --offline --sbom-type spdx --sbom-format json --sbom-output " + result_dir + "/sbom-report/sbom_spdx.json "
                cmd = "cve-bin-tool --sbom-type spdx --sbom-format json --sbom-output " + result_dir + "/sbom-report/sbom_spdx.json "
                scan_cmd = cmd + file_location
                prepare_cmd = "mkdir " + result_dir + "/sbom-report; "
                full_cmd = prepare_cmd + scan_cmd + "; echo done > " + result_file_location + "/" + ref_id + ".sbom_spdx"
                print(full_cmd)
                child_proc = multiprocessing.Process(target=runcmd, args=(full_cmd,scan_rec))
                child_proc.start()

                # subprocess.call(full_cmd, shell=True)
                return Response({'status': 'in-progress', 'ref_id': ref_id})
            case _:
                return Response({'error': 'Invalid type, enter binary or package'}, status=404)

    def generate_vex(self, request, pk=None):
        print("Software VEX generation request recived")
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        pk = serializer.data['id']
        queryset = SoftwareSecurityScan.objects.all()
        scan_rec = get_object_or_404(queryset, pk=pk)

        ref_id = request.data.__getitem__('type') + "_" + request.data.__getitem__('name') + "_vex_" + str(uuid.uuid4())
        scan_rec.ref_id = ref_id
        # invoke the scan
        scan_type = request.data.__getitem__('type')
        file_name = request.data.__getitem__('name')
        file_path = request.data.__getitem__('location').replace("\\", "/")
        scan_level = request.data.__getitem__('level')
        file_product = request.data.__getitem__('product')
        file_release = request.data.__getitem__('release')
        file_vendor = request.data.__getitem__('vendor')
        file_revision_reason = request.data.__getitem__('revision_reason')
        print(file_product, file_release, file_vendor, file_revision_reason)
        if file_path == "" and file_name == "":
            return Response({'error': 'Invalid file name or path'}, status=404)
        elif file_path == "":
            file_location = (self.file_root + file_name + "/softwarefiles").replace("//", "/")
            result_file_location = self.result_root + file_name
        elif file_name == "":
            file_location = (self.file_root + file_path + "/softwarefiles").replace("//", "/")
            result_file_location = self.result_root + file_path
        else:
            file_location = (self.file_root + file_path + "/" + file_name + "/softwarefiles").replace("//", "/")
            result_file_location = self.result_root + file_path + "/" + file_name
        # result_dir = result_file_location + "/" + ref_id
        if file_product == "" or file_release == "" or file_vendor == "" or file_revision_reason == "":
            return Response({'error': 'Product, release, vendor, revision reason must be specified.'}, status=404)
        match scan_type:
            case "cyclonedx":
                result_dir = result_file_location + "/vex_cyclonedx"
                for done_root, done_dirs, done_files in os.walk(result_file_location):
                    for done_file in done_files:
                        if done_file.endswith('.vex_cyclonedx'):
                            old_scan = str(done_file).removesuffix('.vex_cyclonedx')
                            # rename the existing scan result
                            rename_cmd = "mv " + result_file_location + "/vex_" + scan_type + " " + result_file_location + "/" + old_scan
                            full_cmd = rename_cmd + "; rm " + result_file_location + "/" + done_file
                            subprocess.call(full_cmd, shell=True)
                            break
            case "csaf":
                result_dir = result_file_location + "/vex_csaf"
                for done_root, done_dirs, done_files in os.walk(result_file_location):
                    for done_file in done_files:
                        if done_file.endswith('.vex_csaf'):
                            old_scan = str(done_file).removesuffix('.vex_csaf')
                            # rename the existing scan result
                            rename_cmd = "mv " + result_file_location + "/vex_" + scan_type + " " + result_file_location + "/" + old_scan
                            full_cmd = rename_cmd + "; rm " + result_file_location + "/" + done_file
                            subprocess.call(full_cmd, shell=True)
                            break
            case "openvex":
                result_dir = result_file_location + "/vex_openvex"
                for done_root, done_dirs, done_files in os.walk(result_file_location):
                    for done_file in done_files:
                        if done_file.endswith('.vex_openvex'):
                            old_scan = str(done_file).removesuffix('.vex_openvex')
                            # rename the existing scan result
                            rename_cmd = "mv " + result_file_location + "/vex_" + scan_type + " " + result_file_location + "/" + old_scan
                            full_cmd = rename_cmd + "; rm " + result_file_location + "/" + done_file
                            subprocess.call(full_cmd, shell=True)
                            break
            case _:
                scan_type = "cyclonedx"
                result_dir = result_file_location + "/vex_cyclonedx"
                for done_root, done_dirs, done_files in os.walk(result_file_location):
                    for done_file in done_files:
                        if done_file.endswith('.vex_cyclonedx'):
                            old_scan = str(done_file).removesuffix('.vex_cyclonedx')
                            # rename the existing scan result
                            rename_cmd = "mv " + result_file_location + "/vex_" + scan_type + " " + result_file_location + "/" + old_scan
                            full_cmd = rename_cmd + "; rm " + result_file_location + "/" + done_file
                            subprocess.call(full_cmd, shell=True)
                            break
        scan_rec.type = "vex_" + scan_type
        scan_rec.save()

        '''
        if not os.path.exists(result_file_location):
            full_cmd = "mkdir " + result_file_location
            subprocess.call(full_cmd, shell=True)
        if not os.path.exists(result_dir):
            full_cmd = "mkdir " + result_dir
            subprocess.call(full_cmd, shell=True)
        else:
        '''
        if os.path.exists(result_dir):
            shutil.rmtree(result_dir)
        os.makedirs(result_dir, exist_ok=True)
        match scan_type:
            case "cyclonedx":
                # invoke emba firmware/binary scanning
                print("Build CycloneDX VEX: " + file_location)
                # cmd = "cve-bin-tool --offline --vex-type cyclonedx " + "--product " + file_product + " --release " + file_release + " --vendor " + file_vendor + " --revision-reason " + file_revision_reason + " --vex-output " + result_dir + "/vex-report/vex_cyclonedx.json "
                cmd = "cve-bin-tool --vex-type cyclonedx " + "--product " + file_product + " --release " + file_release + " --vendor " + file_vendor + " --revision-reason " + file_revision_reason + " --vex-output " + result_dir + "/vex-report/vex_cyclonedx.json "
                scan_cmd = cmd + file_location
                prepare_cmd = "mkdir " + result_dir + "/vex-report; "
                full_cmd = prepare_cmd + scan_cmd + "; echo done > " + result_file_location + "/" + ref_id + ".vex_cyclonedx"
                print(full_cmd)
                child_proc = multiprocessing.Process(target=runcmd, args=(full_cmd, scan_rec))
                child_proc.start()

                # subprocess.call(full_cmd, shell=True)
                return Response({'status': 'in-progress', 'ref_id': ref_id})
            case "csaf":
                print("Build CSAF VEX: " + file_location)
                # cmd = "cve-bin-tool --offline --vex-type csaf " + "--product " + file_product + " --release " + file_release + " --vendor " + file_vendor + " --revision-reason " + file_revision_reason + " --vex-output " + result_dir + "/vex-report/vex_csaf.json "
                cmd = "cve-bin-tool --vex-type csaf " + "--product " + file_product + " --release " + file_release + " --vendor " + file_vendor + " --revision-reason " + file_revision_reason + " --vex-output " + result_dir + "/vex-report/vex_csaf.json "
                scan_cmd = cmd + file_location
                prepare_cmd = "mkdir " + result_dir + "/vex-report; "
                full_cmd = prepare_cmd + scan_cmd + "; echo done > " + result_file_location + "/" + ref_id + ".vex_csaf"
                print(full_cmd)
                child_proc = multiprocessing.Process(target=runcmd, args=(full_cmd,scan_rec))
                child_proc.start()

                # subprocess.call(full_cmd, shell=True)
                return Response({'status': 'in-progress', 'ref_id': ref_id})
            case "openvex":
                print("Build OpenVEX VEX: " + file_location)
                # cmd = "cve-bin-tool --offline --vex-type openvex " + "--product " + file_product + " --release " + file_release + " --vendor " + file_vendor + " --revision-reason " + file_revision_reason + " --vex-output " + result_dir + "/vex-report/vex_openvex.json "
                cmd = "cve-bin-tool --vex-type openvex " + "--product " + file_product + " --release " + file_release + " --vendor " + file_vendor + " --revision-reason " + file_revision_reason + " --vex-output " + result_dir + "/vex-report/vex_openvex.json "
                scan_cmd = cmd + file_location
                prepare_cmd = "mkdir " + result_dir + "/vex-report; "
                full_cmd = prepare_cmd + scan_cmd + "; echo done > " + result_file_location + "/" + ref_id + ".vex_openvex"
                print(full_cmd)
                child_proc = multiprocessing.Process(target=runcmd, args=(full_cmd,scan_rec))
                child_proc.start()

                # subprocess.call(full_cmd, shell=True)
                return Response({'status': 'in-progress', 'ref_id': ref_id})
            case _:
                return Response({'error': 'Invalid type, enter binary or package'}, status=404)

    def generate_license(self, request, pk=None):
        print("Software license generation request recived")
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        pk = serializer.data['id']
        queryset = SoftwareSecurityScan.objects.all()
        scan_rec = get_object_or_404(queryset, pk=pk)

        ref_id = request.data.__getitem__('type') + "_" + request.data.__getitem__('name') + "_license_" + str(uuid.uuid4())
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
            result_file_location = self.result_root + file_name
        elif file_name == "":
            file_location = (self.file_root + file_path + "/softwarefiles").replace("//", "/")
            result_file_location = self.result_root + file_path
        else:
            file_location = (self.file_root + file_path + "/" + file_name + "/softwarefiles").replace("//", "/")
            result_file_location = self.result_root + file_path + "/" + file_name
        # result_dir = result_file_location + "/" + ref_id
        match scan_type:
            case "json":
                result_dir = result_file_location + "/license_json"
                for done_root, done_dirs, done_files in os.walk(result_file_location):
                    for done_file in done_files:
                        if done_file.endswith('.license_json'):
                            old_scan = str(done_file).removesuffix('.license_json')
                            # rename the existing scan result
                            rename_cmd = "mv " + result_file_location + "/license_" + scan_type + " " + result_file_location + "/" + old_scan
                            full_cmd = rename_cmd + "; rm " + result_file_location + "/" + done_file
                            subprocess.call(full_cmd, shell=True)
                            break
            case _:
                scan_type = "json"
                result_dir = result_file_location + "/license_json"
                for done_root, done_dirs, done_files in os.walk(result_file_location):
                    for done_file in done_files:
                        if done_file.endswith('.license_json'):
                            old_scan = str(done_file).removesuffix('.license_json')
                            # rename the existing scan result
                            rename_cmd = "mv " + result_file_location + "/" + scan_type + " " + result_file_location + "/" + old_scan
                            full_cmd = rename_cmd + "; rm " + result_file_location + "/" + done_file
                            subprocess.call(full_cmd, shell=True)
                            break
        scan_rec.type = "license_" + scan_type
        scan_rec.save()

        '''
        if not os.path.exists(result_file_location):
            full_cmd = "mkdir " + result_file_location
            subprocess.call(full_cmd, shell=True)
        if not os.path.exists(result_dir):
            full_cmd = "mkdir " + result_dir
            subprocess.call(full_cmd, shell=True)
        else:
        '''
        if os.path.exists(result_dir):
            shutil.rmtree(result_dir)
        os.makedirs(result_dir, exist_ok=True)
        match scan_type:
            case "json":
                # invoke emba firmware/binary scanning
                print("Build JSON software license document: " + file_location)
                cmd = "./scancode -clpeui -n 2 --json-pp " + result_dir + "/license-report/licenses.json "
                scan_cmd = "cd " + self.scancode_home + "; " + cmd + file_location
                prepare_cmd = "mkdir " + result_dir + "/license-report; "
                full_cmd = prepare_cmd + scan_cmd + "; echo done > " + result_file_location + "/" + ref_id + ".license_json"
                print(full_cmd)
                child_proc = multiprocessing.Process(target=runcmd, args=(full_cmd, scan_rec))
                child_proc.start()

                # subprocess.call(full_cmd, shell=True)
                return Response({'status': 'in-progress', 'ref_id': ref_id})
            case _:
                return Response({'error': 'Invalid type, enter binary or package'}, status=404)

    def update(self, request, pk=None):
        pass

    def partial_update(self, request, pk=None):
        pass

    def destroy(self, request, pk=None):
        pass
