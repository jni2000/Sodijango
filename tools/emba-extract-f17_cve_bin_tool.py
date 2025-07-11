#!/usr/bin/python3

import os, io, json, copy, re, sys
from typing import List, Optional
from dataclasses import dataclass
from bs4 import BeautifulSoup
from hamcrest import empty
from landscape.lib.apt.package.store import ensure_hash_id_schema

@dataclass
class Exploit:
    def __init__(self, desc: str, eid: str = None, lnk: str = None):
        self.description = desc
        self.id = eid
        self.link = lnk

@dataclass
class Find:
    def __init__(self, desc: str, modul: str, ver: str, cve: str, cvss: str, epss: str, lvl: str, src: str, lnk: str, lnk_tag: str, explts: Optional[List[Exploit]] = None):
        self.description = desc
        self.module = modul
        self.version = ver
        self.cve_id = cve
        self.cvss_score = cvss
        self.epss_score = epss
        self.severity = lvl
        self.method = src
        self.exploits = explts or []
        self.cve_link = lnk
        self.cve_link_tag = lnk_tag
        self.exploit_count = len(self.exploits) or 0

    def append(self, exploit: Optional[Exploit] = None):
        if exploit is not None:
            self.exploits.append(exploit)
            self.exploit_count += 1

    def reset(self):
        self.exploits = []
        self.count = 0

    def count(self):
        return self.exploit_count

@dataclass
class Subsec:
    def __init__(self, desc: str, cncl: str = "", finds: Optional[List[Find]] = None):
        self.description = desc
        self.conclusion = cncl
        self.finds = finds or []
        self.find_count = len(self.finds) or 0

    def append(self, find: Optional[Find] = None):
        if find is not None:
            self.finds.append(find)
            self.find_count += 1

    def reset(self):
        self.finds = []
        self.find_count = 0

    def count(self):
        return self.find_count


@dataclass
class Section:
    def __init__(self, desc: str, subsecs: Optional[List[Subsec]] = None, nt: str = ""):
        self.description = desc
        self.subsections = subsecs or []
        self.subsection_count = len(self.subsections) or 0
        self.note = nt

    def append(self, subsec: Optional[Subsec] = None):
        if subsec is not None:
            self.subsections.append(subsec)
            self.subsection_count += 1

    def reset(self):
        self.subsections = []
        self.subsection_count = 0

    def count(self):
        return self.subsection_count


@dataclass
class Sections:
    def __init__(self, secs: Optional[List[Section]] = None):
        self.sections = secs or []
        self.section_count = len(self.sections) or 0

    def append(self, sec: Optional[Section] = None):
        if sec is not None:
            self.sections.append(sec)
            self.section_count += 1

    def reset(self):
        self.sections = []
        self.section_count = 0

    def count(self):
        return self.section_count

def Parse_exploits(parts):
    exploits = []
    if parts is not empty():
        count = 9
        while count < len(parts)-1:
            eid = parts[count].replace(")", "")
            count += 1
            elnk = parts[count].replace(")", "")
            count += 1
            # print("Exploit, " + eid +", " + elnk)
            exploit = Exploit("Exploit", eid, elnk)
            exploits.append(copy.deepcopy(exploit))
    return exploits

def parse_finding(line):
    find = None
    if line is not empty():
        parts = line.split(" : ")
        if parts is not empty():
            modul = parts[0]
            ver = parts[1]
            cve = parts[2]
            cvss = parts[3]
            severity_string = cvss.split()
            severity = float(severity_string[0])
            if severity >= 9.0:
                lvl = "critical"
            elif severity >= 7.0:
                lvl = "high"
            elif severity >= 4.0:
                lvl = "medium"
            elif severity >= 0.1:
                lvl = "low"
            else:
                lvl = "none"

            epss = parts[4]
            src = parts[5]
            exploits = []
            if "No exploit available" in parts[6]:
                exploit = Exploit(parts[6])
                exploits.append(copy.deepcopy(exploit))
            else:
                exploits = Parse_exploits(parts)
            if parts[7] and parts[8]:
                lnk = parts[8]
                lnk_tag = parts[7]
            find = Find("Finding details", modul, ver, cve, cvss, epss, lvl, src, lnk, lnk_tag, exploits)
    return find

def main():
    section_delimiter = "==> "
    subsection_delimiter  = "[*] "
    conclusion_delimiter  = "[+]"
    finding_delimiter = "BIN NAME"
    breakdown_entry = " : "

    if len(sys.argv) > 1:
        in_file = sys.argv[1]
        json_file = sys.argv[2]
    else:
        in_file = "html-report/f17_cve_bin_tool.html"
        json_file = "clean-text/f17_cve_bin_tool.json"
    print("Extract " + in_file + " into " + json_file + "......")

    output_sections = Sections()
    try:
        # Prompt the user to enter the filename
        # in_file = input("Enter the name of the file to open: ")

        # Open the file in read mode ('r')
        # The 'with' statement ensures the file is properly closed even if errors occur
        with (open(in_file, 'r') as file):
            # Read the content of the file
            html_data = file.read()
            soup = BeautifulSoup(html_data, 'html.parser')
            div_to_extract = soup.find('div', id='main')
            if div_to_extract:
                extracted_content = str(div_to_extract)
                out_file = os.path.splitext(in_file)[0] + "_extracted" + os.path.splitext(in_file)[1]
                with open(out_file, 'w', encoding='utf-8') as f:
                    f.write(extracted_content)
                # find all links and save to a file
                # soup1 = BeautifulSoup(extracted_content, 'html.parser')
                all_pres = div_to_extract.find_all('pre')
                pre_file = os.path.splitext(out_file)[0] + "_items" + os.path.splitext(in_file)[1]
                # json_file = os.path.splitext(in_file)[0] + ".json"
                pre_text_aray = []
                # Iterate through the extracted <a> tags
                for pre in all_pres:
                    #.replace("[+]", "   ").lstrip()
                    # pre_text = pre_text.replace("[*]", "   ").lstrip()
                    # pre_text = pre.get_text().replace("kernel_verifica:", "kernel_verifica :")
                    pre_text = pre.get_text().replace("Snyk:", "").replace("PSS:", "").replace(": ", " : ")
                    # pre_text = pre.get_text().replace(": ", " : ")
                    links_within_pre = pre.find_all('a')
                    for link in links_within_pre:
                        href = link.get('href')
                        link_text = link.get_text()
                        if href is None:
                            href = ""
                        if link_text is None:
                            link_text = ""
                        pre_text = pre_text + " : " + link_text + " : " + href
                    pre_text = pre_text.replace("</span>", "").replace("</pre>", "")
                    pre_text = " ".join(pre_text.split())
                    pre_text_aray.append(pre_text)
                    unique_pre_text_array = [s for s in pre_text_aray if s.strip()]
                    # unique_pre_text_array = list(dict.fromkeys(unique_pre_text_array))
                with open(pre_file, 'w', encoding='utf-8') as f:  # Use 'with open' to ensure the file is closed properly
                    # Write the information to the file
                    f.writelines(s + '\n' for s in unique_pre_text_array)
                with open(pre_file) as textFile:
                    lines = [line.rstrip() for line in textFile]
                    line_cnt = 0
                    while line_cnt < len(lines):
                        line = lines[line_cnt]
                        if section_delimiter in line:
                            output_section = Section(line.removeprefix(section_delimiter))
                            line_cnt += 1
                            while line_cnt < len(lines):
                                line = lines[line_cnt]
                                if subsection_delimiter in line:
                                    output_subsection = Subsec(line.removeprefix(subsection_delimiter))
                                    line_cnt += 1
                                    if line_cnt < len(lines):
                                        line = lines[line_cnt]
                                    else:
                                        break
                                    if finding_delimiter in line:
                                        # move to the exact findings
                                        line_cnt += 1
                                        while line_cnt < len(lines):
                                            line = lines[line_cnt]
                                            if conclusion_delimiter in line:
                                                output_subsection.conclusion = line.removeprefix(conclusion_delimiter)
                                                line_cnt += 1
                                                break
                                            elif finding_delimiter in line:
                                                line_cnt += 1
                                            else:
                                                output_finding = parse_finding(line)
                                                export_finding = copy.deepcopy(output_finding)
                                                output_subsection.append(export_finding)
                                                line_cnt += 1
                                    else:
                                        if conclusion_delimiter in line:
                                            output_subsection.conclusion = line.removeprefix(conclusion_delimiter)
                                            line_cnt += 1
                                    export_subsection = copy.deepcopy(output_subsection)
                                    output_section.append(export_subsection)
                                    if section_delimiter in line:
                                        break
                                elif conclusion_delimiter in line:
                                    output_section.note += line.replace(conclusion_delimiter, "")
                                    line_cnt += 1
                                    break
                                elif section_delimiter in line:
                                    break
                                elif line_cnt < len(lines):
                                    line_cnt += 1
                                else:
                                    break
                            export_section = copy.deepcopy(output_section)
                            output_sections.append(export_section)
                        elif line_cnt < len(lines):
                            line_cnt += 1
                        else:
                            break
                    output_sections.count()
                    with open(json_file, 'w', encoding='utf-8') as f:  # Use 'with open' to ensure the file is closed properly
                        f.writelines(json.dumps(output_sections, default=lambda o: o.__dict__))
                    # print(json.dumps(output_sections, default=lambda o: o.__dict__))
    except FileNotFoundError:
        print(f"Error: The file '{in_file}' was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__=="__main__":
    main()
