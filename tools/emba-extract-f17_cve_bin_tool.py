#!/usr/bin/python3

import os, io, json, copy, re, sys
from typing import List, Optional
from dataclasses import dataclass
from bs4 import BeautifulSoup
from hamcrest import empty

import JsonShared

@dataclass
class Exploit:
    def __init__(self, desc: str, eid: str = None, lnk: str = None):
        self.description = desc
        self.id = eid
        self.link = lnk

@dataclass
class UnknownFind:
    def __init__(self, description):
        self.description = description

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
    def __init__(self, desc: str, cncl: str = "", finds: Optional[List] = None):
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
    
class Legend:
    def __init__(self, r, l, d, p, p_link, s, s_link, x, x_link, v):
        self.r = r
        self.l = l
        self.d = d
        self.p = p
        self.p_link = p_link
        self.s = s
        self.s_link = s_link
        self.x = x
        self.x_link = x_link
        self.v = v

def Parse_exploits(line):
    line = line.removeprefix("Exploit (")
    line = line.removesuffix("</span></pre>")
    exploits = []
    exploit_split = line.split(" / ")
    exploit_split = [item.strip() for item in exploit_split]
    for exploit in exploit_split:
        col_split = exploit.split(": ", maxsplit = 1)
        desc = col_split[0]
        if len(col_split) == 1:
            elnk = ""
            eid = ""
            if "KEV" in desc:
                desc = desc.split(" (")[0]
                elnk = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
            exploit = Exploit(desc, eid, elnk)
            exploits.append(exploit)
        else:
            soup = BeautifulSoup(col_split[1], 'html.parser')
            a_tags = soup.find_all('a')
            if len(a_tags) == 0:
                eid = col_split[1]
                exploit = Exploit(desc, eid, "")
                exploits.append(exploit)
            else:
                for tag in a_tags:
                    eid = tag.get('title')
                    elnk = tag.get('href')
                    exploit = Exploit(desc, eid, elnk)
                    exploits.append(exploit)

    return exploits

    # if parts is not empty():
    #     count = 10
    #     desc = parts[6].split("(")[1].strip()
    #     while count < len(parts)-1:
    #         eid = parts[count].replace(")", "")
    #         count += 1
    #         elnk = parts[count].replace(")", "")
    #         count += 1
    #         # print("Exploit, " + eid +", " + elnk)
    #         exploit = Exploit(desc, eid, elnk)
    #         exploits.append(copy.deepcopy(exploit))
    # return exploits

def isFloat(value):
    try:
        float(value)
        return True
    except ValueError:
        return False

def parse_finding(pre_tag):
    raw_str = str(pre_tag)

    raw_parts = raw_str.split(": ", maxsplit=6)
    raw_parts = [item.strip() for item in raw_parts]
    

    line = pre_tag.get_text(separator=' ', strip=True)
    find = UnknownFind(line)
    if line is not empty():
        parts = line.split(": ")
        parts = [item.strip() for item in parts]
        if len(parts) >= 7:
            modul = parts[0]
            ver = parts[1]
            cve = parts[2]
            
            cvss = parts[3]
            severity_string = cvss.split()

            if isFloat(severity_string[0]):
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
            else:
                lvl = "unknown"

            

            epss = parts[4]
            src = parts[5]
            exploits = []

            soup = BeautifulSoup(raw_parts[2], 'html.parser')
            cvss_tag = soup.find('a')
            lnk = cvss_tag.get('href')
            lnk_tag = cvss_tag.get('title')
            if "No exploit available" in raw_parts[-1]:
                exploits = []
            elif "Exploit" in raw_parts[-1]:
                exploits = Parse_exploits(raw_parts[-1])
            else:
                exploits = []

            
            find = Find("Finding details", modul, ver, cve, cvss, epss, lvl, src, lnk, lnk_tag, exploits)
    return find


def main():
    section_delimiter = "==> "
    subsection_delimiter  = "[ * ] "
    conclusion_delimiter  = "[ + ] "
    finding_delimiter = "BIN NAME"
    breakdown_entry = " : "

    if len(sys.argv) > 1:
        in_file = sys.argv[1]
        json_file = sys.argv[2]
    else:
        in_file = "BinaryScanHTMLFiles/html-report/f17_cve_bin_tool.html"
        json_file = "clean-text/f17_cve_bin_tool.json"
    print("Extract " + in_file + " into " + json_file + "......")

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

            main_div = soup.find("div", id="main")
            pre_tags = main_div.find_all(["pre", "a"], recursive=False)
            texts = [tag.get_text(strip=True) for tag in pre_tags]

            
            sections = JsonShared.Sections()

            arrow_delim = "==>"
            plus_delim = "[ + ]"
            star_delim = "[ * ]"

            overview_lines = []
            capture = False
            for i in range(len(pre_tags)):
                raw_text = pre_tags[i].get_text(separator=' ', strip=True)
                # Look for section headers
                if pre_tags[i].find("span", class_="blue") and (arrow_delim in raw_text or plus_delim in raw_text):
                    if "Software inventory overview" in raw_text:
                        
                        capture = True
                    else:
                        capture = False
                else:
                    if capture:
                        overview_lines.append(pre_tags[i])


            if len(overview_lines):
                overview_section = JsonShared.Section("Software inventory overview")
                for i in overview_lines:
                    raw_text = i.get_text(separator=' ', strip=True)
                    if star_delim in raw_text:
                        subsec = JsonShared.Subsection(raw_text.removeprefix(star_delim))
                        overview_section.append_subsection(subsec)
                sections.append(overview_section)
                
            vuln_lines = []
            capture = False
            for i in range(len(pre_tags)):
                raw_text = pre_tags[i].get_text(separator=' ', strip=True)
                # Look for section headers
                if pre_tags[i].find("span", class_="blue") and (arrow_delim in raw_text or plus_delim in raw_text):
                    if "Vulnerability overview" in raw_text:
                        capture = True
                    else:
                        capture = False
                else:
                    if capture:
                        vuln_lines.append(pre_tags[i])

            if len(vuln_lines):
                
                vuln_sec = JsonShared.Section("Vulnerability overview")
                subsec = None
                find_capture = False
                for i in vuln_lines:
                    raw_text = i.get_text(separator=' ', strip=True)
                    if star_delim in raw_text:
                        subsec = JsonShared.Subsection(raw_text.removeprefix(star_delim))
                    elif plus_delim in raw_text:
                        find_capture = False
                        if subsec:
                            subsec.conclusion = raw_text.removeprefix(plus_delim)
                            vuln_sec.append_subsection(subsec)
                            subsec = None
                    else:
                        row_wspace = raw_text.split(":")
                        row = [item.strip() for item in row_wspace]
                        if row == ["BIN NAME", "BIN VERS", "CVE ID", "CVSS VALUE", "EPSS", "SOURCE", "EXPLOIT"]:
                            find_capture = True
                        elif find_capture and len(row) >= 7:
                            finding = parse_finding(i)
                            subsec.append(finding)

                sections.append(vuln_sec)




            

            # if div_to_extract:
            #     extracted_content = str(div_to_extract)
            #     out_file = os.path.splitext(in_file)[0] + "_extracted" + os.path.splitext(in_file)[1]
            #     with open(out_file, 'w', encoding='utf-8') as f:
            #         f.write(extracted_content)
            #     # find all links and save to a file
            #     # soup1 = BeautifulSoup(extracted_content, 'html.parser')
            #     all_pres = div_to_extract.find_all(['pre', 'a'], recursive=False)
            #     pre_file = os.path.splitext(out_file)[0] + "_items" + os.path.splitext(in_file)[1]
            #     # json_file = os.path.splitext(in_file)[0] + ".json"
            #     pre_text_aray = []
                
            #     # Iterate through the extracted <a> tags
            #     for pre in all_pres:
            #         #.replace("[+]", "   ").lstrip()
            #         # pre_text = pre_text.replace("[*]", "   ").lstrip()
            #         # pre_text = pre.get_text().replace("kernel_verifica:", "kernel_verifica :")
            #         pre_text = pre.get_text(separator=' ', strip=True).replace(": ", " : ")
            #         # pre_text = pre.get_text().replace(": ", " : ")
            #         links_within_pre = pre.find_all('a')
            #         for link in links_within_pre:
            #             href = link.get('href')
            #             link_text = link.get_text()
            #             if href is None:
            #                 href = ""
            #             if link_text is None:
            #                 link_text = ""
            #             pre_text = pre_text + " : " + link_text + " : " + href
            #         pre_text = pre_text.replace("</span>", "").replace("</pre>", "")
            #         pre_text = " ".join(pre_text.split())
            #         pre_text_aray.append(pre_text)
            #         unique_pre_text_array = [s for s in pre_text_aray if s.strip()]
            #         # unique_pre_text_array = list(dict.fromkeys(unique_pre_text_array))
            #     with open(pre_file, 'w', encoding='utf-8') as f:  # Use 'with open' to ensure the file is closed properly
            #         # Write the information to the file
            #         f.writelines(s + '\n' for s in unique_pre_text_array)
            #     with open(pre_file) as textFile:
            #         lines = [line.rstrip() for line in textFile]
            #         line_cnt = 0
            #         while line_cnt < len(lines):
            #             line = lines[line_cnt]
            #             if section_delimiter in line and "Vulnerability Exploitability eXchange" not in line:
            #                 output_section = Section(line.split(":")[0].removeprefix(section_delimiter))
            #                 line_cnt += 1
            #                 while line_cnt < len(lines):
            #                     line = lines[line_cnt]
            #                     if subsection_delimiter in line:
            #                         output_subsection = Subsec(line.removeprefix(subsection_delimiter))
            #                         line_cnt += 1
            #                         if line_cnt < len(lines):
            #                             line = lines[line_cnt]
            #                         else:
            #                             break
            #                         if finding_delimiter in line:
            #                             # move to the exact findings
            #                             line_cnt += 1
            #                             while line_cnt < len(lines):
            #                                 line = lines[line_cnt]
            #                                 if conclusion_delimiter in line:
            #                                     output_subsection.conclusion = line.removeprefix(conclusion_delimiter)
            #                                     line_cnt += 1
            #                                     break
            #                                 elif finding_delimiter in line:
            #                                     line_cnt += 1
            #                                 else:
            #                                     output_finding = parse_finding(line)
            #                                     export_finding = copy.deepcopy(output_finding)
            #                                     output_subsection.append(export_finding)
            #                                     line_cnt += 1
            #                         else:
            #                             if conclusion_delimiter in line:
            #                                 output_subsection.conclusion = line.removeprefix(conclusion_delimiter)
            #                                 line_cnt += 1
            #                         export_subsection = copy.deepcopy(output_subsection)
            #                         output_section.append(export_subsection)
            #                         if section_delimiter in line:
            #                             break
            #                     elif conclusion_delimiter in line:
            #                         output_section.note += line.replace(conclusion_delimiter, "")
            #                         line_cnt += 1
            #                         break
            #                     elif section_delimiter in line:
            #                         break
            #                     elif line_cnt < len(lines):
            #                         line_cnt += 1
            #                     else:
            #                         break
            #                 export_section = copy.deepcopy(output_section)
            #                 output_sections.append(export_section)
            #             elif line_cnt < len(lines):
            #                 line_cnt += 1
            #             else:
            #                 break

            #         output_sections.count()
            #         # with open(json_file, 'w', encoding='utf-8') as f:  # Use 'with open' to ensure the file is closed properly
            #         #     f.writelines(json.dumps(output_sections, default=lambda o: o.__dict__))
            #         # print(json.dumps(output_sections, default=lambda o: o.__dict__))
            # # tags = div_to_extract.find_all(["pre", "a"], recursive=False)
            # # vex_capture = False
            # # section = None
            # # for tag in tags:
            # #     text = tag.get_text(separator=' ', strip=True)
            # #     if vex_capture:
            # #         if "[ + ]" in text:
            # #             if tag.name == 'a' and tag.find('pre'):
            # #                 href = tag.get('href')
            # #                 pre = tag.find('pre')
            # #                 subsection = Subsec(text.removeprefix("[ + ] "), href)
            # #                 section.append(subsection)
            # #     if "Vulnerability Exploitability eXchange" in text:
            # #         vex_capture = True
            # #         section = Section(text.removeprefix(section_delimiter))

            # # exploit_notes = Legend("remote exploits", "local exploits", "DoS exploits", "PoC code found on Packetstormsecurity (unknown exploit vector)", "https://packetstormsecurity.com/files/tags/exploit/", "PoC code found on Snyk vulnerability database (unknown exploit vector)", "https://security.snyk.io/vuln", "Vulnerability is known as exploited", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "Vulnerability verified - Kernel or BusyBox (S26, S118)")
            # # exploit_notes_subsec = Subsec("Exploitability notes")
            # # exploit_notes_subsec.append(exploit_notes)
            # # section.append(exploit_notes_subsec)
            # # output_sections.append(section)

            # with open(json_file, 'w', encoding='utf-8') as f:  # Use 'with open' to ensure the file is closed properly
            #     f.writelines(json.dumps(output_sections, default=lambda o: o.__dict__))

        JsonShared.write_json_file(json_file, sections)
    except FileNotFoundError:
        print(f"Error: The file '{in_file}' was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__=="__main__":
    main()
