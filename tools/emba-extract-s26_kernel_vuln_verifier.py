import copy
import os
import sys
from typing import List, Optional
from bs4 import BeautifulSoup
import json

from hamcrest import empty
import JsonShared

class Exploit:
    def __init__(self, desc: str, eid: str = None, lnk: str = None):
        self.description = desc
        self.id = eid
        self.link = lnk

class Find:
    def __init__(self, desc: str, modul: str, ver: str, cve: str, cvss: str, epss: str, severity: str, method: str, lnk: str, lnk_tag: str, explts: Optional[List[Exploit]] = None):
        self.description = desc
        self.module = modul
        self.version = ver
        self.cve_id = cve
        self.cvss_score = cvss
        self.epss_score = epss
        self.severity = severity
        self.method = method
        self.exploits = explts or []
        self.link = lnk
        self.link_tag = lnk_tag
        self.exploit_count = len(self.exploits) or 0

class Vuln:
    def __init__(self, cve, cve_link, score, path, verified, method):
        self.cve_id = cve
        self.cve_link = cve_link
        self.cvss_value = score
        self.location = path
        self.verification_status = verified
        self.notes = method

class CVE_Result_Find:
    def __init__(self, kernel_version, arch, cve, cve_link, cvss_v2, cvss_v3, symbols, compile_files):
        self.kernel_version = kernel_version
        self.arch = arch
        self.cve = cve
        self.cve_link = cve_link
        self.cvss_v2 = cvss_v2
        self.cvss_v3 = cvss_v3
        self.symbols = symbols
        self.compile_files = compile_files


class UnknownFind:
    def __init__(self, description):
        self.description = description

class Text_Find:
    def __init__(self, details):
        self.details = details



def Parse_exploits(parts):
    exploits = []
    if parts is not empty():
        count = 10
        desc = parts[6].split("(")[1].strip()
        while count < len(parts)-1:
            eid = parts[count].replace(")", "")
            count += 1
            elnk = parts[count].replace(")", "")
            count += 1
            # print("Exploit, " + eid +", " + elnk)
            exploit = Exploit(desc, eid, elnk)
            exploits.append(copy.deepcopy(exploit))
    return exploits

def parse_finding(line):
    find = UnknownFind(line)
    if line is not empty():
        parts = line.split(" : ")
        parts = [item.strip() for item in parts]
        if len(parts) >= 9:
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
                # exploit = Exploit(parts[6])
                # exploits.append(copy.deepcopy(exploit))
                exploits = []
                if parts[7] and parts[8]:
                    lnk = parts[8]
                    lnk_tag = parts[7]
            elif "KEV" in parts[6]:
                exploit = Exploit("KEV", "", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog")
                exploits.append(exploit)
                if parts[7] and parts[8]:
                    lnk = parts[8]
                    lnk_tag = parts[7]
            else:
                if (len(parts) < 10):
                    return find
                exploits = Parse_exploits(parts)
                if parts[8] and parts[9]:
                    lnk = parts[9]
                    lnk_tag = parts[8]
            
            find = Find("Finding details", modul, ver, cve, cvss, epss, lvl, src, lnk, lnk_tag, exploits)
    return find

def parse_cve_results(link):
    with open(link, "r", encoding="utf-8") as file:
        soup = BeautifulSoup(file, "html.parser")

    main_div = soup.find("div", id="main")
    pre_tags = main_div.find_all("pre")

    finds = []
    
    capture = False
    for tag in pre_tags:
        raw_text = tag.get_text(separator=' ', strip=True)
        if capture:
            row = raw_text.split(";")
            link = tag.find('a').get('href')
            if len(row) == 7:
                cve_result_find = CVE_Result_Find(row[0], row[1], row[2], link, row[3], row[4], row[5], row[6])
            elif len(row) == 6:
                cve_result_find = CVE_Result_Find(row[0], row[1], row[2], link, row[3], row[3], row[4], row[5])
            else:
                continue
            
            finds.append(cve_result_find)

        if "Kernel version;Architecture;CVE;CVSSv2;CVSSv3;Verified with symbols;Verified with compile files" in raw_text:
            
            capture = True

    return finds

def get_html_text(link):
    with open(link, "r", encoding="utf-8") as file:
        soup = BeautifulSoup(file, "html.parser")

    main_div = soup.find("div", id="main")
    pre_tags = main_div.find_all("pre")

    out = ""
    for tag in pre_tags:
        raw_text = tag.get_text(separator=' ', strip=True)
        out += raw_text + "\n"

    find = Text_Find(out)
    return [find]

def main():
    if len(sys.argv) > 1:
        in_file = sys.argv[1]
        json_file = sys.argv[2]
    else:
        in_file = "BinaryScanHTMLFiles/html-report/s26_kernel_vuln_verifier.html"
        json_file = "clean-text/s26_kernel_vuln_verifier.json"
    print("Extract " + in_file + " into " + json_file + "......")
    try:
        with open(in_file, "r", encoding="utf-8") as file:
            soup = BeautifulSoup(file, "html.parser")

        # Find the main div
        main_div = soup.find("div", id="main")
        pre_tags = main_div.find_all(["pre", "a"], recursive=False)
        texts = [tag.get_text(strip=True) for tag in pre_tags]

        sections = JsonShared.Sections()

        arrow_delim = "==>"
        plus_delim = "[ + ]"
        star_delim = "[ * ]"



        i = 0
        while i < len(pre_tags):
            raw_text = pre_tags[i].get_text(separator=' ', strip=True)
            # Look for section headers
            if pre_tags[i].find("span", class_="blue") and (arrow_delim in raw_text or plus_delim in raw_text):
                if "Kernel vulnerability identification and verification" in raw_text:
                    section = JsonShared.Section("Kernel vulnerability identification and verification")
                    
                    i += 1

                    find_capture = False
                    subsection = None
                    while not (pre_tags[i + 1].find("span", class_="blue")):
                        ## TODO: We are hard coding the "snyk", "pss" etc replacements so that the link and tag don't get messed up, do we know for sure that these are all of the __:?
                        raw_text = pre_tags[i].get_text(separator=' ', strip=True).replace(": ", " : ")
                        if plus_delim in raw_text or star_delim in raw_text:
                            if find_capture:
                                subsection.conclusion = raw_text[6:]
                            else:
                                subsection = JsonShared.Subsection(raw_text[6:])
                                section.append_subsection(subsection)
                            find_capture = False
                        

                        row_wspace = raw_text.split(":")
                        row = [item.strip() for item in row_wspace]
                        if row == ["BIN NAME", "BIN VERS", "CVE ID", "CVSS VALUE", "EPSS", "SOURCE", "EXPLOIT"]:
                            find_capture = True
                        if find_capture and row != ["BIN NAME", "BIN VERS", "CVE ID", "CVSS VALUE", "EPSS", "SOURCE", "EXPLOIT"]:
                            links_within_pre = pre_tags[i].find_all('a')
                            pre_text = raw_text
                            for link in links_within_pre:
                                href = link.get('href')
                                link_text = link.get_text()
                                if href is None:
                                    href = ""
                                if link_text is None:
                                    link_text = ""
                                pre_text = pre_text + " : " + link_text + " : " + href
                                pre_text = pre_text.replace("</span>", "").replace("</pre>", "")
                            
                            find = parse_finding(pre_text)
                            try:
                                subsection.append(find)
                            except:
                                print('Error: Subsection header not found')
                                ## TODO: Figure out better error handling system
                        i += 1
                    sections.append(section)

                elif "kernel vulnerability verification" in raw_text:
                    section = JsonShared.Section(raw_text.removeprefix(arrow_delim))
                    i += 1
                    subsection = None
                    while not (pre_tags[i].find("span", class_="blue")):
                        curr_text = pre_tags[i].get_text(separator=' ', strip=True)
                        if star_delim in curr_text:
                            subsection = JsonShared.Subsection(pre_tags[i].get_text(strip=True)[3:])
                            section.append_subsection(subsection)
                        elif plus_delim in curr_text:
                            if subsection:
                                curr_text = curr_text.removeprefix(plus_delim)
                                link = pre_tags[i].find('a').get("href")
                                dash_split = curr_text.split(" - ")
                                cve_id = dash_split[0].split("(")[0].strip()
                                severity = dash_split[0].split("(")[1].strip()[:-1]
                                path = dash_split[1].split()[0].strip()
                                verified = dash_split[1].split()[1].strip()
                                method = dash_split[2].strip()

                                vuln = Vuln(cve_id, link, severity, path, verified, method)
                                subsection.append(vuln)
                            else:
                                raise SyntaxError
                        i += 1
                    i -= 1

                    sections.append(section)

                elif "kernel verification results" in raw_text:
                    section = JsonShared.Section(raw_text.removeprefix(arrow_delim))
                    i += 1

                    while not (pre_tags[i].find("span", class_="blue")) and "Exploitability notes" not in pre_tags[i].get_text(strip=True):
                        finds = []
                        if pre_tags[i].name == 'a' and pre_tags[i].find('pre'):
                            pre = pre_tags[i].find('pre')
                            link = pre_tags[i].get('href')

                            if plus_delim in pre_tags[i].get_text(separator=' ', strip=True):
                                try:
                                    finds = parse_cve_results(os.path.join(os.path.dirname(in_file), link))
                                except FileNotFoundError as e:
                                    print(e)
                            else:
                                try:
                                    finds = get_html_text(os.path.join(os.path.dirname(in_file), link))
                                except FileNotFoundError as e:
                                    print(e)
                                
                        else:
                            pre = pre_tags[i]
                            link = ""
                        subsection = JsonShared.Subsection(pre.get_text(separator=' ', strip=True)[6:], link, finds)
                        section.append_subsection(subsection)
                        i += 1
                    i -= 1

                    sections.append(section)
            i += 1

        JsonShared.write_json_file(json_file, sections)


    
    except FileNotFoundError:
        print(f"Error: The file '{in_file}' was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__=="__main__":
    main()
