import os
import sys
from bs4 import BeautifulSoup
import json
import JsonShared

## TODO: Is the objective to only parse the yara rule ... matched in ... structured items? Could there potentially be other formatted items?

plus_delim = "[ + ] "

class Find:
    def __init__(self, yara_rule:str, match_loc:str, details:str):
        self.yara_rule = yara_rule
        self.match_loc = match_loc
        self.details = details

def get_details(link, key):
    with open(link, "r", encoding="utf-8") as file:
        soup = BeautifulSoup(file, "html.parser")
        main_div = soup.find("div", id="main")
        tags = main_div.find_all("pre")
        
        details = ""
        capture = False
        for tag in tags:
            raw_text = tag.get_text(separator=' ', strip=True)
            if capture and plus_delim in raw_text:
                break
            if capture:
                details += raw_text + '\n'
            if key in raw_text:
                capture = True
    return details

def main():
    if len(sys.argv) > 1:
        in_file = sys.argv[1]
        json_file = sys.argv[2]
    else:
        in_file = "BinaryScanHTMLFiles/html-report/s110_yara_check.html"
        json_file = "clean-text/s110_yara_check.json"
    print("Extract " + in_file + " into " + json_file + "......")

    try:
        with open(in_file, "r", encoding="utf-8") as file:
            soup = BeautifulSoup(file, "html.parser")


        sections = JsonShared.Sections()
        section = JsonShared.Section("Yara Check")
        subsection = JsonShared.Subsection("")

        # Find the main div
        main_div = soup.find("div", id="main")
        tags = main_div.find_all('a')

        find_delim = "[ + ] Yara rule"

        for i in tags:
            raw_text = i.get_text(separator=' ', strip=True)
            if find_delim in raw_text:
                rule_loc_pair = raw_text.removeprefix(find_delim).split("matched in")
                link = i.get("href", "").strip()
                link = os.path.join(os.path.dirname(in_file), link)
                key = raw_text.removeprefix(find_delim)
                details = get_details(link, key)
                find = Find(rule_loc_pair[0], rule_loc_pair[1], details)

                subsection.append(find)

        section.append_subsection(subsection)
        sections.append(section)
        JsonShared.write_json_file(json_file, sections)

    except FileNotFoundError:
        print(f"Error: The file '{in_file}' was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__=="__main__":
    main()