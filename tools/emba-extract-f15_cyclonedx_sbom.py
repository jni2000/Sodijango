import os
import sys

from bs4 import BeautifulSoup

import JsonShared


def main():
    if len(sys.argv) > 1:
        in_file = sys.argv[1]
        json_file = sys.argv[2]
    else:
        in_file = "BinaryScanHTMLFiles/html-report/f15_cyclonedx_sbom.html"
        json_file = "clean-text/f15_cyclonedx_sbom.json"
    print("Extract " + in_file + " into " + json_file + "......")
    try:
        with open(in_file, "r", encoding="utf-8") as file:
            soup = BeautifulSoup(file, "html.parser")
            main_div = soup.find("div", id="main")
            tags = main_div.find_all(["pre", "a"], recursive=False)
            href = ""
            for tag in tags:
                if "Cyclonedx SBOM in json format" in tag.get_text(strip=True):
                    if tag.name == 'a':
                        href = tag.get('href')

            if href:
                sections = JsonShared.Sections()
                section = JsonShared.Section("CycloneDX SBOM Generator")
                desc = ""
                link = os.path.join(os.path.dirname(in_file), href)
                with open(link,'r') as firstfile:
                    for line in firstfile:
                        desc += line

                subsection = JsonShared.Subsection(desc)
                section.append_subsection(subsection)
                sections.append(section)

                JsonShared.write_json_file(json_file, sections)

            else:
                raise Exception("No reference to Cyclonedx SBOM in json format")
            


    except FileNotFoundError:
        print(f"Error: The file '{in_file}' was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__=="__main__":
    main()
