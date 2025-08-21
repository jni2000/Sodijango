import sys
from bs4 import BeautifulSoup
import csv

import JsonShared


def main():
    if len(sys.argv) > 1:
        in_file = sys.argv[1]
        json_file = sys.argv[2]
    else:
        in_file = "BinaryScanHTMLFiles/html-report/index.html"
        json_file = "clean-text/index.json"
    print("Extract " + in_file + " into " + json_file + "......")

    try:
        # Load the HTML content
        with open(in_file, "r", encoding="utf-8") as file:
            soup = BeautifulSoup(file, "html.parser")

        section_descs = ["Architecture and OS", "File Structure, Yara matches, and kernel vulnerabilities", "Configuration issues and kernel settings", "Binary protections", "Software inventory, vulnerabilities, and exploits"]

        # Find the main div
        main_div = soup.find("div", id="main")
        tags = main_div.find_all(["pre", "a"], recursive=False)

        sections = JsonShared.Sections()
        capture = False
        crit_sec = []
        for i in range(len(tags)):
            if "Detected architecture and endianness" in tags[i].get_text(strip=True):
                capture = True
            if capture:
                crit_sec.append(tags[i])

        def is_hr_pre(tag):
            return tag.name == 'pre' and tag.find('hr', class_='mono')

        plus_delim = "[ + ] "
        star_delim = "[ * ] "

        desc_index = 0

        section = JsonShared.Section(section_descs[desc_index])
        desc_index += 1
        for i in range(len(crit_sec)):
            if crit_sec[i].name == 'a' and crit_sec[i].find('pre'):
                pre = crit_sec[i].find('pre')
                link = crit_sec[i].get('href')
                text = pre.get_text(separator=' ', strip=True)
                if plus_delim in text:
                    text = text.removeprefix(plus_delim)
                elif star_delim in text:
                    text = text.removeprefix(star_delim)
                if "Detected architecture and endianness ( verified ): " in text:
                    text = text.removeprefix("Detected architecture and endianness ( verified ): ")
                if "Operating system detected ( verified ): " in text:
                    text = text.removeprefix("Operating system detected ( verified ): ")
                if "Found" in text and "yara rule matches" in text:
                    text = text.split(" in ")
                    if text[1].endswith(" files."):
                        text = text[0] + "."

                
                subsection = JsonShared.Subsection(text, link)
                section.append_subsection(subsection)
            elif crit_sec[i].name == 'pre':
                if is_hr_pre(crit_sec[i]):
                    if section.description == "Binary protections":
                        sections.sections.insert(0, section)
                        sections.section_count += 1
                    else:
                        sections.append(section)
                    if (desc_index < len(section_descs)):
                        section = JsonShared.Section(section_descs[desc_index])
                        desc_index += 1
                else:
                    text = crit_sec[i].get_text(separator=' ', strip=True)
                    if plus_delim in text:
                        text = text.removeprefix(plus_delim)
                    elif star_delim in text:
                        text = text.removeprefix(star_delim)
                    if "Found the following configuration issues" in text:
                        continue
                    subsection = JsonShared.Subsection(text, "")
                    section.append_subsection(subsection)


        JsonShared.write_json_file(json_file, sections)

    except FileNotFoundError:
        print(f"Error: The file '{in_file}' was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__=="__main__":
    main()




# # Prepare data
# data = []
# for link in links:
#     href = link.get("href", "").strip()
#     # Extract visible text, joining all text in the <pre> tag if present
#     text = link.get_text(separator=" ", strip=True)
#     text = text.replace("[ + ]", "")
#     print(text)
#     data.append({"description": text, "link": href})

# # Write to CSV
# with open("output.csv", "w", newline="", encoding="utf-8") as csvfile:
#     writer = csv.DictWriter(csvfile, fieldnames=["description", "link"])
#     writer.writeheader()
#     writer.writerows(data)

# print("CSV has been written to 'output.csv'")
