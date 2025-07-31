import sys
from bs4 import BeautifulSoup
import json

import JsonShared


def main():
    if len(sys.argv) > 1:
        in_file = sys.argv[1]
        json_file = sys.argv[2]
    else:
        in_file = "BinaryScanHTMLFiles/html-report/p99_prepare_analyzer.html"
        json_file = "clean-text/p99_prepare_analyzer.json"
    print("Extract " + in_file + " into " + json_file + "......")

    try:
        json_out = {
            "sections": [
                {
                    "description": "Analysis Preparation",
                    "subsections": [],
                    "subsection_count": 0,
                }
            ],
            "section_count": 1
        }

        with open(in_file, "r", encoding="utf-8") as file:
            soup = BeautifulSoup(file, "html.parser")

        # Find the main div
        main_div = soup.find("div", id="main")


        pre_tags = main_div.find_all('pre')
        texts = [tag.get_text(strip=True) for tag in pre_tags]

        crit_sec = []
        crit_start = "Architecture auto detection and backend data population for"
        crit_end = "Detected architecture and endianness of the firmware"

        capture = False
        for text in texts:
            if crit_start in text:
                capture = True
            if capture:
                crit_sec.append(text)
            if crit_end in text:
                break

        # TODO: What to do if crit start and crit end aren't in the html?


        # TODO: Each of the objects in finds is not of the same type, is that alright? eg. 
        subsection = {
            "description": "",
            "conclusion": "",
            "finds": [],
            "find_count": 0
        }
        arch_find = {
            "architecture": "",
            "count": 0
        }
        end_find = {
            "endianness": "",
            "count": 0
        }

        # TODO: Checks for out of bounds and check for if the keywords are not present
        for i in range(len(crit_sec)):
            if "Architecture" in crit_sec[i] and "Count" in crit_sec[i]:
                terms = crit_sec[i + 1].split()
                # If there are less than two terms, something is wrong;
                # TODO: Is there a possibility that the count is not the last term? Or is there a possibility that the categories are different? Will it always be arch count and end count?

                arch_find["architecture"] = ' '.join(terms[:-1])
                arch_find["count"] = terms[-1]

            if "Endianness" in crit_sec[i] and "Count" in crit_sec[i]:
                terms = crit_sec[i + 1].split()

                end_find["endianness"] = ' '.join(terms[:-1])
                end_find["count"] = terms[-1]

            
        subsection["finds"] = [arch_find, end_find]
        subsection["find_count"] = 2

        json_out["sections"][0]["subsections"].append(subsection)
        json_out["sections"][0]["subsection_count"] += 1

        JsonShared.write_json_file(json_file, json_out)

    except FileNotFoundError:
        print(f"Error: The file '{in_file}' was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__=="__main__":
    main()