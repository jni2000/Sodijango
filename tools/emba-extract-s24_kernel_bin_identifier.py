import os
import sys
from bs4 import BeautifulSoup
import json
import JsonShared


class Conf_Find:
    def __init__(self, data, link):
        self.data = data
        self.link = link

class Find:
    def __init__(self, configuration_name, type, desired_value, decision, configuration_purpose, check_result, result_note):
        self.configuration_name = configuration_name
        self.type = type
        self.desired_value = desired_value
        self.decision = decision
        self.configuration_purpose = configuration_purpose
        self.check_result = check_result
        self.result_note = result_note

def main():
    if len(sys.argv) > 1:
        in_file = sys.argv[1]
        json_file = sys.argv[2]
    else:
        in_file = "BinaryScanHTMLFiles/html-report/s24_kernel_bin_identifier.html"
        json_file = "clean-text/s24_kernel_bin_identifier.json"
    print("Extract " + in_file + " into " + json_file + "......")
    try:
        sections = JsonShared.Sections()

        with open(in_file, "r", encoding="utf-8") as file:
            soup = BeautifulSoup(file, "html.parser")

        # Find the main div
        main_div = soup.find("div", id="main")
        pre_tags = main_div.find_all(['pre', 'a'], recursive=False)
        section = JsonShared.Section("Kernel Binary and Configuration Identifier", None)

        plus_delim = "[ + ] "
        star_delim = "[ * ] "

        for i in range(len(pre_tags)):
            if pre_tags[i].find("span", class_="green"):
                raw_text = pre_tags[i].get_text(separator=' ', strip=True)
                conclusion = ""
                find = None
                if plus_delim in raw_text:
                    subsection = JsonShared.Subsection(raw_text.removeprefix(plus_delim), conclusion, None)
                    if pre_tags[i].name == 'a' and pre_tags[i].find("pre"):
                        link = pre_tags[i].get('href')
                        link = os.path.join(os.path.dirname(in_file), link)
                        with open(link, "r", encoding="utf-8") as file:
                            snd_soup = BeautifulSoup(file, "html.parser")
                                
                        snd_main_div = snd_soup.find("div", id="main")
                        conf_pre = snd_main_div.find_all('pre')
                        capture = False
                        for pre in conf_pre:
                            if "Automatically generated file; DO NOT EDIT" in pre.get_text(strip=True):
                                finding = '\n'.join([tag.get_text(strip=True) for tag in conf_pre])
                                find = Conf_Find(finding, link)
                                subsection.append(find)
                                break
                            else:
                                items = pre.get_text(separator=' ', strip=True).split("|")
                                items = [item.strip() for item in items]
                                if capture and (plus_delim not in pre.get_text(strip=True)):
                                    if len(items) == 6:
                                        value_found = ""
                                        if "FAIL:" in items[5]:
                                            check_result = "FAIL"
                                            if len(items[5].split("FAIL:")) > 1:
                                                value_found = items[5].split("FAIL:")[1]
                                        elif "OK" in items[5]:
                                            check_result = "OK"
                                            if len(items[5].split("OK:")) > 1:
                                                value_found = items[5].split("OK:")[1]
                                        else:
                                            value_found = ""
                                            check_result = items[5]
                                        find = Find(items[0], items[1], items[2], items[3], items[4], check_result, value_found)
                                        subsection.append(find)

                                if items == ["option_name", "type", "desired_val", "decision", "reason", "check_result"]:
                                    capture = True
                                
                    next_raw = pre_tags[i + 1].get_text(separator=' ', strip=True)
                    if pre_tags[i + 1].find("span", class_="orange") and plus_delim not in next_raw and star_delim not in next_raw:
                        conclusion = next_raw

                subsection.conclusion = conclusion
                section.append_subsection(subsection)

        sections.append(section)


        JsonShared.write_json_file(json_file, sections)

    except FileNotFoundError:
        print(f"Error: The file '{in_file}' was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__=="__main__":
    main()





