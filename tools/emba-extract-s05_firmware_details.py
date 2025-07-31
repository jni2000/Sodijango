import sys
from bs4 import BeautifulSoup
import json
import JsonShared

class Find:
    def __init__(self, label, children):
        self.label = label
        self.children = children

def get_indent(line):
    indent = 0
    for c in line:
        if c == "[":
            break
        else:
            indent += 1
        # if c in ['│', ' ', '├', '└', '─', '┬', '┤', '├', '┼']:
        #     if c == ' ' or c == '─':
        #         indent += 1
        #     elif c in ['│', '├', '└']:
        #         indent += 2
        # else:
        #     break
    return indent


def parse_name(line):
    name = ""
    capture = False
    for c in line:
        if c == "[":
            capture = True
        if capture:
            name += c
    return name

def parse_filesystem(fs_string):
    lines = fs_string.strip().splitlines()
    root = None
    
    i = 0
    while i < len(lines):
        name = lines[i].split(']')[1].strip()
        if name == "softwarefiles":
            root = Find(parse_name(lines[i + 1]), [])
            i += 1
            break
        i += 1

    lines = lines[i:]
    stack = [(-1, root)]

    if not root:
        raise Exception("softwarefiles directory not found")
    for line in lines:
        indent = get_indent(line)
        while stack and indent <= stack[-1][0]:
            stack.pop()
        
        name = parse_name(line)
        find = Find(name, [])
        stack[-1][1].children.append(find)
        stack.append((indent, find))

    return root

def main():
    if len(sys.argv) > 1:
        in_file = sys.argv[1]
        json_file = sys.argv[2]
    else:
        in_file = "BinaryScanHTMLFiles/html-report/s05_firmware_details.html"
        json_file = "clean-text/s05_firmware_details.json"
    print("Extract " + in_file + " into " + json_file + "......")
    try:
        with open(in_file, "r", encoding="utf-8") as file:
            soup = BeautifulSoup(file, "html.parser")

        # Find the main div
        main_div = soup.find("div", id="main")
        pre_tags = main_div.find_all('pre')
        texts = [tag.get_text(strip=False) for tag in pre_tags]

        sections = JsonShared.Sections()

        section_delim = "==>"
        subsection_delim = "[-]"
        ## TODO: what if subsection delimiter is different? Possibly based on results of Release/Version Information section? 

        i = 0
        while i < len(texts):
            if section_delim in texts[i]:
                    
                section = JsonShared.Section(texts[i].removeprefix(section_delim))

                ## Special case for Filesystem information section
                fs_section = []
                if "Filesystem information" in texts[i]:
                    for j in range(i + 1, len(texts)):
                        if section_delim in texts[j]:
                            i = j
                            break
                        fs_section.append(texts[j])
                    fs_string = "\n".join(fs_section[:-1])
                    root = parse_filesystem(fs_string)
                    subsection = JsonShared.Subsection("", fs_section[-1])
                    subsection.append(root)
                    section.append_subsection(subsection)
                else:
                    j = i + 1
                    while j < len(texts):
                        if section_delim in texts[j]:
                            break
                        subsection = JsonShared.Subsection(texts[j].removeprefix(subsection_delim))
                        section.append_subsection(subsection)
                        j += 1
                    i = j - 1

                sections.append(section)
            i += 1

        JsonShared.write_json_file(json_file, sections)

    except FileNotFoundError:
        print(f"Error: The file '{in_file}' was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__=="__main__":
    main()


