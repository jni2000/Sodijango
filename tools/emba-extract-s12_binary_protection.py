import sys
from bs4 import BeautifulSoup
import json
import JsonShared

class Find:
    def __init__(self, relro, canary, nx, pie, rpath, runpath, symbols, forti, file):
        self.relro = relro
        self.canary = canary
        self.nx = nx
        self.pie = pie
        self.rpath = rpath
        self.runpath = runpath
        self.symbols = symbols
        self.forti = forti
        self.file = file

def main():
    if len(sys.argv) > 1:
        in_file = sys.argv[1]
        json_file = sys.argv[2]
    else:
        in_file = "BinaryScanHTMLFiles/html-report/s12_binary_protection.html"
        json_file = "clean-text/s12_binary_protection.json"
    print("Extract " + in_file + " into " + json_file + "......")
    try:

        sections = JsonShared.Sections()
        section = JsonShared.Section("Binary Protections")
        subsection = JsonShared.Subsection("")

        with open(in_file, "r", encoding="utf-8") as file:
            soup = BeautifulSoup(file, "html.parser")

        # Find the main div
        main_div = soup.find("div", id="main")
        pre_tags = main_div.find_all('pre')
        texts = [tag.get_text(strip=True) for tag in pre_tags]


        start = False
        header = ['RELRO', 'CANARY', 'NX', 'PIE', 'RPATH', 'RUNPATH', 'SYMBOLS', 'FORTI', 'FILE']
        for tag in pre_tags:
            if start:
                spans = tag.find_all("span")
                span_texts = [span.get_text(strip=True) for span in spans]
                span_colors = [span.get("class")[0] for span in spans]

                plain_text = ''
                for s in tag.strings:
                    if not isinstance(s, str):
                        continue
                    if s.parent.name == 'span':
                        continue  # Skip span text
                    plain_text += s


                ## TODO: Will Forti column always only have one word?
                span_texts.append(plain_text.split()[0])
                span_texts.append(" ".join(plain_text.split()[1:]))

                find = Find((span_texts[0], span_colors[0]), (span_texts[1], span_colors[1]), (span_texts[2], span_colors[2]), (span_texts[3], span_colors[3]), (span_texts[4], span_colors[4]), (span_texts[5], span_colors[5]), (span_texts[6], span_colors[6]), span_texts[7], span_texts[8])
                subsection.append(find)
            if tag.get_text(strip=True).split() == header:
                start = True


        section.append_subsection(subsection)
        sections.append(section)
        JsonShared.write_json_file(json_file, sections)
            
    except FileNotFoundError:
        print(f"Error: The file '{in_file}' was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__=="__main__":
    main()