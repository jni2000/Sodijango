import json
from typing import List, Optional
from dataclasses import dataclass

@dataclass
class Subsection:
    def __init__(self, desc: str, cncl: str = "", finds: Optional[List] = None, gui_display: bool = True):
        self.description = desc
        self.conclusion = cncl
        self.finds = finds or []
        self.find_count = len(self.finds) or 0
        self.gui_display = gui_display

    def append(self, find):
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
    def __init__(self, desc: str, subsecs: Optional[List[Subsection]] = None, nt: str = "", gui_display: bool = True):
        self.description = desc
        self.subsections = subsecs or []
        self.subsection_count = len(self.subsections) or 0
        self.note = nt
        self.gui_display = gui_display

    def append_subsection(self, subsec: Optional[Subsection] = None):
        if subsec is not None:
            self.subsections.append(subsec)
            self.subsection_count += 1

    def reset(self):
        self.subsections = []
        self.subsection_count = 0

    def count(self):
        return self.subsection_count
    
    def to_json(self):
        return {
            "description": self.description,
            "subsections": self.subsections,
            "subsection_count": self.subsection_count
        }
    
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


def write_json_file(filepath: str, json_object):
    with open(filepath, 'w', encoding='utf-8') as f:  # Use 'with open' to ensure the file is closed properly
                        f.writelines(json.dumps(json_object, default=lambda o: o.__dict__))
