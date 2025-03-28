#!/usr/bin/python3

import os, io, json, copy, re, sys
from typing import List, Optional
from dataclasses import dataclass


@dataclass
class Entry:
    def __init__(self, attr: str, val: str):
        self.attribute = attr
        self.value = val


@dataclass
class ItemDetails:
    def __init__(self, sumry: str, ents: Optional[List[Entry]] = None):
        self.summary = sumry
        self.entries = ents or []
        self.entry_count = len(self.entries) or 0

    def append(self, ent: Optional[Entry] = None):
        if ent is not None:
            self.entries.append(ent)
            self.entry_count += 1

    def reset(self):
        self.entries = []
        self.entry_count = 0

    def count(self):
        return self.entry_count


@dataclass
class Item:
    def __init__(self, tsk: str, idt: str, sts: str, tp: str, details_desc: ItemDetails):
        self.item_description = tsk
        self.item_details = idt
        self.item_format = "text"
        self.status = sts
        self.type = tp
        self.content = details_desc


@dataclass
class Found:
    def __init__(self, ovw: str, detls: Optional[List[Item]] = None):
        self.overview = ovw
        self.items = detls or []
        self.item_count = len(self.items) or 0

    def append(self, detl: Optional[Item] = None):
        if detl is not None:
            self.items.append(detl)
            self.item_count += 1

    def reset(self):
        self.items = []
        self.item_count = 0

    def count(self):
        return self.item_count


@dataclass
class Step:
    def __init__(self, step_desc: str, fnd: Optional[Found] = None):
        self.step_description = step_desc
        self.found = fnd


@dataclass
class Result:
    def __init__(self, result_desc: str, stps: Optional[List[Step]] = None):
        self.result_description = result_desc
        self.steps = stps or []
        self.step_count = len(self.steps) or 0

    def append(self, stp: Optional[Step] = None):
        if stp is not None:
            self.steps.append(stp)
            self.step_count += 1

    def reset(self):
        self.steps = []
        self.step_count = 0

    def count(self):
        return self.step_count


@dataclass
class Module:
    def __init__(self, mdul: str, module_desc: str, module_ref: str, rslt: Optional[Result] = None):
        self.module = mdul
        self.module_description = module_desc
        self.module_reference = module_ref
        self.result = rslt
        self.module_category = "Unknown"


@dataclass
class Modules:
    def __init__(self, mduls: Optional[List[Module]] = None):
        self.modules = mduls or []
        self.module_count = len(self.modules) or 0

    def append(self, mdul: Optional[Module] = None):
        if mdul is not None:
            self.modules.append(mdul)
            self.module_count += 1

    def reset(self):
        self.modules = []
        self.module_count = 0

    def count(self):
        return self.module_count

def find_files_with_prefix(directory, regex_pattern):
    filelist = []
    regex = re.compile(regex_pattern)
    for root, _, files in os.walk(directory):
        for file in files:
            if regex.match(file):  # Match the regex pattern
                filelist.append(os.path.join(root, file))
    return filelist

classification_matrix = {
    "d02_" : "Difference",
    "d05_" : "Difference",
    "d10_" : "Difference",
    "f02_" : "Unclassified",
    "f05_" : "Unclassified",
    "f10_" : "Overview",
    "f15_" : "Overview",
    "f20_" : "Overview",
    "f50_" : "Overview",
    "l10_" : "Emulation",
    "l15_" : "Emulation",
    "l20_" : "Emulation",
    "l22_" : "Emulation",
    "l23_" : "Emulation",
    "l25_" : "Emulation",
    "l35_" : "Emulation",
    "l99_" : "Emulation",
    "p02_" : "Preparation",
    "p05_" : "Preparation",
    "p07_" : "Preparation",
    "p10_" : "Preparation",
    "p14_" : "Preparation",
    "p15_" : "Preparation",
    "p17_" : "Preparation",
    "p18_" : "Preparation",
    "p19_" : "Preparation",
    "p20_" : "Preparation",
    "p21_" : "Preparation",
    "p22_" : "Preparation",
    "p23_" : "Preparation",
    "p25_" : "Preparation",
    "p35_" : "Preparation",
    "p40_" : "Preparation",
    "p55_" : "Preparation",
    "p60_" : "Preparation",
    "p61_" : "Preparation",
    "p65_" : "Preparation",
    "p99_" : "Preparation",
    "q02_" : "Preparation",
    "s02_" : "Bootloader & Firmware",
    "s03_" : "Bootloader & Firmware",
    "s04_" : "Kernel & OS",
    "s05_" : "Bootloader & Firmware",
    "s06_" : "Miscellaneous",
    "s07_" : "Bootloader & Firmware",
    "s08_" : "Miscellaneous",
    "s09_" : "Bootloader & Firmware",
    "s100_" : "Vulnerability",
    "s106_" : "Secrets & Passwords",
    "s107_" : "Secrets & Passwords",
    "s108_" : "Secrets & Passwords",
    "s109_" : "Secrets & Passwords",
    "s10_" : "Bootloader & Firmware",
    "s110_" : "Vulnerability",
    "s115_" : "Unclassified",
    "s116_" : "Unclassified",
    "s118_" : "Unclassified",
    "s12_" : "Bootloader & Firmware",
    "s13_" : "Vulnerability",
    "s14_" : "Vulnerability",
    "s15_" : "Miscellaneous",
    "s16_" : "Miscellaneous",
    "s17_" : "Vulnerability",
    "s18_" : "Vulnerability",
    "s19_" : "Kernel & OS",
    "s20_" : "Language Specific",
    "s21_" : "Language Specific",
    "s22_" : "Language Specific",
    "s23_" : "Vulnerability",
    "s24_" : "Kernel & OS",
    "s25_" : "Kernel & OS",
    "s26_" : "Kernel & OS",
    "s27_" : "Language Specific",
    "s35_" : "Language Specific",
    "s36_" : "Vulnerability",
    "s40_" : "Secrets & Passwords",
    "s45_" : "Secrets & Passwords",
    "s50_" : "Secrets & Passwords",
    "s55_" : "Miscellaneous",
    "s60_" : "Secrets & Passwords",
    "s65_" : "Miscellaneous",
    "s75_" : "Miscellaneous",
    "s80_" : "Miscellaneous",
    "s85_" : "Vulnerability",
    "s90_" : "Miscellaneous",
    "s95_" : "Miscellaneous",
    "s99_" : "Miscellaneous"
}

def main():
    directory = '.'
    module_delimiter = "[+] "
    module_mark = "======"
    step_delimiter = "==> "
    step_mark = "------"
    task_positive = "[+]"
    task_negative = "[-]"
    task_stats = "[*]"
    task_warn = "[!]"

    breakdown_entry = ":"

    argumentList = sys.argv[1:]

    # create the module array
    output_modules = Modules()
    filelist = []
    for filename in os.listdir(directory):
        f = os.path.join(directory, filename)
        # checking if it is a file
        if (os.path.isfile(f)) and (os.path.splitext(filename)[1] == '.txt'):
            if not argumentList:
                filelist.append(f)
            elif argumentList[0] == "preparation":
                regex = re.compile(r'^p\d+_.*\.txt$')
                if regex.match(filename):
                    filelist.append(f)
            elif argumentList[0] == "overview":
                regex = re.compile(r'^f\d+_.*\.txt$')
                if regex.match(filename):
                    filelist.append(f)
            elif argumentList[0] == "difference":
                regex = re.compile(r'^d\d+_.*\.txt$')
                if regex.match(filename):
                    filelist.append(f)
            elif argumentList[0] == "emulation":
                regex = re.compile(r'^l\d+_.*\.txt$')
                if regex.match(filename):
                    filelist.append(f)
            elif argumentList[0] == "modules":
                regex = re.compile(r'^s\d+_.*\.txt$')
                if regex.match(filename):
                    filelist.append(f)
            elif argumentList[0] == "ai":
                regex = re.compile(r'^q\d+_.*\.txt$')
                if regex.match(filename):
                    filelist.append(f)
            else:
                filelist.append(f)
    if filelist:
        # print(filelist, len(filelist))
        for f in filelist:
            # read file
            filename = os.path.basename(f)
            filename_cat = filename.split("_")[0] + "_"

            with open(f) as textFile:
                lines = [line.rstrip() for line in textFile]
                line_cnt = 0
                line = lines[line_cnt].replace("    ", "\t")  # parse module title if started with module_delimiter
                # create a module
                if module_delimiter in line:
                    output_module = Module(line.removeprefix(module_delimiter), "", filename)
                    if filename_cat in classification_matrix:
                        output_module.module_category = classification_matrix.get(filename_cat)
                    line_cnt += 1
                    line = lines[line_cnt].replace("    ", "\t")  # parse module mark =====
                    if module_mark in line:
                        # print("Module result start")
                        line_cnt += 1
                else:
                    output_module = Module(filename.removesuffix(".txt"), "", filename)

                if "s12_" in filename:
                    if 'output_step' in locals():
                        del output_step
                    if 'output_found' in locals():
                        del output_found
                    if 'output_item' in locals():
                        del output_item

                output_result = Result("")
                while line_cnt < len(lines):
                    line = lines[line_cnt].replace("    ", "\t")
                    if (step_delimiter not in line) and (step_mark not in line) and (task_positive not in line) and (
                            task_negative not in line) and (task_stats not in line) and (task_warn not in line):
                        if "s12_" in filename:
                            if not line.startswith("\t"):
                                output_module.module_description += "\n" + line
                        else:
                            output_module.module_description += "\n" + line

                        # special handlong for s12_...txt file
                        if "s12_" in filename:
                            if line.startswith("\t"):
                                line_modified = ",".join(line.split())
                                if 'output_step' not in locals():
                                    output_step = Step("Step")
                                if 'output_found' not in locals():
                                    output_found = Found("")
                                if 'output_item' not in locals():
                                    output_item = Item("Item", "", "Found", "Result", None)
                                output_item.item_details += line_modified + "\n"
                                output_item.item_format = "csv"
                    else:
                        if step_delimiter in line:
                            output_step = Step(line.removeprefix(step_delimiter).replace(step_delimiter, ""))
                            line_cnt += 1
                            line = lines[line_cnt].replace("    ", "\t")
                            if step_mark in line:
                                line_cnt += 1
                            output_found = Found("")
                            while line_cnt < len(lines):
                                line = lines[line_cnt].replace("    ", "\t")
                                if task_positive in line:
                                    output_item = Item(
                                        line.removeprefix(task_positive).replace(task_positive, "").replace("Found ", ""),
                                        "", "Found", "Result", None)
                                    export_item = copy.deepcopy(output_item)
                                    output_found.append(export_item)
                                    line_cnt += 1
                                elif task_negative in line:
                                    output_item = Item(
                                        line.removeprefix(task_negative).replace(task_negative, "").replace("Found ",
                                                                                                            "").replace(
                                            "NO ", ""), "", "Not-found", "Result", None)
                                    export_item = copy.deepcopy(output_item)
                                    output_found.append(export_item)
                                    line_cnt += 1
                                elif task_stats in line:
                                    if "s03_" in filename:
                                        output_item = Item(line.removeprefix(task_stats).replace(task_stats, ""), "",
                                                           "Found", "Result", None)
                                    else:
                                        output_item = Item(line.removeprefix(task_stats).replace(task_stats, ""), "", "N/A",
                                                           "Action-Statistics", None)
                                    export_item = copy.deepcopy(output_item)
                                    output_found.append(export_item)
                                    line_cnt += 1
                                elif task_warn in line:
                                    output_item = Item(line.removeprefix(task_warn).replace(task_warn, ""), "", "N/A",
                                                       "Warn-Info", None)
                                    export_item = copy.deepcopy(output_item)
                                    output_found.append(export_item)
                                    line_cnt += 1
                                elif step_mark in line:
                                    line_cnt += 1
                                    continue
                                elif step_delimiter in line:
                                    line_cnt -= 1
                                    break
                                else:
                                    if 'export_item' in locals():
                                        if "s03_" in filename:
                                            if "Operating system detection:" in line:
                                                line = line.replace("Operating system detection:",
                                                                    "Operating system detection,count")
                                            else:
                                                line = line.replace(":", ",")
                                        if "f20_" in filename:
                                            if "Vulnerability details for" in export_item.item_description:
                                                line = line.replace(":", ",")
                                            if "Minimal exploit summary file generated" in export_item.item_description:
                                                line = line.replace(":", ",")
                                        export_item.item_details += line + "\n"
                                        if "f15_" in filename:
                                            if "Cyclonedx SBOM in json and CSV format created:" in export_item.item_description:
                                                export_item.item_description = ""
                                                export_item.status = "N/A"
                                                export_item.type = "Action-Statistics"
                                            if "in json format:" in export_item.item_description:
                                                export_item.item_format = "json"
                                        if "s03_" in filename:
                                            export_item.item_format = "csv"
                                        if "f20_" in filename:
                                            if "Vulnerability details for" in export_item.item_description:
                                                export_item.item_format = "csv"
                                                export_item.status = "Found"
                                                export_item.type = "Result"
                                            if "Minimal exploit summary file generated" in export_item.item_description:
                                                export_item.item_format = "csv"
                                                export_item.status = "Found"
                                                export_item.type = "Result"
                                    line_cnt += 1
                                    continue
                        elif (task_positive in line) or (task_negative in line) or (task_stats in line) or (
                                task_warn in line):
                            output_step = Step("Step")
                            output_found = Found("")
                            while line_cnt < len(lines):
                                line = lines[line_cnt].replace("    ", "\t")
                                if task_positive in line:
                                    output_item = Item(line.removeprefix(task_positive).replace(task_positive, ""), "",
                                                       "Found", "Result", None)
                                    export_item = copy.deepcopy(output_item)
                                    output_found.append(export_item)
                                    line_cnt += 1
                                elif task_negative in line:
                                    output_item = Item(line.removeprefix(task_negative).replace(task_negative, ""), "",
                                                       "Not-found", "Result", None)
                                    export_item = copy.deepcopy(output_item)
                                    output_found.append(export_item)
                                    line_cnt += 1
                                elif task_stats in line:
                                    output_item = Item(line.removeprefix(task_stats).replace(task_stats, ""), "", "N/A",
                                                       "Actions / Statistics", None)
                                    export_item = copy.deepcopy(output_item)
                                    output_found.append(export_item)
                                    line_cnt += 1
                                elif task_warn in line:
                                    output_item = Item(line.removeprefix(task_warn).replace(task_warn, ""), "", "N/A",
                                                       "Warn-Info", None)
                                    export_item = copy.deepcopy(output_item)
                                    output_found.append(export_item)
                                    line_cnt += 1
                                elif step_mark in line:
                                    line_cnt += 1
                                    continue
                                elif step_delimiter in line:
                                    line_cnt -= 1
                                    break
                                else:
                                    if 'export_item' in locals():
                                        if "s03_" in filename:
                                            if "Operating system detection:" in line:
                                                line = line.replace("Operating system detection:",
                                                                    "Operating system detection,count")
                                            else:
                                                line = line.replace(":", ",")
                                        if "f20_" in filename:
                                            if "Vulnerability details for" in export_item.item_description:
                                                line = line.replace(":", ",")
                                            if "Minimal exploit summary file generated" in export_item.item_description:
                                                line = line.replace(":", ",")
                                        export_item.item_details += line + "\n"
                                        if "f15_" in filename:
                                            if "Cyclonedx SBOM in json and CSV format created:" in export_item.item_description:
                                                export_item.item_description = ""
                                                export_item.status = "N/A"
                                                export_item.type = "Action-Statistics"
                                            if "in json format:" in export_item.item_description:
                                                export_item.item_format = "json"
                                        if "s03_" in filename:
                                            export_item.item_format = "csv"
                                        if "f20_" in filename:
                                            if "Vulnerability details for" in export_item.item_description:
                                                export_item.item_format = "csv"
                                                export_item.status = "Found"
                                                export_item.type = "Result"
                                            if "Minimal exploit summary file generated" in export_item.item_description:
                                                export_item.item_format = "csv"
                                                export_item.status = "Found"
                                                export_item.type = "Result"
                                    line_cnt += 1
                                    continue
                        if 'output_found' in locals():
                            export_found = copy.deepcopy(output_found)
                            output_step.found = export_found
                            output_found.reset()
                            export_found.count()
                        if 'output_step' in locals():
                            export_step = copy.deepcopy(output_step)
                            output_result.append(export_step)
                    line_cnt += 1

                if "s12_" in filename:
                    export_item = copy.deepcopy(output_item)
                    output_found.append(export_item)
                    if 'output_found' in locals():
                        export_found = copy.deepcopy(output_found)
                        output_step.found = export_found
                        output_found.reset()
                        export_found.count()
                    if 'output_step' in locals():
                        export_step = copy.deepcopy(output_step)
                        output_result.append(export_step)

                export_result = copy.deepcopy(output_result)
                output_module.result = export_result
                output_result.reset()
                export_result.count()
                export_module = copy.deepcopy(output_module)
                output_modules.append(export_module)
    output_modules.count()
    print(json.dumps(output_modules, default=lambda o: o.__dict__).replace("emba", "BinScanTool").replace("EMBA", "BinScanTool").replace("e-m-b-a", "BinScanTool"))

if __name__=="__main__":
    main()