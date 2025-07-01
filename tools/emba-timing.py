#!/usr/bin/python3

import os, io, json, copy, re, sys
from typing import List, Optional
from dataclasses import dataclass

def main():
    argumentList = sys.argv[1:]
    f = argumentList[0]
    #print("Process " + f + ".")
    starting = []
    finished = []
    with open(f) as textFile:
        lines = [line.rstrip() for line in textFile]
        line_cnt = 0
        while line_cnt < len(lines):
            line = lines[line_cnt]
            line_split = line.split(" - ")
            temp = line_split[0]
            line_split[0] = line_split[1]
            line_split[1] = temp
            line = ", ".join(line_split)
            line = line.replace("[*] ", "").replace("^M", "").replace(" ", ",").replace(",,", ",")
            if "starting" in line:
                starting.append(line)
            elif "finished" in line:
                finished.append(line)
            line_cnt += 1
        starting.sort()
        finished.sort()
        line_cnt = 0
        length = len(starting)
        if len(starting) != len(finished):
            print("Warning -- started tasks do not match the finished ones!")
            length = min(len(starting), len(finished))
        print("start_day, start_month, start_date, start_time, start_time_zone, start_year, start_module, start_note, finish_day, finish_month, finish_date, finish_time, finish_time_zone, finish_year, finish_module, finish_note\n")
        while line_cnt < length:
            print(starting[line_cnt] + ", " + finished[line_cnt])
            line_cnt += 1

if __name__=="__main__":
    main()
