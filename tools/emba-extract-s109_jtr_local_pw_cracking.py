import sys
from bs4 import BeautifulSoup
import JsonShared

def main():
    if len(sys.argv) > 1:
        in_file = sys.argv[1]
        json_file = sys.argv[2]
    else:
        in_file = "BinaryScanHTMLFiles/html-report/s109_jtr_local_pw_cracking.html"
        json_file = "clean-text/s109_jtr_local_pw_cracking.json"
    print("Extract " + in_file + " into " + json_file + "......")


    try:
         # Load the HTML content
        with open(in_file, "r", encoding="utf-8") as file:
            soup = BeautifulSoup(file, "html.parser")

    except FileNotFoundError:
        print(f"Error: The file '{in_file}' was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")