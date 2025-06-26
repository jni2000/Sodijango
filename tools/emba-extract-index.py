#!/usr/bin/python3

import os
from bs4 import BeautifulSoup
try:
    # Prompt the user to enter the filename
    in_file = input("Enter the name of the file to open: ")

    # Open the file in read mode ('r')
    # The 'with' statement ensures the file is properly closed even if errors occur
    with open(in_file, 'r') as file:
        # Read the content of the file
        html_data = file.read()
        soup = BeautifulSoup(html_data, 'html.parser')
        div_to_extract = soup.find('div', id='main')
        if div_to_extract:
            extracted_content = str(div_to_extract)
            out_file = os.path.splitext(in_file)[0] + "_extracted" + os.path.splitext(in_file)[1]
            with open(out_file, 'w', encoding='utf-8') as f:
                f.write(extracted_content)
            # find all links and save to a file
            # soup1 = BeautifulSoup(extracted_content, 'html.parser')
            all_links = div_to_extract.find_all('a')
            link_file = os.path.splitext(out_file)[0] + "_links.csv"
            with open(link_file, 'w', encoding='utf-8') as f:  # Use 'with open' to ensure the file is closed properly
                # Iterate through the extracted <a> tags
                for link in all_links:
                    # Extract the link text and the href attribute
                    link_text = link.get_text().replace("[+]", "   ").lstrip()  # Get the text within the <a> tag
                    link_text = link_text.replace("[*]", "   ").lstrip()  # Get the text within the <a> tag
                    link_url = link.get('href')  # Get the value of the 'href' attribute

                    # Write the information to the file
                    if link_url is not None:
                        f.write(f"{link_text}, ")
                        f.write(f"{link_url}\n")
except FileNotFoundError:
    print(f"Error: The file '{in_file}' was not found.")
except Exception as e:
    print(f"An error occurred: {e}")
