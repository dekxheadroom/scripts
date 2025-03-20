#! /usr/bin/env python3
"""
the purpose for this script is to upload fruit descriptions and their image to 
fruit catalog server that runs on Django
"""

import os
import requests
import json
import re
import logging

#configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_desc_files(source_dir):
    """gets a list of .txt filepaths from source directory"""
    try:
        desc_file_paths = [
            os.path.join(source_dir, filename) 
            for filename in os.listdir(source_dir) 
            if filename.lower().endswith(".txt")
        ]
        return desc_file_paths 
    except FileNotFoundError:
        logging.error(f"Error: Input Directory '{source_dir}' not found.")
        return[]
    except OSError as e:
       logging.error(f"Error accessing directory:{e}")
       return[]

def create_desc_listdict(data_dir):
    """creates a list of dictionaries from description text files"""
    Desc_to_Process = get_desc_files(data_dir) #Desc_to_Process is list of paths to each description text file 
    desc_listdict =[]
    for description_path in Desc_to_Process:
        try:
            with open(description_path, "r") as raw_text:
                lines = raw_text.readlines()
            if len(lines) < 3: #check for feedback files with missing entries
                logging.warning(f"Error: file '{description_path}' may not contain all necessary entries")
                continue
            
            #extract filename without extension so as to use it for image file name
            filename_no_ext = os.path.splitext(os.path.basename(description_path))[0]
            
            desc_dict = {
                "name": lines[0].strip(), 
                "weight": int(re.search(r'\d+', lines[1].strip()).group(0)), 
                "description":lines[2].strip(), 
                "image_name":f"{filename_no_ext}.jpeg"
            }
            desc_listdict.append(desc_dict)
        except FileNotFoundError:
            logging.error(f"Error: File not found:{description}")
        except requests.exceptions.RequestException as e:
            logging.error(f"Error uploading {description}:{e}")
        except Exception as e:
            logging.error(f"An unexpected error occurred:{e}")
    
    return desc_listdict

def post_feedback(url, description_data):
    """post description data to specified url"""
    if description_data:
        for desc_to_post in description_data:
            try:
                response = requests.post(url, json=desc_to_post)
                response.raise_for_status()
                logging.info(f"Feedback sucessfully posted for: {desc_to_post['name']}.")
            except requests.exceptions.RequestException as e:
                logging.error(f"An error posting data:{e}")
    else:
        logging.warning("Oops. nothing to post")

if __name__ == "__main__":
    image_dir = os.path.expanduser("~/supplier-data/images/")
    data_dir = os.path.expanduser("~/supplier-data/descriptions/")
    url = "http://35.193.139.119/fruits/"
    description_data = create_desc_listdict(data_dir)
    post_feedback(url, description_data)