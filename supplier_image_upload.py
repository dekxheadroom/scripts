#!/usr/bin/env python3
"""
this script is to upload jpeg files from local host to web server. 
get list of JPEG files, iterate through list and use post request to upload. 
"""

import requests
import os
import logging

#configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

#define paths and configurations
source_dir = os.path.expanduser("~/supplier-data/images/")
url = "http://localhost/upload/"

def get_jpeg_filepaths(source_dir):
    '''get list of jpeg image filepath from source directory'''
    try:
      jpeg_image_filepaths = [
        os.path.join(source_dir,img) 
        for img in os.listdir(source_dir) 
        if os.path.isfile(os.path.join(source_dir, img)) 
        and os.path.splitext(img)[1].lower() in (".jpg",".jpeg") 
      ]
      return jpeg_image_filepaths
    except FileNotFoundError:
       logging.error(f"Error: Input Directory '{source_dir}' not found.")
       return[]
    except OSError as e:
       logging.error(f"Error accessing directory:{e}")
       return[]

def upload_images(url, filepaths):
    """upload JPEG files from local host to web server"""
    for filepath in filepaths:
      try:
        with open(filepath, 'rb') as opened:
           response = requests.post(url, files={'file': opened})
           response.raise_for_status()
           logging.info(f"Uploaded {filepath} - Status code:{response.status_code}")
      except FileNotFoundError:
         logging.error(f"Error: File not found:{filepath}")
      except requests.exceptions.RequestException as e:
         logging.error(f"Error uploading {filepath}:{e}")
      except Exception as e:
         logging.error(f"An unexpected error occurred:{e}")

if __name__ == "__main__":
  jpeg_files = get_jpeg_filepaths(source_dir)
  if jpeg_files:
     upload_images(url, jpeg_files)
  else:
     logging.info("No JPEG files found to upload.")