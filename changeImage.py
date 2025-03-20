#!/usr/bin/env python3

#this script is to batch convert images in a folder to
#.jpeg format, resolution 600 x 400 px

from PIL import Image
import os

#define paths and configurations
input_dir = os.path.expanduser("~/supplier-data/images/")
output_dir = os.path.expanduser("~/supplier-data/images/")
target_format = "JPEG"
target_size = (600, 400)

#get tiff image files in source directory
#check if content is a tiff file
try:
  tiff_image_files = [
    img 
    for img in os.listdir(input_dir) 
    if os.path.isfile(os.path.join(input_dir, img)) 
    and os.path.splitext(img)[1].lower() in (".tif",".tiff") 
    ]
except FileNotFoundError:
  print(f"Error: Input Directory '{input_dir}' not found.")
  exit()


#process images
for raw_file in tiff_image_files:
  input_path = os.path.join(input_dir, raw_file)
  output_path = os.path.join(output_dir,os.path.splitext(raw_file)[0] + ".jpeg") 
  try:
    with Image.open(input_path) as raw_image:
      raw_image.resize(target_size).convert('RGB').save(output_path)
      print(f"Processed: {input_path} -> {output_path}")
  except FileNotFoundError:
    print(f"Error: Input file '{input_path} not found.")
  except Exception as e:
    print(f"Error processing '{input_path}: {e}")
    print(f"  Error details: {e}")
    continue

print("Image processing complete")