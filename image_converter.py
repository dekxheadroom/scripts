#!/usr/bin/env python3

#this script is to batch convert images in a folder to
#.jpeg format, resolution 128 x 128 px, portrait orientation

from PIL import Image
import os

#define paths and configurations
input_dir = "images"
output_dir = "/opt/icons/"
target_format = "JPEG"
target_size = (128, 128)
final_angle = 90

#get image files in input directory
#check if content is a file
try:
  raw_image_files = [img for img in os.listdir(input_dir) if os.path.isfile(os.path.join(input_dir, img))]
except FileNotFoundError:
  print(f"Error: Input Directory '{input_dir}' not found.")
  exit()

#create output directory
os.makedirs(output_dir, exist_ok=True)

#process images
for img_file in raw_image_files:
  input_path = os.path.join(input_dir, img_file)
  #prefix processed file name with "new"
  new_file_name = "new_" + img_file
  output_path = os.path.join(output_dir,new_file_name) 
  try:
    with Image.open(input_path) as raw_image:
      output_img = raw_image.rotate(final_angle).resize(target_size).convert('RGB').save(output_path, target_format)
      print(f"Processed: {input_path} -> {output_path}")
  except FileNotFoundError:
    print(f"Error: Input file '{input_path} not found.")
  except Exception as e:
    print(f"Error processing '{input_path}: {e}")
    print(f"  Error details: {e}")
    continue

  print("Image processing complete")