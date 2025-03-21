#!/usr/bin/env python3
"""
this script is to extract fruit data from txt files in "description" directory,
prepare a PDF report, and then email it
"""
import reports
import emails
from datetime import date
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def process_fruit_data(data_dir):
  """process .txt filepaths from source directory and return list of dictionaries"""
  desc_listdict =[]
  try:
    for filename in os.listdir(data_dir):
        if filename.lower().endswith(".txt"):
            filepath = os.path.join(data_dir,filename)
            try:
                with open(filepath, "r") as raw_text:
                    lines = raw_text.readlines()
                    if len(lines) < 2: #check for feedback files with missing entries
                        logging.warning(f"Error: file '{filepath}' may not contain all necessary entries")
                        continue          
                    
                    desc_dict ={
                        "name":lines[0].strip(), 
                        "weight":lines[1].strip() 
                    }
                    desc_listdict.append(desc_dict)
            except FileNotFoundError:
                logging.error(f"Error: File not found:{filepath}")
            except Exception as e:
                logging.error(f"An unexpected error occurred:{e}")
  except FileNotFoundError:
      logging.error(f"Directory not found:{data_dir}")
      return []
  except OSError as e:
      logging.error(f"Error accessing directory {data_dir}:{e}")
      return []

  return desc_listdict

def prepare_fruits_weight_paragraph(data_dir):
  """prepares paragraph summarising fruit names and weights"""
  fruit_data = process_fruit_data(data_dir)
  summary = []
  if fruit_data:
    for item in fruit_data:
      summary.append(f"name: {item['name']}")
      summary.append(f"weight: {item['weight']}")
      summary.append("")
  return summary

if __name__ == "__main__":
    """pdf report parameters"""
    data_dir = os.path.expanduser("~/supplier-data/descriptions/")
    attachment = "/tmp/processed.pdf"
    title = f"Processed Update on {date.today()}"
    summary = prepare_fruits_weight_paragraph(data_dir)
    paragraph = "<br/>".join(summary)
  
    """email parameters"""
    sender = "automation@example.com"
    receiver = "student@example.com"
    subject = "Upload Completed - Online Fruit Store"
    body = "All fruits are uploaded to our website successfully. A detailed list is attached to this email."
  
    try:
        reports.generate_report(attachment, title, paragraph)
        message = emails.generate_email(sender, receiver, subject, body, attachment)
        emails.send_email(message)
        logging.info("Report generated and email sent successfully.")
    except Exception as e:
        logging.exception(f"Error generating report or sending email: {e}")
  

