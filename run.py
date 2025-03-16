#! /usr/bin/env python3
"""
the purpose for this script is to upload customer reviews in the form of individual text files
and display on company's website. The script is to convert .txt files into dictionaries
and upload it to website using Django
"""

import os
import requests

def get_feedback_files(input_source):
    """gets a list of .txt files in the specified directory"""
    try:
        allfiles = os.listdir(input_source)
        feedback_files = [filename for filename in allfiles if filename.lower().endswith("txt")]
        return feedback_files 
    except FileNotFoundError:
        print(f"Error: Directory '{input_source}' not found.")
        return [] 

def create_feedback_listdict(source_dir):
    """creates a list of dictionaries from feedback text files"""
    Files_to_Process = get_feedback_files(source_dir)
    feedback_listdict =[]
    try:
        for feedback in Files_to_Process:
            filepath = os.path.join(source_dir, feedback)
            with open(filepath, "r") as raw_text:
                lines = raw_text.readlines()
            
            if len(lines) < 4: #check for feedback files with missing entries
                print(f"Error: file '{feedback}' may not contain all necessary entries")
                continuels

            feedback_dict = {"title": lines[0].strip(), "name": lines[1].strip(), "date":lines[2].strip(), "feedback": lines[3].strip()}
            feedback_listdict.append(feedback_dict)
        return feedback_listdict
    except Exception as e:
        print(f"Error reading file:{e}")
        return None 

def post_feedback(url, feedback_data):
    """post feedback data to specified url"""
    if feedback_data:
        for text_to_post in feedback_data:
            try:
                response = requests.post(url, json=text_to_post)
                if response.status_code == 201:
                    print("Feedback sucessfully posted.")
                else:
                    print(f"Error posting data. Status code: {response.status_code}")
                    print(response.text)
            except requests.exceptions.RequestException as e:
                print(f"An error occurred:{e}")
    else:
        print("Oops. nothing to post")

if __name__ == "__main__":
    source_dir = "/data/feedback"
    url = "http://34.168.221.147/feedback/"
    feedback_data = create_feedback_listdict(source_dir)
    post_feedback(url, feedback_data)