"""Query data that has malicous IPs."""


# Modules and API load
from dotenv import load_dotenv
import requests
import os
load_dotenv()
API_KEY = os.getenv("DSHIELD_API_KEY")
BASE_URL = os.getenv("DSHIELD_LINK")
SAVE_PATH = os.getenv("IP_Data_Save_Path")


# Function to get IP's info from Dshield
def get_notable_ips():
    headers = {"User-Agent": "Dshield-API-Client"}
    response = requests.get(f"{BASE_URL}/intelfeed?json", headers=headers)
    if response.status_code == 200:
        try:
            data = response.json()
            return data
        except ValueError:
            return {"error": "Invalid JSON response"}
    else:
        return {"error": "Failed to fetch data", "status code": response.status_code}


# Function that reformats json data to txt file
def save_data(data):
    with open(SAVE_PATH, "w") as f:
        for data in data:
            forstr = f"IP: {data.get('ip', 'unknown')} - Category: {data.get('description', 'Unknown')}\n"
            f.write(forstr)


# Main function to run for api
def main():
    data = get_notable_ips()
    save_data(data)


main()
