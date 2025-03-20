"""Script that scan ips from dshield api using virustotal api."""


from pyrate_limiter import Duration, Rate, Limiter, BucketFullException
import time
import re
import os
import requests
import json
from dotenv import load_dotenv
load_dotenv()
API_KEY = os.getenv("TV_API_KEY")
BASE_URL = os.getenv("TV_LINK")
FILE_PATH = os.environ.get("IP_Data_Save_Path")
SAVE_PATH = os.environ.get("IP_Report_Save_Path")
re_ipaddress_pattern = r"((\d{1,3}\.){3})\d{1,3}"

# Limits for flow control on VT 4 per hour 500 per day
hour_rate = Rate(4, Duration.MINUTE)
daily_rate = Rate(500, Duration.DAY)
rates = [hour_rate, daily_rate]
limiter = Limiter(rates)


# Function to get info from sample file
def get_ips_from_file():
    ip_list = []
    with open(FILE_PATH, "r") as f:
        sample_file = f.readlines()
        for line in sample_file:
            # Two re.search first gets pattern function data
            if re.search(re_ipaddress_pattern, line):
                # Declutters first search to only 'ip-data' selected
                m = re.search(re_ipaddress_pattern, line).group()
                ip_list.append(m)
        return ip_list


# Function to run ips against VT IP API
def run_ips_vt_api(ip_list):
    # Loop to iterate ips
    for ips in ip_list:
        try:
            # Leaky bucket stops program if to many request per time allotted
            limiter.try_acquire(ips)
            # injecting url ips and key to run api
            headers = {"accept": "application/json",
                       "x-apikey": f"{API_KEY}"}
            response = requests.get(f"{BASE_URL}/{ips}", headers=headers)
            # Loading data as parse json format
            data = response.json()
            # Saving part of response that includes if malicious or not
            with open(SAVE_PATH, "a") as f:
                reputation = json.dumps(data["data"]["attributes"]["last_analysis_stats"])
                f.write(f"IP: {ips} Reputation: {reputation}\n")
            # Rate on repeat less then 4 per min
            time.sleep(16)
        except ValueError:
            print("Error")
        except BucketFullException as err:
            print(err)
            print(err.meta_info)


def main():
    ip_list = get_ips_from_file()
    run_ips_vt_api(ip_list)


main()
