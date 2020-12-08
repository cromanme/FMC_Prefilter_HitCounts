# -*- coding: utf-8 -*-
__author__ = "Christian Méndez Murillo"
__email__ = "cmendezm@cisco.com"
__copyright__ = """
Copyright 2020, Cisco Systems, Inc. 
All Rights Reserved. 
 
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES 
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND 
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT 
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR 
OTHER DEALINGS IN THE SOFTWARE. 
"""
__status__ = "Development"  # Prototype, Development or Production

import sys
import logging
import requests
import json
import csv
import time
from datetime import datetime
from dateutil import tz
from getpass import getpass

requests.packages.urllib3.disable_warnings()

logging.basicConfig(filename='app.log', 
                    filemode='w', 
                    format='%(levelname)s_%(message)s',
                    level=logging.INFO)

LOGGER = logging.getLogger(__name__)

def converttime(date_info):
    if len(date_info) > 5:
        init_time = date_info
        init_time = init_time.replace('Z', '')
        init_time = init_time.replace('T', ' ')

        from_zone = tz.gettz('UTC')
        to_zone = tz.gettz('America/Costa_Rica')

        # utc = datetime.utcnow()
        utc = datetime.strptime(init_time, '%Y-%m-%d %H:%M:%S')

        # Tell the datetime object that it's in UTC time zone since 
        # datetime objects are 'naive' by default
        utc = utc.replace(tzinfo=from_zone)

        # Convert time zone
        lima_time = utc.astimezone(to_zone)
        lima_time = str(lima_time)
        lima_time = lima_time.replace('-05:00',' UTC -5')
        return lima_time
    else:
        return date_info


# Module Functions and Classes
def main(*args):

    print()
    
    uri = "https://172.29.1.237/api/"
    user = input("Username: ")
    passwd = getpass("Password: ")
    print()

    # Request Authentication Token

    url = uri + "fmc_platform/v1/auth/generatetoken"
    response = requests.request("POST", url, auth=(user,passwd), verify=False)
    LOGGER.info(f"Requesting authentication token...")
    LOGGER.info(f"Response status code = {response.status_code}")
    if response.status_code == 200 or response.status_code == 204:
        token = response.headers.get("X-auth-access-token")
        domain_uuid = response.headers.get("DOMAIN_UUID")
        LOGGER.info(f"Token value: {token}")
        LOGGER.info(f"Domain UUID Value: {domain_uuid}")
    else:
        sys.exit("Invalid Credentials")

    # Request Prefilter Policies

    LOGGER.info(f"Requesting Prefilter Policies list...")
    url = uri + "fmc_config/v1/domain/"+ domain_uuid +"/policy/prefilterpolicies"
    headers = {
    'X-auth-access-token': token
    }
    response = requests.request("GET", url, headers=headers, verify=False)
    LOGGER.info(f"Response status code = {response.status_code}")
    filter_id = response.json().get("items")[1]["id"]
    filter_name = response.json().get("items")[1]["name"]
    LOGGER.info(f"Prefilter Name value: = {filter_name}")
    LOGGER.info(f"Prefilter ID value: = {filter_id}")

    # Request HA Device ID

    LOGGER.info(f"Requesting HA Device ID...")
    url = uri + "fmc_config/v1/domain/"+ domain_uuid +"/devicehapairs/ftddevicehapairs"
    headers = {
    'X-auth-access-token': token
    }
    parameters = {'expanded': "true"}
    response = requests.request("GET", url, headers=headers, params=parameters, verify=False)
    LOGGER.info(f"Response status code = {response.status_code}")
    device_id = response.json().get("items")[0].get("id")
    device_id = response.json().get("items")[0].get("id")
    LOGGER.info(f"Response status code = {response.status_code}")
    LOGGER.info(f"Response status code = {response.status_code}")

    # Refresh Prefilter HitCounts
    print("Refreshing Prefilter HitCounts, please wait...")
    LOGGER.info(f"Refreshing Prefilter HitCounts...")
    url = uri + "fmc_config/v1/domain/"+ domain_uuid +"/policy/prefilterpolicies/"+ filter_id +"/operational/hitcounts"
    headers = {
    'X-auth-access-token': token
    }
    parameters = {'filter': '"deviceid:'+device_id+'"',
                }
    response = requests.request("PUT", url, headers=headers, params=parameters, verify=False)
    LOGGER.info(f"Response status code = {response.status_code}")
    time.sleep(29)

    # Open a file for writing 
    data_file = open('data_file.csv', 'w') 

    # Create the CSV writer object 
    csv_writer = csv.writer(data_file) 

    # Define headers to the CSV file 

    csv_headers = ["Rule Index", "Policy Name", "Rule Name", "Description", "HitCount", "First Hit Time", "Last Hit Time"]
    csv_writer.writerow(csv_headers) 
    row = []

    # Request Prefilter HitCounts
    print("Retrieving Prefilter Hit Coutns..")
    LOGGER.info(f"Retrieving Prefilter Hit Coutns..")
    offset_number = 0

    url = uri + "fmc_config/v1/domain/"+ domain_uuid +"/policy/prefilterpolicies/"+ filter_id +"/operational/hitcounts"
    headers = {
    'X-auth-access-token': token
    }
    offset_number = 0
    parameters = {'filter': '"deviceid:'+device_id+'"',
                'offset': offset_number,
                'limit': '100',
                'expanded': 'true'
                }
    response = requests.request("GET", url, headers=headers, params=parameters, verify=False)
    LOGGER.info(f"Response status code = {response.status_code}")
    rules = response.json().get("items")
    count = response.json().get("paging").get("count")

    for rule in rules:
        row.append(str(rule.get("metadata").get("ruleIndex")))
        row.append(str(rule.get("metadata").get("policy").get("name")))
        row.append(str(rule.get("rule").get("name")))
        row.append(str(rule.get("metadata").get("policy").get("description")))
        row.append(str(rule.get("hitCount")))
        row.append(converttime(rule.get("firstHitTimeStamp")))
        row.append(converttime(rule.get("lastHitTimeStamp")))
        csv_writer.writerow(row)
        row = []
    
    data_file.close() 
    print("Script successfully completed")

# Check to see if this file is the "__main__" script being executed
if __name__ == '__main__':
    _, *script_args = sys.argv
    main(*script_args)


