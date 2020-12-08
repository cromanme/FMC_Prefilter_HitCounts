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

def converttime(date_info):
    if len(date_info) > 5:
        init_time = date_info
        init_time = init_time.replace('Z', '')
        init_time = init_time.replace('T', ' ')

        from_zone = tz.gettz('UTC')
        to_zone = tz.gettz('America/Lima')

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
    
    uri = "https://10.80.83.68/api/"
    user = input("Username: ")
    passwd = getpass("Password: ")
    print()

    # Request Authentication Token

    url = uri + "fmc_platform/v1/auth/generatetoken"
    response = requests.request("POST", url, auth=(user,passwd), verify=False)
    if response.status_code == 200 or response.status_code == 204:
        token = response.headers.get("X-auth-access-token")
        domain_uuid = response.headers.get("DOMAIN_UUID")
    else:
        sys.exit("Invalid Credentials")

    # Request Access Policies

    url = uri + "fmc_config/v1/domain/"+ domain_uuid +"/policy/accesspolicies"
    headers = {
    'X-auth-access-token': token
    }
    response = requests.request("GET", url, headers=headers, verify=False)
    acp_id = response.json().get("items")[0].get("id")

    # Request Device ID

    url = uri + "fmc_config/v1/domain/"+ domain_uuid +"/deviceclusters/ftddevicecluster"
    headers = {
    'X-auth-access-token': token
    }
    parameters = {'expanded': "true"}
    response = requests.request("GET", url, headers=headers, params=parameters, verify=False)
    device_id = response.json().get("items")[0].get("masterDevice").get("id")

    # Refresh ACP HitCounts
    print("Refreshing ACP Hit Counts, please wait...")
    url = uri + "fmc_config/v1/domain/"+ domain_uuid +"/policy/accesspolicies/"+ acp_id +"/operational/hitcounts"
    headers = {
    'X-auth-access-token': token
    }
    parameters = {'filter': '"deviceid:'+device_id+'"',
                }
    response = requests.request("PUT", url, headers=headers, params=parameters, verify=False)
    time.sleep(29)

    # Request ACP HitCounts
    print("Retrieving ACP Hit Coutns..")
    url = uri + "fmc_config/v1/domain/"+ domain_uuid +"/policy/accesspolicies/"+ acp_id +"/operational/hitcounts"
    headers = {
    'X-auth-access-token': token
    }
    parameters = {'filter': '"deviceid:'+device_id+'"',
                'limit': '100',
                'expanded': 'true'
                }
    response = requests.request("GET", url, headers=headers, params=parameters, verify=False)
    rules = response.json().get("items")

    # now we will open a file for writing 
    data_file = open('data_file.csv', 'w') 

    # create the csv writer object 
    csv_writer = csv.writer(data_file) 

    # Headers to the CSV file 

    csv_headers = ["Rule Name", "Policy Name", "HitCount", "First Hit Time", "Last Hit Time"]
    csv_writer.writerow(csv_headers) 
    row = []

    for rule in rules:
        row.append(rule.get("rule").get("name"))
        row.append(str(rule.get("metadata").get("policy").get("name")))
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

