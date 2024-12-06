import re
import requests

# Parse out all IPs from a given string and returns a list of IPs
def parse_for_ip(text):
    ipv4_pattern=r"\b(?:(?:\d{1,2}|1\d{1,2}|2[0-4][0-9]|25[0-5])\.){3}(?:\d{1,2}|1\d{1,2}|2[0-4][0-9]|25[0-5])\b"
    ips =  re.findall(ipv4_pattern, text)
    return ips

# Enrich IP with VirusTotal data
# rate limit of 4 requests per minute
def enrich_virustotal(ip):
    base_url = "https://www.virustotal.com/api/v3/ip_addresses/"
    url = base_url + ip
    headers = {
        "accept": "application/json",
        "x-apikey": "00cda4011d0e13eda15114dd9f0db644175d7ecb49f256e9069158c0caa6d1c2"
    }
    
    status_code, response = send_request("GET", url, headers)

    # TODO handle rate limit and other response codes with logging and error handling

    return response



# API Request
def send_request(method, url, headers, data=None):
    if method == "GET":
        response = requests.get(url, headers=headers)
    elif method == "POST":
        response = requests.post(url, headers=headers, data=data)
    return response.status_code, response.json()
