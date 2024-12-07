import re
import requests
import time

# Parse out all IPs from a given string and returns a list of IPs
def parse_for_ip(text):
    ipv4_pattern=r"\b(?:(?:\d{1,2}|1\d{1,2}|2[0-4][0-9]|25[0-5])\.){3}(?:\d{1,2}|1\d{1,2}|2[0-4][0-9]|25[0-5])\b"
    ips =  re.findall(ipv4_pattern, text)
    return ips

# Enrich IP with VirusTotal data
# rate limit of 4 requests per minute
def enrich_virustotal(logger, ip):
    base_url = "https://www.virustotal.com/api/v3/ip_addresses/"
    url = base_url + ip
    headers = {
        "accept": "application/json",
        "x-apikey": "00cda4011d0e13eda15114dd9f0db644175d7ecb49f256e9069158c0caa6d1c2"
    }
    logger.info(url)
    logger.info(headers)
    status_code, response = send_request("GET", url, headers)
    logger.info(response)

    # DONE handle rate limit and other response codes with logging and error handling
    if status_code == 429:
        logger.error(response)
        time.sleep(60)
        status_code, response = send_request("GET", url, headers)

    return response

# API Request
def send_request(method, url, headers, data=None):
    if method == "GET":
        response = requests.get(url, headers=headers)
    elif method == "POST":
        response = requests.post(url, headers=headers, data=data)
    return response.status_code, response.json()

# defang IP address and URLs
def defang(text):
    defanged_text = text.replace(".", "[.]")
    return defanged_text

# Parse VirusTotal data
def parse_vt_data(vt_data):
    # DONE Add checks to handle missing data
    if "data" in vt_data and "attributes" in vt_data["data"]:
        parsed_data = {
        "ip_address": vt_data["data"].get("id"),
        "network": vt_data["data"]["attributes"].get("network"),
        "country": vt_data["data"]["attributes"].get("country"),
        "continent": vt_data["data"]["attributes"].get("continent"),
        "reputation": vt_data["data"]["attributes"].get("reputation"),
        "last_analysis_stats": vt_data["data"]["attributes"].get("last_analysis_stats"),
        "total_votes": vt_data["data"]["attributes"].get("total_votes"),
        "as_owner": vt_data["data"]["attributes"].get("as_owner"),
        "threat_severity_level": vt_data["data"]["attributes"].get("threat_severity", {}).get("threat_severity_level"),
        "level_description": vt_data["data"]["attributes"].get("threat_severity", {}).get("level_description"),
    }
    return parsed_data

# Build a block response
def build_block_response(ip, parsed_vt_data):
    block = {
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": f"{ip} ({parsed_vt_data['network']}) - *Owner:* {parsed_vt_data['as_owner']}\n"
                    f"*Country:* {parsed_vt_data['country']} - *Continent:* {parsed_vt_data['continent']}\n"
                    f"*Commmunity Score:* {parsed_vt_data['reputation']}\n"
                    f"*Last Analysis Stats:* {parsed_vt_data['last_analysis_stats']}\n"
                    f"*Total Votes:* {parsed_vt_data['total_votes']}\n"
                    f"*Threat Severity Level:* {parsed_vt_data['threat_severity_level']} - {parsed_vt_data['level_description']}\n"
        },
        "accessory": {
            "type": "button",
            "text": {
                "type": "plain_text",
                "text": "View in VirusTotal"
            },
            "value": "View in VirusTotal",
            "url": f"https://www.virustotal.com/gui/ip-address/{parsed_vt_data['ip_address']}/detection",
            "action_id": "button-action"
        }
    }
    return block