import requests
import json
import os
import time
import hashlib
import hmac
import base64
import uuid
from urllib.parse import urljoin

def get_credentials_from_edrc():
    edrc_path = os.path.expanduser('~/.edrc')
    creds = {}
    with open(edrc_path, 'r') as f:
        for line in f:
            if '=' in line:
                key, value = line.strip().split('=', 1)
                creds[key] = value
    return creds

def create_auth_header(method, url, creds):
    timestamp = time.strftime('%Y%m%dT%H:%M:%S+0000', time.gmtime())
    nonce = str(uuid.uuid4())
    
    auth_header = (
        f"EG1-HMAC-SHA256 "
        f"client_token={creds['client_token']};"
        f"access_token={creds['access_token']};"
        f"timestamp={timestamp};"
        f"nonce={nonce};"
    )
    
    signing_key = base64.b64decode(creds['client_secret'])
    data_to_sign = f"{method}\t{url}\t\t"
    
    signature = hmac.new(
        signing_key,
        data_to_sign.encode('utf-8'),
        hashlib.sha256
    ).digest()
    
    signature_b64 = base64.b64encode(signature).decode('utf-8')
    auth_header += f"signature={signature_b64}"
    
    return auth_header

def get_contracts_and_groups(creds):
    host = creds['host']
    base_url = f"https://{host}"
    
    # Get contracts
    endpoint = "/papi/v1/contracts"
    url = urljoin(base_url, endpoint)
    
    auth_header = create_auth_header("GET", url, creds)
    headers = {"Authorization": auth_header}
    
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        print(f"Error getting contracts: {response.status_code}")
        print(response.text)
        return None, None
    
    contracts = response.json().get('contracts', {}).get('items', [])
    if not contracts:
        print("No contracts found")
        return None, None
    
    # Use the first contract ID
    contract_id = contracts[0]['contractId']
    
    # Get groups
    endpoint = "/papi/v1/groups"
    url = urljoin(base_url, endpoint)
    
    auth_header = create_auth_header("GET", url, creds)
    headers = {"Authorization": auth_header}
    
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        print(f"Error getting groups: {response.status_code}")
        print(response.text)
        return contract_id, None
    
    groups = response.json().get('groups', {}).get('items', [])
    if not groups:
        print("No groups found")
        return contract_id, None
    
    # Use the first group ID
    group_id = groups[0]['groupId']
    
    return contract_id, group_id

def get_staging_version(property_name):
    creds = get_credentials_from_edrc()
    host = creds['host']
    base_url = f"https://{host}"
    
    # Get contract and group IDs
    contract_id, group_id = get_contracts_and_groups(creds)
    if not contract_id or not group_id:
        return "Failed to get contract or group ID"
    
    print(f"Using contract ID: {contract_id}")
    print(f"Using group ID: {group_id}")
    
    # Step 1: Get property ID
    endpoint = f"/papi/v1/properties?contractId={contract_id}&groupId={group_id}"
    url = urljoin(base_url, endpoint)
    
    auth_header = create_auth_header("GET", url, creds)
    headers = {"Authorization": auth_header}
    
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        return f"Error getting properties: {response.status_code} - {response.text}"
    
    properties = response.json().get('properties', {}).get('items', [])
    
    property_id = None
    property_names = []
    for prop in properties:
        property_names.append(prop['propertyName'])
        if prop['propertyName'] == property_name:
            property_id = prop['propertyId']
            break
    
    if not property_id:
        return f"Property '{property_name}' not found. Available properties: {', '.join(property_names)}"
    
    # Step 2: Get activations for this property
    endpoint = f"/papi/v1/properties/{property_id}/activations"
    url = urljoin(base_url, endpoint)
    
    auth_header = create_auth_header("GET", url, creds)
    headers = {"Authorization": auth_header}
    
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        return f"Error getting activations: {response.status_code} - {response.text}"
    
    activations = response.json().get('activations', {}).get('items', [])
    
    # Find the most recent staging activation
    staging_activations = [a for a in activations if a['network'] == 'STAGING']
    if not staging_activations:
        return f"No version found on staging for {property_name}"
    
    # Sort by activation date (most recent first)
    staging_activations.sort(key=lambda x: x.get('createDate', ''), reverse=True)
    latest_activation = staging_activations[0]
    
    return f"Version {latest_activation['propertyVersion']} is active on staging for {property_name}"

if __name__ == "__main__":
    property_name = input("Enter your domain/property name: ")
    result = get_staging_version(property_name)
    print(result)