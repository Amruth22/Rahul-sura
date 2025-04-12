import requests
import json
import os
import time
import hashlib
import hmac
import base64
import uuid
from urllib.parse import urlparse

def get_credentials_from_edrc():
    edrc_path = os.path.expanduser('~/.ederc')
    creds = {}
    try:
        with open(edrc_path, 'r') as f:
            for line in f:
                if '=' in line:
                    key, value = line.strip().split('=', 1)
                    creds[key.strip()] = value.strip()
        return creds
    except Exception as e:
        print(f"Error reading credentials file: {str(e)}")
        # Print the file content for debugging
        try:
            with open(edrc_path, 'r') as f:
                content = f.read()
            print(f"File content (without credentials):")
            for line in content.split('\n'):
                if '=' in line:
                    key, _ = line.split('=', 1)
                    print(f"{key.strip()}=<REDACTED>")
                else:
                    print(line)
        except:
            pass
        raise

def make_edge_auth_header(method, url, body=None, headers=None, max_body=2048):
    creds = get_credentials_from_edrc()
    timestamp = time.strftime('%Y%m%dT%H:%M:%S+0000', time.gmtime())
    nonce = str(uuid.uuid4())
    
    parsed_url = urlparse(url)
    request_host = parsed_url.netloc
    request_path = parsed_url.path
    if parsed_url.query:
        request_path += f"?{parsed_url.query}"
    
    # Create auth header
    auth_header = (
        f"EG1-HMAC-SHA256 "
        f"client_token={creds['client_token']};"
        f"access_token={creds['access_token']};"
        f"timestamp={timestamp};"
        f"nonce={nonce};"
    )
    
    # Create signature
    signing_key = base64.b64decode(creds['client_secret'])
    data_to_sign = f"{method}\thttps\t{request_host}\t{request_path}\t"
    
    # Add headers if any
    if headers:
        canonicalized_headers = ""
        for header_name in sorted(headers.keys()):
            canonicalized_headers += f"{header_name.lower()}:{headers[header_name]}\t"
        data_to_sign += canonicalized_headers
    
    # Add empty tab for headers if none
    if not headers:
        data_to_sign += "\t"
    
    # Add body hash if any
    if body:
        content_hash = hashlib.sha256(body.encode('utf-8')).digest()
        content_hash_base64 = base64.b64encode(content_hash).decode('utf-8')
        data_to_sign += content_hash_base64
    else:
        data_to_sign += ""
    
    # Add a final tab
    data_to_sign += "\t"
    
    print(f"Data to sign: '{data_to_sign}'")
    
    signature = hmac.new(
        signing_key,
        data_to_sign.encode('utf-8'),
        hashlib.sha256
    ).digest()
    
    signature_b64 = base64.b64encode(signature).decode('utf-8')
    auth_header += f"signature={signature_b64}"
    
    return auth_header

def get_staging_version(property_name):
    try:
        # Disable SSL warnings
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        creds = get_credentials_from_edrc()
        print(f"Credentials loaded from ~/.ederc")
        print(f"Credential keys found: {list(creds.keys())}")
        
        host = creds['host']
        base_url = f"https://{host}"
        
        # Get contracts
        endpoint = "/papi/v1/contracts"
        url = f"{base_url}{endpoint}"
        
        auth_header = make_edge_auth_header("GET", url)
        headers = {"Authorization": auth_header}
        
        print(f"Request URL: {url}")
        print(f"Authorization header: {auth_header[:30]}...{auth_header[-30:]}")
        
        response = requests.get(url, headers=headers, verify=False)
        print(f"Contracts response: {response.status_code}")
        
        if response.status_code != 200:
            return f"Error getting contracts: {response.status_code} - {response.text}"
        
        contracts = response.json().get('contracts', {}).get('items', [])
        if not contracts:
            return "No contracts found"
        
        contract_id = contracts[0]['contractId']
        
        # Get groups
        endpoint = "/papi/v1/groups"
        url = f"{base_url}{endpoint}"
        
        auth_header = make_edge_auth_header("GET", url)
        headers = {"Authorization": auth_header}
        
        response = requests.get(url, headers=headers, verify=False)
        
        if response.status_code != 200:
            return f"Error getting groups: {response.status_code} - {response.text}"
        
        groups = response.json().get('groups', {}).get('items', [])
        if not groups:
            return "No groups found"
        
        group_id = groups[0]['groupId']
        
        print(f"Using contract ID: {contract_id}")
        print(f"Using group ID: {group_id}")
        
        # Get properties
        endpoint = f"/papi/v1/properties?contractId={contract_id}&groupId={group_id}"
        url = f"{base_url}{endpoint}"
        
        auth_header = make_edge_auth_header("GET", url)
        headers = {"Authorization": auth_header}
        
        response = requests.get(url, headers=headers, verify=False)
        
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
        
        # Get activations
        endpoint = f"/papi/v1/properties/{property_id}/activations"
        url = f"{base_url}{endpoint}"
        
        auth_header = make_edge_auth_header("GET", url)
        headers = {"Authorization": auth_header}
        
        response = requests.get(url, headers=headers, verify=False)
        
        if response.status_code != 200:
            return f"Error getting activations: {response.status_code} - {response.text}"
        
        activations = response.json().get('activations', {}).get('items', [])
        
        staging_activations = [a for a in activations if a['network'] == 'STAGING']
        if not staging_activations:
            return f"No version found on staging for {property_name}"
        
        staging_activations.sort(key=lambda x: x.get('createDate', ''), reverse=True)
        latest_activation = staging_activations[0]
        
        return f"Version {latest_activation['propertyVersion']} is active on staging for {property_name}"
    except Exception as e:
        import traceback
        return f"Exception: {str(e)}\n{traceback.format_exc()}"

if __name__ == "__main__":
    # Replace with your actual domain
    property_name = "your-domain.com"
    result = get_staging_version(property_name)
    print(result)