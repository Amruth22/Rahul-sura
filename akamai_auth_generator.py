import requests
import base64
import hmac
import hashlib
import uuid
import time
import os
from urllib.parse import urlparse

def get_credentials_from_edrc():
    edrc_path = os.path.expanduser('~/.ederc')
    creds = {}
    with open(edrc_path, 'r') as f:
        for line in f:
            if '=' in line:
                key, value = line.strip().split('=', 1)
                creds[key.strip()] = value.strip()
    return creds

def make_auth_header(method, url, body=None):
    creds = get_credentials_from_edrc()
    
    parsed_url = urlparse(url)
    host = parsed_url.netloc
    path = parsed_url.path
    if parsed_url.query:
        path = f"{path}?{parsed_url.query}"
    
    # Generate timestamp in the correct format (UTC)
    timestamp = time.strftime('%Y%m%dT%H:%M:%S+0000', time.gmtime())
    nonce = str(uuid.uuid4())
    
    # Create the data to sign
    data_to_sign = f"{method}\thttps\t{host}\t{path}\t\t\t"
    
    # Sign the data
    signing_key = base64.b64decode(creds['client_secret'])
    signature = hmac.new(
        signing_key,
        data_to_sign.encode('utf-8'),
        hashlib.sha256
    ).digest()
    
    signature_b64 = base64.b64encode(signature).decode('utf-8')
    
    # Create the auth header
    auth_header = (
        f"EG1-HMAC-SHA256 "
        f"client_token={creds['client_token']};"
        f"access_token={creds['access_token']};"
        f"timestamp={timestamp};"
        f"nonce={nonce};"
        f"signature={signature_b64}"
    )
    
    return auth_header

def check_client_permissions():
    creds = get_credentials_from_edrc()
    host = creds['host']
    
    # Build the URL
    url = f"https://{host}/identity-management/v1/api-clients/self"
    
    # Generate authentication header
    auth_header = make_auth_header("GET", url)
    
    # Make the request
    print(f"Making request to {url}")
    print(f"Using auth header (first 30 chars): {auth_header[:30]}...")
    
    # Disable SSL verification warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    headers = {"Authorization": auth_header}
    response = requests.get(url, headers=headers, verify=False)
    
    print(f"Response status code: {response.status_code}")
    
    if response.status_code == 200:
        data = response.json()
        
        # Extract and display permissions
        print("\nAPI Client Permissions:\n")
        
        if 'authorizations' in data:
            for auth in data['authorizations']:
                print(f"API: {auth.get('resource', 'Unknown')}")
                print(f"  Actions: {', '.join(auth.get('actions', []))}")
                print(f"  Scope: {auth.get('scope', 'N/A')}")
                print()
                
                # Check specifically for PAPI
                if 'PAPI' in auth.get('resource', '') or 'property' in auth.get('resource', '').lower():
                    print(f"*** Found Property Manager API permissions: {', '.join(auth.get('actions', []))} ***")
        else:
            print("No authorizations found in the response.")
            print("\nFull response:")
            import json
            print(json.dumps(data, indent=2))
    else:
        print(f"Error: {response.text}")

if __name__ == "__main__":
    check_client_permissions()