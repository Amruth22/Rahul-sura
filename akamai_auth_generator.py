import base64
import hmac
import hashlib
import uuid
import time
import os

def get_credentials_from_edrc():
    edrc_path = os.path.expanduser('~/.ederc')
    creds = {}
    with open(edrc_path, 'r') as f:
        for line in f:
            if '=' in line:
                key, value = line.strip().split('=', 1)
                creds[key.strip()] = value.strip()
    return creds

def generate_auth_header():
    creds = get_credentials_from_edrc()
    
    method = "GET"
    host = creds['host']
    path = "/identity-management/v1/api-clients/self"
    
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

if __name__ == "__main__":
    auth_header = generate_auth_header()
    print("Authentication Header:")
    print(auth_header)
    
    host = get_credentials_from_edrc()['host']
    print("\nFull curl command:")
    print(f"curl -H \"Authorization: {auth_header}\" https://{host}/identity-management/v1/api-clients/self")