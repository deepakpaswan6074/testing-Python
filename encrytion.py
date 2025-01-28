mport json
import requests
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

# UAT Public Key (Extracted)
UAT_PUBLIC_KEY_PEM = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu60AzxMOMrBQ4zrsyh4y
ftU82X+bUz5NqVAa7kvrHJQVawqfQJiI6T72tFDULHxyiBXu+zOmPQH9WGIk9Rri
IIAUT6iRKtmLfk7ihZkVoYSbvN3mKFAhOGghBJmlJeEL301yhU38y2Nu/nx0mm/Y
/r5DsSAzhet+U5GNBL8fYo0uOZ9Ooziuv9h+nqX0u2tcIPJmausesw42ceXXDJul
YjHOMIRg8cyidWSIYLEdebxocOzXuq9hcpoxF45F5br9+syYuQSqzSYDj02xRcee
nU/rh78Al4cRcYDTmQ6OrZL+OrAcUjiqkR+mX+QKPI5vpo4I5cQMIzkSg+SQFevW
BwIDAQAB
-----END PUBLIC KEY-----
"""

# RSA Key Loading
def load_public_key(pem_key: str):
    return serialization.load_pem_public_key(pem_key.encode())

# AES Encryption
def aes_encrypt(data: str, aes_key: bytes):
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return {
        "ciphertext": ciphertext.hex(),
        "nonce": cipher.nonce.hex(),
        "tag": tag.hex()
    }

# RSA Encryption
def rsa_encrypt(aes_key: bytes, public_key):
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key.hex()

# Prepare Encrypted Payload
def prepare_payload(json_payload: dict):
    public_key = load_public_key(UAT_PUBLIC_KEY_PEM)
    aes_key = get_random_bytes(32) # AES-256 key
    encrypted_aes_key = rsa_encrypt(aes_key, public_key)
    encrypted_data = aes_encrypt(json.dumps(json_payload), aes_key)
    
    return {
        "data": json.dumps(encrypted_data),
        "key": encrypted_aes_key,
        "bit": 0 # static value
    }

# Send API Request
def send_request(encrypted_payload):
    headers = {
        "Content-Type": "application/json",
        "IBL-Client-Id": "e866224bb5cc16f47351a8593a481061",
        "IBL-Client-Secret": "7f127b087cff15cc5d03b7ad8697f947"
    }
    url = "https://indusapiuat.indusind.com/indusapi-np/uat/finacle/v1/finacledbt"
    response = requests.post(url, headers=headers, json=encrypted_payload)
    return response.json()

# Test Payload
if __name__ == "__main__":
    json_payload = {
        "request": {
            "header": {
                "requestUUID": "Requestww4567",
                "channelId": "COR"
            },
            "body": {
                "finacledbtReq": {
                    "aadharConFlg": "N",
                    "cifId": "68046312",
                    "lastBkNameAadhar": "607189"
                }
            }
        }
    }
    encrypted_payload = prepare_payload(json_payload)
    response = send_request(encrypted_payload)
    print(json.dumps(response, indent=4))
