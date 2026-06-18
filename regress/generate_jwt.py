#!/usr/bin/env python3
import argparse
import base64
import json
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

def generate_jwt(subject, jti, not_before=None, expires=None):
    header = {
        "alg": "EdDSA",
        "kid": 1
    }
    
    payload = {
        "sub": subject,
        "jti": jti
    }
    
    if not_before is not None:
        payload["nbf"] = not_before
    
    if expires is not None:
        payload["exp"] = expires
    
    # Encode header and payload
    header_encoded = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=').decode()
    payload_encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode()
    
    message = f"{header_encoded}.{payload_encoded}"
    
    # Generate private key and sign
    private_key = Ed25519PrivateKey.generate()
    signature = private_key.sign(message.encode())
    signature_encoded = base64.urlsafe_b64encode(signature).rstrip(b'=').decode()
    
    # Get public key for JWK
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes_raw()
    public_key_b64 = base64.urlsafe_b64encode(public_bytes).rstrip(b'=').decode()
    
    # Create JWK
    jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": public_key_b64
    }
    
    return {
        "jwt": f"{message}.{signature_encoded}",
        "jwk": json.dumps(jwk)
    }
    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generate JWT and JWK for testing')
    parser.add_argument('--subject', default='test_user', help='Subject (sub) claim')
    parser.add_argument('--jti', type=int, default=1, help='JWT ID (jti) claim')
    parser.add_argument('--nbf', type=int, help='Not Before (nbf) claim in Unix time')
    parser.add_argument('--exp', type=int, help='Expiration (exp) claim in Unix time')
    
    args = parser.parse_args()
    
    result = generate_jwt(args.subject, args.jti, args.nbf, args.exp)
    print(f"JWT: {result['jwt']}")
    print(f"JWK: {result['jwk']}")
