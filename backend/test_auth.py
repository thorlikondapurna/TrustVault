from backend.auth import create_access_token, decode_access_token


# Create a token for user ID 1
token = create_access_token(1)

print("Generated token:")
print(token)

# Decode the token
decoded = decode_access_token(token)

print("\nDecoded token:")
print(decoded)

print("\nUser ID:", decoded["sub"])