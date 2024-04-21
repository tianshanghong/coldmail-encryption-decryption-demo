# from eth_account import Account
import base64
import ecies
from bip_utils import Bip39MnemonicGenerator, Bip39SeedGenerator, Bip39WordsNum, Bip32Secp256k1


# Create a new account
# acct = Account.create('some random string')

# Get the private key in hex format
# private_key_hex = acct.key.hex()
# print("Private key:", private_key_hex)



# public_key = acct._key_obj.public_key.to_hex() 
# print("Public key:", public_key)

# Get the uncompressed public key in hex format
public_key = "0x040580f2399f866607a082e0420d878fa05e63ddb967234f72dee6b164a3da5b1e94dd8ed170c71aa57daf3f9310f81155df91618eb58203693927ea78058f5a36"

# define the encrypt function
def encrypt_message(public_key_hex, message):
    encrypted_msg = ecies.encrypt(public_key_hex, message.encode())
    return encrypted_msg

def encrypt_message_to_base64(public_key_hex, message):
    encrypted_msg = ecies.encrypt(public_key_hex, message.encode())
    encrypted_msg_base64 = base64.b64encode(encrypted_msg).decode()
    return encrypted_msg_base64

# define the decrypt function
def decrypt_message(private_key_hex, encrypted_msg):
    decrypted_msg = ecies.decrypt(private_key_hex, encrypted_msg)
    return decrypted_msg.decode()

def decrypt_message_from_base64(private_key_hex, encrypted_msg_base64):
    encrypted_msg = base64.b64decode(encrypted_msg_base64)
    decrypted_msg = ecies.decrypt(private_key_hex, encrypted_msg)
    return decrypted_msg.decode()

# Encrypt and decrypt a message
message = "Hello, this is a test message!"
encrypted_message = encrypt_message(public_key, message)
print("Encrypted:", encrypted_message)
encrypted_message_base64 = encrypt_message_to_base64(public_key, message)
print("Encrypted (Base64):", encrypted_message_base64)


# Read private key from mnemonic phrases
mnemonic = "soap claw frown piano panel hat youth divide near camp phone size" # metamask acount I have
# Generate seed from mnemonic
seed = Bip39SeedGenerator(mnemonic).Generate()
print("Seed:", seed.hex())
# Generate BIP32 root key
bip32_root_key = Bip32Secp256k1.FromSeed(seed)
print("BIP32 Root Key:", bip32_root_key.PrivateKey().Raw().ToHex())
# Generate BIP32 child key
bip32_child_key = bip32_root_key.DerivePath("m/44'/60'/0'/0/0")
print("BIP32 Child Key:", bip32_child_key.PrivateKey().Raw().ToHex())
# Get the private key
private_key_hex = bip32_child_key.PrivateKey().Raw().ToHex()
# # Optionally, get the public key
# print("Public Key:", bip32_child_key.PublicKey().RawCompressed().ToHex())

decrypted_message = decrypt_message(private_key_hex, encrypted_message)
print("Decrypted:", decrypted_message)

decrypted_message = decrypt_message_from_base64(private_key_hex, encrypted_message_base64)
print("Decrypted:", decrypted_message)

