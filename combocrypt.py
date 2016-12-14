import os
import base64
import json
import time
import struct

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization, ciphers, padding as symmetric_padding, hmac
from cryptography.hazmat.primitives.ciphers import algorithms, modes, Cipher
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asymmetric_padding

VERSION = 1

RSA_DEFAULT_KEYSIZE = 4096
AES_KEYSIZE = 256 // 8 # use 256-bit AES
HMAC_KEYSIZE = hashes.SHA512().digest_size # for SHA512 backend, this will be a 512-bit HMAC key

backend = default_backend()

# exception start

class IncorrectVersionException(Exception):
	pass

class InvalidFormatException(Exception):
	pass

class InvalidSignatureException(Exception):
	pass

# exception end

# RSA start

def generate_rsa_keypair(key_size = RSA_DEFAULT_KEYSIZE):
	"""Generate a random RSA keypair of the default size"""
	private_key = rsa.generate_private_key(
		public_exponent = 65537,
		key_size = key_size,
		backend = backend
	)
	public_key = private_key.public_key()
	return public_key, private_key

def save_rsa_public_key(key, file):
	"""Save a RSA public key to the given file"""
	encoded = key.public_bytes(
		encoding = serialization.Encoding.PEM,
		format = serialization.PublicFormat.SubjectPublicKeyInfo
	)
	with open(file, "wb") as writer: # open the file for writing as text
		writer.write(encoded) # write the encoded string to the given file

def save_rsa_private_key(key, file):
	"""Save a RSA private key to the given file"""
	encoded = key.private_bytes(
		encoding = serialization.Encoding.PEM,
		format = serialization.PrivateFormat.PKCS8,
		encryption_algorithm = serialization.NoEncryption()
	)
	with open(file, "wb") as writer: # open the file for writing as text
		writer.write(encoded) # write the encoded string to the given file

def load_rsa_public_key(file):
	"""Load a RSA public key from a file created by save_rsa_public_key"""
	with open(file, "rb") as reader: # open the file for reading as text
		encoded = reader.read() # read the entire PEM-encoded key string from the file
		return serialization.load_pem_public_key(data = encoded, backend = backend) # load the string as a public key

def load_rsa_private_key(file):
	"""Load a RSA private key from a file created by save_rsa_private_key"""
	with open(file, "rb") as reader: # open the file for reading as text
		encoded = reader.read() # read the entire PEM-encoded key string from the file
		return serialization.load_pem_private_key(data = encoded, password = None, backend = backend) # load the string as a public key

def _rsa_encrypt_bytes(plaintext, public_key):
	"""RSA encrypt a bytes object with the given public key"""
	return public_key.encrypt(
		plaintext = plaintext,
		padding = asymmetric_padding.OAEP(
			mgf = asymmetric_padding.MGF1(
				algorithm = hashes.SHA512()
			),
			algorithm = hashes.SHA512(),
			label = None
		)
	)

def _rsa_decrypt_bytes(ciphertext, private_key):
	"""RSA decrypt bytes encrypted by rsa_encrypt_bytes()"""
	return private_key.decrypt(
		ciphertext = ciphertext,
		padding = asymmetric_padding.OAEP(
			mgf = asymmetric_padding.MGF1(
				algorithm = hashes.SHA512()
			),
			algorithm = hashes.SHA512(),
			label = None
		)
	)

# RSA end

# AES start

def _random_bits(size):
	"""Generate a random AES key, HMAC key, or IV of the given size, in bytes"""
	return os.urandom(size) # the result consists of cryptographically secure random bytes

def _pad_bytes(data):
	"""Pad bytes of data for encryption by a CBC-mode AES cipher"""
	padder = symmetric_padding.PKCS7(algorithms.AES.block_size).padder()
	padded_data = padder.update(data)
	padded_data += padder.finalize()
	return padded_data

def _unpad_bytes(data):
	"""Unpad bytes of data that were padded by _pad_bytes"""
	unpadder = symmetric_padding.PKCS7(algorithms.AES.block_size).unpadder()
	unpadded_data = unpadder.update(data)
	unpadded_data += unpadder.finalize()
	return unpadded_data

def _aes_encrypt_bytes(data, key):
	"""Encrypt some data with the given AES key"""
	padded_data = _pad_bytes(data)
	iv = _random_bits((algorithms.AES.block_size // 8))
	encryptor = Cipher(
		algorithm = algorithms.AES(key),
		mode = modes.CBC(iv),
		backend = backend
	).encryptor()
	return iv, (encryptor.update(padded_data) + encryptor.finalize())

def _aes_decrypt_bytes(data, iv, key):
	"""Decrypt data that was encrypted by _aes_encrypt_bytes"""
	decryptor = Cipher(
		algorithm = algorithms.AES(key),
		mode = modes.CBC(iv),
		backend = backend
	).decryptor()
	decrypted_data = decryptor.update(data) + decryptor.finalize()
	return _unpad_bytes(decrypted_data)

# AES end

# HMAC start

def _do_hmac(hmac_key, aes_encrypted_data):
	signer = hmac.HMAC(
		key = hmac_key,
		algorithm = hashes.SHA512(),
		backend = backend
	)
	signer.update(aes_encrypted_data)
	return signer.finalize()

def _verify_hmac(hmac_key, aes_encrypted_data, signature):
	verifier = hmac.HMAC(
		key = hmac_key,
		algorithm = hashes.SHA512(),
		backend = backend
	)
	verifier.update(aes_encrypted_data)
	try:
		verifier.verify(signature)
		return True
	except: # if verifying the signature fails for any reason, return failure
		return False

# HMAC end

def combo_encrypt_data(data, public_key):
	"""Encrypt data using the ComboCrypt scheme, with the given public key as a recipient"""
	aes_key = _random_bits(AES_KEYSIZE) # generate a random 256-bit AES key
	hmac_key = _random_bits(HMAC_KEYSIZE) # generate a random 512-bit HMAC key
	rsa_encrypted_keys = _rsa_encrypt_bytes((aes_key + hmac_key), public_key) # encrypt the AES and HMAC keys with the public key

	packed_timestamp = struct.pack("!Q", int(time.time())) # pack as unsigned long long (uint <18,446,744,073,709,551,616) - 8 bytes
	iv, aes_encrypted_data = _aes_encrypt_bytes((packed_timestamp + data), aes_key) # encrypt the timestamp and data with the random AES key

	signature = _do_hmac(hmac_key, aes_encrypted_data) # create an authentication code for the encrypted data

	packed_version = struct.pack("!B", VERSION) # pack as unsigned char (uint <256) - 1 byte
	return packed_version, rsa_encrypted_keys, iv, aes_encrypted_data, signature # return all the ComboCrypt components

def combo_decrypt_data(packed_version, rsa_encrypted_keys, iv, aes_encrypted_data, signature, private_key):
	"""Decrypt data that was encrypted by combo_encrypt_data"""
	unpacked_version = struct.unpack("!B", packed_version)[0]
	if unpacked_version != VERSION:
		raise IncorrectVersionException("Version mismatch! Expected '" + str(VERSION) + "', got '" + str(unpacked_version) + "'")

	decrypted_keys = _rsa_decrypt_bytes(rsa_encrypted_keys, private_key)
	if len(decrypted_keys) != (32 + 64):
		raise InvalidFormatException("Decrypted keys length mismatch! Expected '" + str((32 + 64)) + "', got '" + str(len(decrypted_keys)) + "'")
	aes_key = decrypted_keys[:32] # first 32 bytes are the AES key
	hmac_key = decrypted_keys[32:] # next 64 bytes are the HMAC key

	hmac_valid = _verify_hmac(hmac_key, aes_encrypted_data, signature)
	if not hmac_valid:
		raise InvalidSignatureException("HMAC signature check failed!")

	decrypted_data = _aes_decrypt_bytes(aes_encrypted_data, iv, aes_key)
	if len(decrypted_data) < 8:
		raise InvalidFormatException("Decrypted data is too short! Excpected at least 8 bytes, got " + str(len(decrypted_data)))
	packed_timestamp = decrypted_data[:8]
	timestamp = struct.unpack("!Q", packed_timestamp)[0]
	message = decrypted_data[8:]

	return message, timestamp