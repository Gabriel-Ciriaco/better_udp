import hashlib

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP, _mode_eax
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA384


def generate_AES_key() -> bytes:
	'''Generates an AES key'''
	random_bytes = get_random_bytes(32)  # 32 bytes * 8 = 256 bits
	key = hashlib.md5(random_bytes).digest()
	return key


def generate_RSA_keys() -> tuple:
	'''Generates a public and a private RSA key'''
	RSA_key = RSA.generate(bits=2048)
	public_key = RSA_key.public_key().export_key()
	private_key = RSA_key.export_key()
	return (private_key, public_key)


def generate_RSA_cipher(private_key: str) -> PKCS1_OAEP.PKCS1OAEP_Cipher:
	key_object = RSA.import_key(private_key)
	return PKCS1_OAEP.new(key_object)


def generate_AES_cipher(key: bytes, nonce: bytes = None) -> _mode_eax.EaxMode:
	if nonce is not None:
		return AES.new(key, AES.MODE_EAX, nonce=nonce)
	else:
		return AES.new(key, AES.MODE_EAX)


def sign_message(private_key: bytes, message: bytes) -> bytes:
	private_key = RSA.import_key(private_key)
	signer = pkcs1_15.new(private_key)
	hashed_message = SHA384.new(message)
	return signer.sign(hashed_message)


def verify_signature(public_key: bytes, encrypted_message: bytes, signature: bytes) -> bool:
	public_key = RSA.import_key(public_key)
	signer = pkcs1_15.new(public_key)
	hashed_message = SHA384.new(encrypted_message)
	try:
		signer.verify(hashed_message, signature)
		return True
	except ValueError:
		return False


def encrypt(
	plaintext: bytes,
	private_RSA_key: str,
	public_RSA_key: str,
	public_AES_key: bytes) -> bytes:
	'''Encrypts a plaintext with
	a given public RSA key and an AES key'''
	RSA_cipher = generate_RSA_cipher(public_RSA_key)
	AES_cipher = generate_AES_cipher(public_AES_key)

	signature = sign_message(private_RSA_key, public_AES_key)
	ciphertext, MAC_tag = AES_cipher.encrypt_and_digest(plaintext)

	data_symetric_encrypted = MAC_tag + AES_cipher.nonce + ciphertext

	return RSA_cipher.encrypt(public_AES_key) + signature + data_symetric_encrypted


def decrypt(ciphertext: bytes, private_key: bytes, sender_public_key: bytes) -> object:
	'''Decrypts a plain text'''
	encrypted_symetric_key = ciphertext[:256]
	signature = ciphertext[256:512]
	encrypted_data = ciphertext[512:]

	RSA_cipher = generate_RSA_cipher(private_key)
	symetric_key = RSA_cipher.decrypt(encrypted_symetric_key)

	is_data_reliable = verify_signature(sender_public_key, symetric_key, signature)

	if is_data_reliable:
		MAC_tag = encrypted_data[:AES.block_size]
		nonce = encrypted_data[AES.block_size:32]
		data = encrypted_data[32:]
		AES_cipher = generate_AES_cipher(symetric_key, nonce)
		return AES_cipher.decrypt_and_verify(data, MAC_tag)
	else:
		return 'Data is not reliable'
