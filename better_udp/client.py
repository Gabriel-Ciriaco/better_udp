import asyncio
import atexit
import socket
from pyclbr import Function

from .encryption import generate_RSA_keys, generate_AES_key, encrypt, decrypt
from .utils import object_to_bytes, bytes_to_object


class Client:
	'''Instatiates an UDP client'''

	def __init__(self, SERVER_ADDRESS: tuple[str, int]) -> None:
		self.SERVER_ADDRESS = SERVER_ADDRESS
		asyncio.run(self.first_connection())

	def on(self, callback_name: str) -> None:
		'''Handle any data object received from the UDP Server'''
		def decorator(callback: Function):
			try:
				callback(getattr(self, callback_name))
			except AttributeError as error:
				print(error)
				pass

		return decorator

	def emit(self, event_name: str, data: object) -> None:
		'''Emits any data object to the UDP Server'''
		try:
			data = object_to_bytes([event_name, data])

			AES_key = generate_AES_key()
			encrypted_data = encrypt(data, self.private_key, self.server_public_key, AES_key)
			data_to_send = f'{self.session_id}'.encode('utf-8') + encrypted_data
			asyncio.run(self.event(data_to_send))
		except EOFError:
			pass

	async def event(self, data: bytes) -> None:
		'''Emits and Receives data to the UDP Server'''
		with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_socket:
			client_socket.sendto(data, self.SERVER_ADDRESS)
			try:
				try:
					data_encrypted = client_socket.recvfrom(2048)[0]
					data_decrypted = decrypt(data_encrypted, self.private_key, self.server_public_key)
					server_event_name, data_from_server = bytes_to_object(data_decrypted)
				except (AttributeError, ValueError) as e:
					if isinstance(e, AttributeError):
						# This ocurrs in connection response since
						# there is no encryption
						data_decrypted = data_encrypted
						server_event_name, data_from_server = bytes_to_object(data_decrypted)

				try:
					# Handle server response
					setattr(self, server_event_name, data_from_server)
				except (AttributeError, UnboundLocalError):
					pass

			except EOFError:
				pass

	async def first_connection(self) -> None:
		'''Handles the first connection with the server'''
		self.private_key, self.public_key = generate_RSA_keys()
		data = ['connect', self.public_key]
		await self.event(object_to_bytes(data))

		@self.on('connect_response')
		def handle_connection_response(data_from_server: object) -> None:
			session_id, public_key = data_from_server
			self.session_id = session_id
			self.server_public_key = public_key
			atexit.register(self.close_connection)

	def close_connection(self) -> None:
		'''Says to the server that client will no longer send data'''
		return self.emit('close_connection', self.session_id)
