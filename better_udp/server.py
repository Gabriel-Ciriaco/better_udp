from pyclbr import Function
from threading import Thread
import socketserver
import uuid

from .encryption import generate_RSA_keys, generate_AES_key, encrypt, decrypt
from .utils import bytes_to_object, object_to_bytes


class Server_Handler(socketserver.DatagramRequestHandler):
	'''
	Handles the Server requests

	It's instatiated every time a connection happens
	'''

	def handle(self):
		'''Handles the connection between client and server'''

		# self is the UDP socket connected to the client
		byte_data_received = self.rfile.getvalue()

		# Decrypt data
		try:
			client_session_id = byte_data_received[:36]
			encrypted_data = byte_data_received[36:]
			client_session_id = client_session_id.decode()

			private_key, client_public_key = self.server.clients_keys.get(client_session_id)[0::2]
			decrypted_data = decrypt(encrypted_data, private_key, client_public_key.encode())
		except TypeError:
			pass

		try:
			if 'decrypted_data' not in locals():  # Ocurrs when there is no encryption
				client_callback_name, data_from_client = bytes_to_object(byte_data_received)
			else:
				client_callback_name, data_from_client = bytes_to_object(decrypted_data)

			if client_callback_name == 'connect':
				# Handles first connection in antoher thread
				listening_thread = Thread(
					target=self.handle_first_connection(data_from_client),
					daemon=True)

				return listening_thread.start()
		except (UnicodeDecodeError, AttributeError):
			pass

		# If the server has the callback the client is asking
		if hasattr(self.server, client_callback_name):
			callback_to_run = getattr(self.server, client_callback_name)

			# Response to send to the client
			data_to_client = callback_to_run(self.client_address, data_from_client)

			if data_to_client is not None:
				data_to_send = object_to_bytes((f'{client_callback_name}_response', data_to_client))

				AES_key = generate_AES_key()
				data_encrypted = encrypt(data_to_send, private_key, client_public_key, AES_key)
				return self.wfile.write(data_encrypted)

	def handle_first_connection(self, client_public_key):
		'''Handles the first connection between the client and the UDP server'''
		client_session_id = str(uuid.uuid4())
		private_key, public_key = generate_RSA_keys()
		self.server.clients_keys[client_session_id] = (private_key, public_key, client_public_key)

		data_to_client = (client_session_id, public_key.decode())
		event_object = ('connect_response', data_to_client)
		self.wfile.write(object_to_bytes(event_object))


class Server:
	'''Instatiates a UPD socket server'''

	def __init__(self, SERVER_IP: str, SERVER_PORT: int) -> None:
		self.SERVER_IP = SERVER_IP
		self.SERVER_PORT = SERVER_PORT
		self.clients_keys = {}

	def start(self, callback: Function) -> None:
		'''
		Starts the UDP server at the chosen IP and Port.

		The callback is a function that contains the logic
		of your server
		'''

		with socketserver.UDPServer((self.SERVER_IP, self.SERVER_PORT), Server_Handler) as UDP_server:
			print('Server is running on {}:{}'.format(self.SERVER_IP, self.SERVER_PORT))
			self.server = UDP_server
			self.server.clients_keys = self.clients_keys
			self.listen_disconnection()

			# Runs the author's server logic
			callback()

			# Runs the UDP server
			self.server.serve_forever()

	def on(self, callback: Function) -> None:
		'''
		Sets an attribute at the server that handles the information
		from the client according to the passed callback.
		'''
		return setattr(self.server, callback.__name__, callback)

	def listen_disconnection(self) -> None:
		@self.on
		def close_connection(client, client_session_id):
			self.clients_keys.pop(client_session_id)
