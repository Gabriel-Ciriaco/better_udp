import json
from typing import Iterable


def object_to_bytes(obj: object) -> bytes:
	try:
		if obj is not None:
			if isinstance(obj, Iterable):
				for item in obj:
					if isinstance(item, bytes):  # Check for bytes in obj
						obj[obj.index(item)] = item.decode()
					else:  # Check for class objects in obj
						try:
							obj[obj.index(item)] = vars(item)
						except TypeError:
							pass

			return bytes(json.dumps(obj), 'utf-8')
	except TypeError:
		return bytes(json.dumps(vars(obj)), 'utf-8')


def bytes_to_object(b: bytes) -> object:
	if b is not None:
		if isinstance(b, bytes):
			return json.loads(b.decode())
		else:
			raise Exception('b is not a byte.')
