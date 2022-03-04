from setuptools import setup, find_packages

VERSION = '0.0.1'
DESCRIPTION = 'Easier way to develop a UDP Server in Python'
LONGER_DESCRIPTION = 'A module that allows you to start the barebones \
					of your UDP server in a easier and secure way. \
					All messages transmitted between the client and \
					the server are end-to-end encrypted to prevent Man in the Middle attacks.\
					So, you only have to worry about the logic of your server itself ;)'

# Setting up
setup(
	name='better_udp',
	version=VERSION,
	author='Gabriel Ciriaco de Carvalho',
	author_email='gabrielciricarvalho@gmail.com',
	description=DESCRIPTION,
	long_description=LONGER_DESCRIPTION,
	packages=find_packages(),
	install_requires=[],
	python_requires='>=3.8'

	keywords=['python', 'UDP', 'server'],
	classifiers=[
		"Development Status :: Alpha",
		"Intended Audience :: Developers",
		"Programming Language :: Python :: 3",
		"Operating System :: Microsoft :: Windows"
	]
)
