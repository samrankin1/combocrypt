from setuptools import setup
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, "README.rst"), encoding = "utf-8") as f:
	long_description = f.read()

setup(
	name = "combocrypt",
	version = "1.1.1",
	description = "Variable-length public-key encryption scheme that utilizes a combination of RSA and AES ciphers",
	long_description = long_description,
	url = "https://github.com/samrankin1/combocrypt",
	author = "Sam Rankin",
	author_email = "sam.rankin@me.com",
	license = "MIT",
	classifiers = [
		"Development Status :: 4 - Beta",
		"Intended Audience :: Developers",
		"License :: OSI Approved :: MIT License",
		"Natural Language :: English",
		"Operating System :: OS Independent",
		"Topic :: Software Development :: Libraries",
		"Topic :: Software Development :: Libraries :: Python Modules",
		"Topic :: Utilities",
		"Programming Language :: Python :: 3",
		"Programming Language :: Python :: 3.3",
		"Programming Language :: Python :: 3.4",
		"Programming Language :: Python :: 3.5",
	],
	keywords = "encryption public-key rsa aes",
	py_modules = ["combocrypt"],
	install_requires = ["pycrypto"],
)