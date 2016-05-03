# sagecipher

[![PyPI](https://img.shields.io/pypi/v/sagecipher.svg)](https://pypi.python.org/pypi/sagecipher)
[![Codecov](https://img.shields.io/codecov/c/github/p-sherratt/sagecipher/master.svg)](https://codecov.io/gh/p-sherratt/sagecipher)
[![Build Status](https://travis-ci.org/p-sherratt/sagecipher.svg?branch=master)](https://travis-ci.org/p-sherratt/sagecipher)

**sagecipher** (**s**sh **age**nt **crypt**) is a very small module which provides a cipher keyed through `ssh-agent`.  The key is obtained by generating random challenge data, passing this to `ssh-agent` to obtain a signature via the users private ssh-key for use as key material, and finally passing this through PBKDF2.

## Installation
```
pip install sagecipher
```

## Usage
Before using, `ssh-agent` must be running with at least one ssh-key available for producing cipher key material:

```python
>>> from sagecipher import *
>>> cfail = Cipher()
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "sagecipher/cipher.py", line 101, in __init__
    signature = sign_via_agent(self.challenge, self.fingerprint)
  File "sagecipher/cipher.py", line 230, in sign_via_agent
    raise SignError(SignError.E_NO_KEYS)
sagecipher.SignError: SSH agent is not running or no keys are available
```

With the `ssh-agent` environment set up and an ssh-key available, the following usage example should work:

```sh
$ source <(ssh-agent)
Agent pid 3710

$ ssh-add
Enter passphrase for /home/psherratt/.ssh/id_rsa:
Identity added: /home/psherratt/.ssh/id_rsa (/home/psherratt/.ssh/id_rsa)
```
```python
>>> from sagecipher import *
>>>
>>> # Create a new cipher using first key available from ssh-agent
>>> c1 = Cipher()
>>> 
>>> # Use the cipher header to create a second/future instance
>>> c2 = Cipher(c1.header())
>>>    
>>> # Display fingerprint of the SSH key used for derivation of cipher key
>>> to_hex(c2.fingerprint)
'11:66:89:44:a3:ec:9b:1c:55:cd:f7:54:20:3b:09:c3'
>>>
>>> # Encrypt with the first instance, decrypt back with the second...
>>> unpad(c2.decrypt_string(c1.encrypt(pad("Hello, cryptic world!"))))
'Hello, cryptic world!'
>>>
>>> # Encrypt and decrypt using helper methods.  The cipher header is
>>> # stored in the encrypted ciphertext.
>>> ciphertext = encrypt_string("Alice, I think someone is listening!")
>>> plaintext = decrypt_string(ciphertext)
>>> plaintext
'Alice, I think someone is listening!'
```
