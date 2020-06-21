# sagecipher

[![PyPI](https://img.shields.io/pypi/v/sagecipher.svg)](https://pypi.python.org/pypi/sagecipher)
[![Codecov](https://img.shields.io/codecov/c/github/p-sherratt/sagecipher/master.svg)](https://codecov.io/gh/p-sherratt/sagecipher)
[![Build Status](https://travis-ci.org/p-sherratt/sagecipher.svg?branch=master)](https://travis-ci.org/p-sherratt/sagecipher)

**sagecipher** (**s**sh **age**nt **cipher**) provides an AES cipher, whose key is obtained by signing nonce data via SSH agent.  The cipher is illustrated in the diagram below.


## Contents

* [Installation](#installation)
* [Usage](#usage)
  * [Using the keyring backend](#keyring)
  * [Using sagecipher in a Python program](#using-in-python)
  * [Using the cli tool to provide on-demand decryption](#cli)


## Installation
```sh
pip install sagecipher
```

## Usage <a name='usage'></a>

Before using, `ssh-agent` must be running with at least one ssh-key available for producing cipher key material:

```sh
$ source <(ssh-agent)
Agent pid 3710

$ ssh-add
Enter passphrase for /home/somebody/.ssh/id_rsa:
Identity added: /home/somebody/.ssh/id_rsa (/home/somebody/.ssh/id_rsa)
```

### Using the keyring backend <a name='keyring'></a>
```sh
$ sagecipher list-keys  # paramiko does not yet expose key comments, unfortunately..
[ssh-rsa] e8:19:fe:c5:0a:b4:57:5d:96:27:b3:e3:ec:ba:24:3c
[ssh-rsa] 38:c5:94:45:ca:01:65:d1:d0:c5:ee:5e:cd:b3:94:39

$ export PYTHON_KEYRING_BACKEND=sagecipher.keyring.Keyring

$ keyring set svc user1
Password for 'user' in 'svc': 
Please select from the following keys...
[1] ssh-rsa e8:19:fe:c5:0a:b4:57:5d:96:27:b3:e3:ec:ba:24:3c
[2] ssh-rsa 38:c5:94:45:ca:01:65:d1:d0:c5:ee:5e:cd:b3:94:39
Selection (1..2): 1

$ keyring get svc user1
password1

$ # the ssh key can be pre-selected in the `KEYRING_PROPERTY_SSH_KEY_FINGERPRINT` env var
$ export KEYRING_PROPERTY_SSH_KEY_FINGERPRINT=e8:19:fe:c5:0a:b4:57:5d:96:27:b3:e3:ec:ba:24:3c

$ keyring get svc user2
password2

$ python
Python 3.6.8 (default, Jan 14 2019, 11:02:34) 
[GCC 8.0.1 20180414 (experimental) [trunk revision 259383]] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import keyring
>>> keyring.get_password('svc', 'user1')
'password1'
>>> keyring.get_password('svc', 'user2')
'password2'

```

### Using sagecipher in a Python program <a name='using-in-python'></a>

```python
>>> from sagecipher import Cipher
>>>
>>> # Encrypts using the first SSH key available from SSH agent...
>>> enc_text = Cipher.encrypt_string("hello, world")
>>> text = Cipher.decrypt_string(enc_text)
>>> text
"hello, world"
```

### Using the cli tool to provide on-demand decryption to other tools <a name='cli'></a>

Check `sagecipher --help` for usage. By default, the 'decrypt' operation will create a FIFO file, and then start a loop to decrypt out to the FIFO whenever it is opened.

```sh
$ sagecipher encrypt - encfile
Key not specified.  Please select from the following...
[1] ssh-rsa AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA
Selection (1..2): [1]: 
Reading from STDIN...

secret sauce
(CTRL-D)
$ sagecipher decrypt encfile
secret sauce
$ mkfifo decfile
$ sagecipher decrypt encfile decfile &
[1] 16753
$ cat decfile # decfile is just a FIFO
secret sauce
$
```

