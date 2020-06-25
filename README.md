# sagecipher

[![PyPI](https://img.shields.io/pypi/v/sagecipher.svg)](https://pypi.python.org/pypi/sagecipher)
[![Codecov](https://img.shields.io/codecov/c/github/p-sherratt/sagecipher/master.svg)](https://codecov.io/gh/p-sherratt/sagecipher)
[![Build Status](https://travis-ci.org/p-sherratt/sagecipher.svg?branch=master)](https://travis-ci.org/p-sherratt/sagecipher)

**sagecipher** (**s**sh **age**nt **cipher**) provides an AES cipher, whose key is obtained by signing nonce data via SSH agent.  This is illustrated below.

![Cipher illustration](https://raw.githubusercontent.com/p-sherratt/sagecipher/master/docs/sagecipher.png)

This can be used in turn by the `keyring` library, and by `ansible-vault` to encrypt/decrypt files or secrets via the users' local or forwarded ssh-agent session.

## Contents

* [Installation](#installation)
* [Usage](#usage)
  * [Using the keyring backend](#keyring)
  * [Using with ansible-vault](#ansible)
  * [Using sagecipher directly in Python](#using-in-python)
  * [Using the sagecipher CLI tool](#cli)


## Installation
```sh
pip install sagecipher
```

## Usage <a name='usage'></a>

Before using, `ssh-agent` must be running with at least one ssh-key available for producing cipher key material:

```console
$ source <(ssh-agent)
Agent pid 3710

$ ssh-add
Enter passphrase for /home/somebody/.ssh/id_rsa:
Identity added: /home/somebody/.ssh/id_rsa (/home/somebody/.ssh/id_rsa)
```

### Using the keyring backend <a name='keyring'></a>

Here we will set the following environment variables:

| Environment Variable                   | Value                        | Description                                                 |
|----------------------------------------|------------------------------|-------------------------------------------------------------|
| `PYTHON_KEYRING_BACKEND`               | `sagecipher.keyring.Keyring` | Tells `keyring` explicitly to use the `sagecipher` backend |
| `KEYRING_PROPERTY_SSH_KEY_FINGERPRINT` | &lt;hex fingerprint of ssh key&gt; | Pre-selects the SSH key for the `sagecipher` backend to use |

If no other keyring backends are available, sagecipher will be selected as the default backend with a `priority` of 1.  The `PYTHON_KEYRING_BACKEND` environment variable can be set to explicitly set the backend.  See the [keyring docs](https://keyring.readthedocs.io/en/latest/) for more help using the keyring library.

```console
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

### Using with ansible-vault <a name='ansible'></a>

In this example we create a secret key in the keyring for use with `ansible-vault`.
This process will work with any keyring backend, but it's assumed we are up and
running with the `sagecipher` keyring backend per the previous section.

For more information, see: 
[https://docs.ansible.com/ansible/latest/user_guide/vault.html]()

1. Set up environment variables

   | Environment Variable                   | Value                        | Description                                                           |
   |----------------------------------------|------------------------------|-----------------------------------------------------------------------|
   | `PYTHON_KEYRING_BACKEND`               | `sagecipher.keyring.Keyring` | Tells `keyring` to use the `sagecipher` backend                       |
   | `KEYRING_PROPERTY_SSH_KEY_FINGERPRINT` | &lt;hex fingerprint of ssh key&gt; | Pre-selects the SSH key for the `sagecipher` backend to use           |
   | `ANSIBLE_VAULT_PASSWORD_FILE`          | &lt;path to password script&gt;    | `ansible-vault` will use this script to find the vault encryption key |
   |                                        |                              

   Replace the key fingerprint below with your own.
   
   ```sh
   export PYTHON_KEYRING_BACKEND=sagecipher.keyring.Keyring
   export KEYRING_PROPERTY_SSH_KEY_FINGERPRINT=e8:19:fe:c5:0a:b4:57:5d:96:27:b3:e3:ec:ba:24:3c
   export ANSIBLE_VAULT_PASSWORD_FILE=~/vault-pass.sh
   ```
   
2. Generate a random key for ansible-vault and store in the keyring

   ```sh
   keyring set ansible-vault key < <(dd if=/dev/urandom bs=32 count=1 | base64)
   ```

3. Create the vault password script to retrieve the vault key

   ```console
   $ cat <<EOF > ~/vault-pass.sh
   #!/bin/sh
   keyring get ansible-vault key
   EOF
   
   $ chmod +x vault-pass.sh
   ```

4. Test it out with `ansible-vault`

   ```console
   $ ansible-vault encrypt_string "secret_password" --name "secret_attribute" > secrets.yml
   $ ansible localhost -m debug -a var="secret_attribute" -e "@secrets.yml"
   
   [WARNING]: No inventory was parsed, only implicit localhost is available
   localhost | SUCCESS => {
       "secret_attribute": "secret_password"
   }
   ```

### Using sagecipher directly in Python <a name='using-in-python'></a>

```python
>>> from sagecipher import Cipher
>>>
>>> # Encrypts using the first SSH key available from SSH agent...
>>> enc_text = Cipher.encrypt_string("hello, world")
>>> text = Cipher.decrypt_string(enc_text)
>>> text
"hello, world"
```

### Using the sagecipher CLI tool <a name='cli'></a>

Check `sagecipher --help` for usage. By default, the 'decrypt' operation will create a FIFO file, and then start a loop to decrypt out to the FIFO whenever it is opened.

The FIFO is created with mode 600 by default, and if the permissions are altered or the parent shell is terminated then the sagecipher background session will end.

```console
$ sagecipher encrypt - encfile
Please select from the following keys...
[1] ssh-rsa e8:19:fe:c5:0a:b4:57:5d:96:27:b3:e3:ec:ba:24:3c
[2] ssh-rsa 38:c5:94:45:ca:01:65:d1:d0:c5:ee:5e:cd:b3:94:39
Selection (1..2): 1
Reading from STDIN...

secret sauce
(CTRL-D)

$ sagecipher decrypt encfile
secret sauce
$ mkfifo decfile
$ sagecipher decrypt encfile decfile &
[1] 16753
$ cat decfile  # decfile is just a FIFO
secret sauce
$
```

