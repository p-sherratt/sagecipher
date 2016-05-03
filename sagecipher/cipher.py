# -*- coding: utf-8 -*-
#
# Copyright 2016  Paul Sherratt <paul@paul.sh>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""Cipher library for ssh-agent.

This module provides an AES cipher using a key derived by signing
arbitrary challenge data via ssh-agent, and helper functions to
encrypt/decrypt single string values.

    >>> from sagecipher.cipher import *

    >>> # Create a new cipher using first key available from ssh-agent
    >>> c1 = Cipher()

    >>> # Use the cipher header to create a second/future instance
    >>> c2 = Cipher(c1.header())

    >>> # Display fingerprint of the SSH key used for derivation of cipher key
    >>> to_hex(c2.fingerprint)

    >>> # Encrypt with the first instance, decrypt back with the second...
    >>> unpad(c2.decrypt(c1.encrypt(pad("Hello, cryptic world!"))))

    >>> # Encrypt and decrypt using helper methods.  The cipher header is
    >>> # stored in the encrypted ciphertext.
    >>> ciphertext = encrypt_string("Alice, I think someone is listening!")
    >>> plaintext = decrypt_string(ciphertext)
"""

# is this cheating?
# pylint: disable=import-error
# fall-back to backports, then to passlib
try:
    from hashlib import pbkdf2_hmac as pbkdf2_hashlib
except ImportError:
    # codecov ignore start
    # (we trust backports...)
    try:
        from backports.pbkdf2 import pbkdf2_hmac as pbkdf2_hashlib
    # codecov ignore stop
    except ImportError:
        from passlib.utils.pbkdf2 import pbkdf2 as pbkdf2_passlib

from Crypto.Cipher import AES
from Crypto import Random
import paramiko

SHA256_ITERATIONS = 100000
PARAMIKO_VER = tuple(int(v) for v in paramiko.__version__.partition(' ')[0].split('.'))
BLOCK_SIZE = AES.block_size
HEADER_SIZE = 64

try:
    pbkdf2_hashlib
except NameError:
    def _pbkdf2_sha256(salt, password):
        return pbkdf2_passlib(password, salt, SHA256_ITERATIONS, 32, prf='hmac-sha256')
else:
    def _pbkdf2_sha256(salt, password):
        return pbkdf2_hashlib('sha256', password, salt, SHA256_ITERATIONS)


class Cipher(object):
    """Use ssh-agent to generate an AES block cipher.

    A challenge is passed to ssh-agent for signing with any available
    private key, and the signed response is fed through PBKDF2 for use
    as a key to an AES block cipher (CBC mode).

    A header string of concatenated 'challenge + salt + IV + SSH key
    fingerprint' may be provided to instantiate a cipher to decrypt data
    previously encrypted by this module.  If not supplied, these
    attributes will be randomly generated.

    If the header is not supplied, the SSH key to use for deriving the
    cipher may be specified in 'hex_fingerprint'.  If specified, an
    exception will be thrown if the key is not available to ssh-agent.

    If both the header and key fingerprint are ommitted, the first key
    available to ssh-agent will be used.

    Kwargs:
        header (str, optional):
            Concatenation of the challenge string, AES salt, IV,
            and SSH key fingerprint.

        hex_fingerprint (str, optional):
            An explicit hex-encoded SSH key fingerprint to use.
    """

    def __init__(self, header=None, hex_fingerprint=None):
        if header is None:
            header = Random.new().read(48)

        self.challenge = header[:16]
        self.salt = header[16:32]
        self._iv = header[32:48]

        if len(header) >= 64:
            self.fingerprint = header[48:64]
        elif hex_fingerprint is not None:
            self.fingerprint = from_hex(hex_fingerprint)
        else:
            self.fingerprint = None

        signature = sign_via_agent(self.challenge, self.fingerprint)
        if self.fingerprint is None:
            self.fingerprint = signature['key_fingerprint']
        elif self.fingerprint != signature['key_fingerprint']:
            raise Exception("Fingerprint mismatch! This shouldn't happen!!!")

        password = signature['signature']
        self.key = _pbkdf2_sha256(self.salt, password)
        self.reset()

    def reset(self, _iv=None):
        """Reset the block cipher.

        This may be used to avoid re-calculating the AES key for repeat
        encrypt/decrypt operations.

        Args:
            _iv (str, optional):
                Change the IV value used to create a new AES cipher instance.
        """

        if _iv is None:
            _iv = self._iv
        self.cipher = AES.new(self.key, AES.MODE_CBC, _iv)

    def decrypt(self, ciphertext):
        """Decrypt data with the cipher object.

        You cannot decrypt (or encrypt) another message with the same
        cipher object, but a new object can be created by calling `reset`.

        Args:
            ciphertext (str): The data to decrypt (must be a multiple of *block_size*)
        """
        return self.cipher.decrypt(ciphertext)

    def encrypt(self, plaintext):
        """Encrypt data with the cipher object.

        You cannot encrypt (or decrypt) another message with the same
        cipher object, but a new object can be created by calling `reset`.

        Args:
            plaintext (str): The data to encrypt (must be a multiple of *block_size*)
        """
        return self.cipher.encrypt(plaintext)

    def header(self):
        """Generate the header string needed to create this cipher."""
        return ''.join([self.challenge, self.salt, self._iv, self.fingerprint])


def decrypt_string(ciphertext):
    """Helper function to decrypt data.

    The provided ciphertext must contain a header provided by the `header`
    function of the Cipher used to encrypt it.  This will be used to
    re-create the Cipher and decrypt the ciphertext.

    Args:
        ciphertext (str): The data to decrypt, including cipher header

    Returns:
        plaintext (str): Decrypted data
    """
    cipher = Cipher(ciphertext[:HEADER_SIZE])
    padded = cipher.decrypt(ciphertext[HEADER_SIZE:])
    return unpad(padded)

def encrypt_string(plaintext):
    """Helper function to encrypt data.

    Args:
        plaintext (str): The data to encrypt

    Returns:
        ciphertext (str): The encrypted ciphertext, with cipher header prepended
    """
    cipher = Cipher()
    return cipher.header() + cipher.encrypt(pad(plaintext))

def pad(string):
    """Pads the given string to a length multiple of the cipher block size."""

    # embed the pad_length into the padding itself for a simple un-pad operation
    pad_length = BLOCK_SIZE - len(string) % BLOCK_SIZE
    return string + pad_length * chr(pad_length)

def unpad(string):
    """Un-pads a string previously padded with the `pad` function."""
    return string[:-ord(string[len(string)-1:])]

def to_hex(string):
    """Encode string as a colon-separated hexidecimal representation of each byte"""
    return ":".join("{:02x}".format(ord(c)) for c in string)

def from_hex(string):
    """This function is the inverse of `to_hex`."""
    return string.replace(':', '').decode('hex')

def sign_via_agent(data, fingerprint=None):
    """Attempt to sign 'data' via ssh-agent.

    Args:
        data (str):
            The data to sign

    Kwargs:
        fingerprint (str, optional):
            The fingerprint of an SSH public key associated with the private key
            to be used for signing data.

    Returns:
        A dict containing the following keys:
            key_fingerprint:
                The SSH public key fingerprint associated with the private key
                used for signing 'data'.
            key_type: The SSH key type used for signing.
            signature: The data signature returned from ssh-agent.
    Raises:
        SignError: An error occured while signing.
    """

    agent = paramiko.Agent()
    keys = agent.get_keys()
    sign_key = None
    key_fp = None

    if not keys:
        raise SignError(SignError.E_NO_KEYS)

    if fingerprint is not None:
        for key in keys:
            key_fp = key.get_fingerprint()
            if fingerprint == key_fp:
                sign_key = key
                break
        if sign_key is None:
            raise SignError(SignError.E_MISSING_KEY, fingerprint=to_hex(fingerprint))
    else:
        sign_key = keys[0]
        key_fp = sign_key.get_fingerprint()

    if PARAMIKO_VER >= (1, 14, 0):
        sig = sign_key.sign_ssh_data(data)
    else:
        sig = sign_key.sign_ssh_data(None, data)

    sig = paramiko.message.Message(sig)

    return {
        'key_fingerprint': key_fp,
        'key_type': sig.get_string(),
        'signature': sig.get_string()
    }

class SignError(Exception):
    """User-friendly error handling of the `sign_via_agent` function

    Args:
        code (int): Exception error code. This should be one of the following:
            E_NO_KEYS = 101
            E_AGENT_VERSION = 102
            E_MISSING_KEY = 103
    Kwargs:
        fingerprint (str, optional):
            The hex-encoded SSH key fingerprint.  This must be specified
            for exception code 103 (E_MISSING_KEY).
    """

    E_NO_KEYS = 101
    E_AGENT_VERSION = 102
    E_MISSING_KEY = 103

    codes = {
        E_NO_KEYS:         'SSH agent is not running or no keys are available',
        E_AGENT_VERSION:   'SSH agent speaks an incompatible protocol',
        E_MISSING_KEY:     'Key with fingerprint [{fingerprint}] not found via SSH agent',
    }

    def __init__(self, code, **kwargs):
        self.code = code
        self.kwargs = kwargs
        super(SignError, self).__init__(str(self))

    def __str__(self):
        """User-friendly description of the error"""
        return self.codes[self.code].format(**self.kwargs)


