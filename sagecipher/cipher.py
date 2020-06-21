from hashlib import pbkdf2_hmac
from collections import namedtuple
from Crypto.Cipher import AES
from Crypto import Random
import paramiko


def to_hex(_bytes):
    """Encode `_bytes` as a colon-delemeted hexidecimal representation of each byte"""

    if type(_bytes) is str:
        _bytes = _bytes.encode()

    return ":".join("{:02x}".format(c) for c in _bytes)


def from_hex(string):
    """This function is the inverse of `to_hex`."""
    return bytes.fromhex(string.replace(":", ""))


class SshAgentKeyError(Exception):
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
        E_NO_KEYS: "SSH agent is not running or no keys are available",
        E_AGENT_VERSION: "SSH agent speaks an incompatible protocol",
        E_MISSING_KEY: "Key with fingerprint [{fingerprint}] not found via SSH agent",
    }

    def __init__(self, code, **kwargs):
        self.code = code
        self.kwargs = kwargs
        super(SshAgentKeyError, self).__init__(str(self))

    def __str__(self):
        """User-friendly description of the error"""
        return self.codes[self.code].format(**self.kwargs)


Signature = namedtuple("Signature", ["key_fingerprint", "key_type", "signature"])


def ssh_agent_sign(data, fingerprint=None):
    """Attempt to sign 'data' via ssh-agent.

    Args:
        data (str):
            The data to sign

    Kwargs:
        fingerprint (str, optional):
            The fingerprint of the key to be used for signing data.

    Returns:
        A dict containing the following keys:
            key_fingerprint:
                The fingerprint of the key used for signing data.
            key_type: The SSH key type used for signing.
            signature: The data signature returned from ssh-agent.
    Raises:
        SshAgentKeyError: An error occured while signing.
    """

    agent = paramiko.Agent()
    try:
        keys = agent.get_keys()

        if not keys:
            raise SshAgentKeyError(SshAgentKeyError.E_NO_KEYS)

        if fingerprint is not None:
            try:
                key = next(key for key in keys if key.get_fingerprint() == fingerprint)
            except StopIteration:
                raise SshAgentKeyError(
                    SshAgentKeyError.E_MISSING_KEY, fingerprint=to_hex(fingerprint)
                )
        else:
            key = keys[0]

        _result = key.sign_ssh_data(data)
        _msg = paramiko.message.Message(_result)

    finally:
        agent.close()

    return Signature(
        key_fingerprint=key.get_fingerprint(),
        key_type=_msg.get_string(),
        signature=_msg.get_string(),
    )


def prompt_for_key():
    keys = paramiko.Agent().get_keys()
    if not keys:
        raise SshAgentKeyError(SshAgentKeyError.E_NO_KEYS)

    if len(keys) == 1:
        return to_hex(keys[0].get_fingerprint())

    print("Please select from the following keys...")
    for i, k in enumerate(keys):
        print("[%s] %s %s" % (i + 1, k.get_name(), to_hex(k.get_fingerprint())))
    i = 0

    while i > len(keys) or i < 1:
        try:
            i = int(input("Selection (1..%s): " % len(keys)))
        except ValueError:
            i = 0

    key = to_hex(keys[i - 1].get_fingerprint())
    return key


class Cipher(object):
    """Use ssh-agent to generate an AES block cipher.

    A nonce is passed to ssh-agent for signing with any available
    private key, and the signed response is fed through PBKDF2 for use
    as a key to AES256 block cipher (CBC mode).

    A header string of concatenated 'nonce + salt + IV + SSH key
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
            Concatenation of the nonce string, AES salt, IV,
            and SSH key fingerprint.

        hex_fingerprint (str, optional):
            An explicit hex-encoded SSH key fingerprint to use.
    """

    SHA256_ITERATIONS = 100000
    BLOCK_SIZE = AES.block_size
    HEADER_SIZE = 64

    def __init__(self, header=None, hex_fingerprint=None):
        if header is None:
            header = Random.new().read(48)

        self.nonce = header[:16]
        self.salt = header[16:32]
        self._iv = header[32:48]

        if len(header) >= 64:
            self.fingerprint = header[48:64]
        elif hex_fingerprint is not None:
            self.fingerprint = from_hex(hex_fingerprint)
        else:
            self.fingerprint = None

        signature = ssh_agent_sign(self.nonce, self.fingerprint)

        if self.fingerprint is None:
            self.fingerprint = signature.key_fingerprint

        password = signature.signature

        self.key = pbkdf2_hmac("sha256", password, self.salt, self.SHA256_ITERATIONS)
        self.reset()

    def reset(self, _iv=None):
        """Reset the block cipher.

        This may be used to avoid re-calculating the AES key for repeat
        encrypt/decrypt operations, however it is recommended to use a new
        Cipher instance (with unique salt+IV) for each encrypted message/file.

        Args:
            _iv (str, optional):
                Change the IV value used to create a new AES cipher instance.
        """

        if _iv is None:
            _iv = self._iv

        self.cipher = AES.new(self.key, AES.MODE_CBC, _iv)

    def decrypt(self, encdata, unpad=True):
        """Decrypts the next block of data.

        Args:
            encdata (bytes): The data to decrypt (must be a multiple of *BLOCK_SIZE*)
            unpad (bool): Unpads the decrypted data
        """
        data = self.cipher.decrypt(encdata)
        return self.unpad(data) if unpad else data

    def encrypt(self, data, pad=True):
        """Encrypts the next block of data.

        Args:
            data (bytes): The data to encrypt (must be a multiple of *BLOCK_SIZE*)
            pad (bool): Pads the data to *BLOCK_SIZE* if not already
        """
        if pad:
            data = self.pad(data)

        return self.cipher.encrypt(data)

    @property
    def header(self):
        """Generate the header string needed to create this cipher."""
        return b"".join([self.nonce, self.salt, self._iv, self.fingerprint])

    @classmethod
    def decrypt_bytes(cls, ciphertext):
        """Helper function to decrypt data.

        The provided ciphertext must contain a header provided by the `header`
        function of the Cipher used to encrypt it.  This will be used to
        re-create the Cipher and decrypt the ciphertext.

        Args:
            ciphertext (bytes): The data to decrypt, including cipher header

        Returns:
            plaintext (bytes): Decrypted data
        """
        cipher = cls(ciphertext[: cls.HEADER_SIZE])
        return cipher.decrypt(ciphertext[cls.HEADER_SIZE :])

    @classmethod
    def encrypt_bytes(cls, plaintext, hex_fingerprint=None):
        """Helper function to encrypt data.

        Args:
            plaintext (bytes): The data to encrypt
            hex_fingerprint (str): If specified, use a specific key for encryption

        Returns:
            ciphertext (bytes): The encrypted ciphertext, with cipher header prepended
        """

        cipher = cls(hex_fingerprint=hex_fingerprint)
        return cipher.header + cipher.encrypt(plaintext)

    @classmethod
    def decrypt_string(cls, ciphertext, encoding="utf-8"):
        """Helper function to decrypt a string.

        The provided ciphertext must contain a header provided by the `header`
        function of the Cipher used to encrypt it.  This will be used to
        re-create the Cipher and decrypt the ciphertext.

        Args:
            ciphertext (str): The data to decrypt, including cipher header
            encoding (str): String encoding to use - defaults to 'utf-8'

        Returns:
            plaintext (str): Decrypted data
        """

        return cls.decrypt_bytes(ciphertext).decode(encoding)

    @classmethod
    def encrypt_string(cls, plaintext, hex_fingerprint=None, encoding="utf-8"):
        """Helper function to encrypt a string.

        Args:
            plaintext (bytes): The data to encrypt
            hex_fingerprint (str): If specified, use a specific key for encryption
            encoding (str): String encoding to use - defaults to 'utf-8'

        Returns:
            ciphertext (bytes): The encrypted ciphertext, with cipher header prepended
        """

        if type(plaintext) is not bytes:
            plaintext = plaintext.encode(encoding)
        return cls.encrypt_bytes(plaintext, hex_fingerprint)

    @classmethod
    def pad(cls, bytes):
        """Pads the given string to a length multiple of the cipher block size."""

        if type(bytes) is str:
            bytes = bytes.encode()

        # embed the pad_length into the padding itself for a simple un-pad operation
        pad_length = cls.BLOCK_SIZE - len(bytes) % cls.BLOCK_SIZE
        return bytes + pad_length * chr(pad_length).encode()

    @classmethod
    def unpad(cls, _bytes):
        """Un-pads `_bytes` previously padded with the `pad` function."""
        return _bytes[: -ord(_bytes[len(_bytes) - 1 :])]
