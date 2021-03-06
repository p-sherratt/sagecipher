from keyrings.alt.file_base import Keyring as KeyringBase
from sagecipher.cipher import Cipher, SshAgentKeyError, prompt_for_key
from keyring.util import properties


class Keyring(KeyringBase):
    priority = 1
    filename = "sagecipher_pass.cfg"
    scheme = "[PBKDF2] AES256.CBC (sagecipher)"
    version = "1.0"

    @property
    def sagecipher_data(self):
        """
        The environment variable `KEYRING_PROPERTY_SAGECIPHER_DATA` can
        be used to specify the data file path.  If this is not defined,
        use the default path.
        """
        if hasattr(self, "_sagecipher_data"):
            return getattr(self, "_sagecipher_data")

    @properties.NonDataProperty
    def file_path(self):
        """
        The path to the file where passwords are stored. This property
        may be overridden by the subclass or at the instance level.
        """
        return self.sagecipher_data or super().file_path

    @property
    def ssh_key_fingerprint(self):
        """
        The environment variable `KEYRING_PROPERTY_SSH_KEY_FINGERPRINT` can
        be used to specify the SSH key to use for encryption.  If this is
        not defined, the user will be prompted interactively for the key
        to use.

        This is not used for decryption, as the key fingerprint is embedded
        into the ciphertext header.
        """
        if hasattr(self, "_ssh_key_fingerprint"):
            return getattr(self, "_ssh_key_fingerprint")
        return prompt_for_key()

    def __setattr__(self, key, value):
        if key == "ssh_key_fingerprint":
            self._ssh_key_fingerprint = value
        elif key == "sagecipher_data":
            self._sagecipher_data = value
        else:
            return super().__setattr__(key, value)

    def encrypt(self, password, assoc=None):
        fingerprint = self.ssh_key_fingerprint
        return Cipher.encrypt_bytes(password, fingerprint)

    def decrypt(self, password_encrypted, assoc=None):
        return Cipher.decrypt_bytes(password_encrypted)
