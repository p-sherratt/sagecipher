from keyrings.alt.file_base import Keyring as KeyringBase
from sagecipher.cipher import Cipher, SshAgentKeyError, prompt_for_key


class Keyring(KeyringBase):
    priority = 1
    filename = "sagecipher_pass.cfg"
    scheme = "[PBKDF2] AES256.CBC (sagecipher)"
    version = "1.0"

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
        else:
            return super().__setattr__(key, value)

    def encrypt(self, password, assoc=None):
        fingerprint = self.ssh_key_fingerprint
        return Cipher.encrypt_bytes(password, fingerprint)

    def decrypt(self, password_encrypted, assoc=None):
        return Cipher.decrypt_bytes(password_encrypted)
