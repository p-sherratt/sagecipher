from keyring.testing.backend import BackendBasicTests
from sagecipher.keyring import Keyring


class TestKeyring(BackendBasicTests):
    def init_keyring(self):
        return Keyring()
