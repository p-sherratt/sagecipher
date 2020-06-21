import pkg_resources

from sagecipher.cipher import Cipher, SshAgentKeyError

__version__ = pkg_resources.get_distribution("sagecipher").version

__all__ = [Cipher, SshAgentKeyError, __version__]
