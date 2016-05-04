#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import re
import unittest
import mock
import sagecipher

class TestCipher(unittest.TestCase):
    def _loadCiphers(self):
        self.cipher1 = sagecipher.Cipher()
        self.cipher2 = sagecipher.Cipher(self.cipher1.header())

    @classmethod
    def setUpClass(cls):
        super(TestCipher, cls).setUpClass()
        cls.ssh_key_path = '/tmp/ssh-testkey.{}'.format(os.getpid())
        if 'SSL_AUTH_SOCK' not in os.environ:
            env_sh = os.popen('ssh-agent').readlines()
            for cmd in env_sh:
                env_cmd = re.search("(\S+)=(\S+);", cmd)
                if env_cmd:
                    os.environ[env_cmd.group(1)]=env_cmd.group(2)
        os.popen('ssh-keygen -b 2048 -t rsa -f {} -q -N ""'.format(cls.ssh_key_path))
        os.popen('ssh-add {}'.format(cls.ssh_key_path))

    def test_fingerprint_mismatch(self):
        self.cipher1 = sagecipher.Cipher()
        p = mock.patch('sagecipher.cipher.sign_via_agent')
        p.return_value = {
                'signature': '',
                'key_type': '',
                'key_fingerprint': sagecipher.to_hex(str('#' * 16))
        }
        p.start()
        self.assertRaises(Exception, lambda: sagecipher.Cipher(self.cipher1.header()))
        p.stop()
   
    def test_passlib(self):
        # force import of passlib pbkdf2 function, and compare headers/keys
        # generated from both hashlib and passlib
        self.cipher1 = sagecipher.Cipher()
        try:
            import builtins
        except ImportError:
            import __builtin__ as builtins
        realimport = builtins.__import__
        def myimport(*args, **kwargs):
            if args[0] == 'hashlib' and args[3] is not None and 'pbkdf2_hmac' in args[3]: 
                raise ImportError
            return realimport(*args, **kwargs)
        builtins.__import__ = myimport
        del(sagecipher.cipher.pbkdf2_hashlib)
        reload(sagecipher.cipher)
        reload(sagecipher)
        self.assertIn('pbkdf2_passlib', dir(sagecipher.cipher))
        self.assertNotIn('pbkdf2_hashlib', dir(sagecipher.cipher))
        self.cipher2 = sagecipher.Cipher(self.cipher1.header())
        self.assertEqual(self.cipher1.header(), self.cipher2.header())

    def test_header(self):
        self._loadCiphers()
        self.assertEqual(self.cipher1.header(), self.cipher2.header())

    def test_no_keys(self):
        auth_sock = os.environ['SSH_AUTH_SOCK']
        os.environ['SSH_AUTH_SOCK'] = ''
        self.assertRaises(sagecipher.AgentKeyError, lambda: sagecipher.Cipher())
        os.environ['SSH_AUTH_SOCK'] = auth_sock

    def test_key_not_found(self):
        mock_header = '-' * sagecipher.HEADER_SIZE
        mock_fingerprint = 'AA:' * 15 + 'AA'
        self.assertRaises(sagecipher.AgentKeyError, lambda: sagecipher.Cipher(mock_header))
        self.assertRaises(sagecipher.AgentKeyError, lambda: sagecipher.Cipher(hex_fingerprint=mock_fingerprint))

    def test_inverse(self):
        self._loadCiphers()
        ciphertext = self.cipher1.encrypt(sagecipher.pad('test'))
        plaintext = sagecipher.unpad(self.cipher2.decrypt(ciphertext))
        self.assertEqual(plaintext, 'test')

    def test_helper_inverse(self):
        self.assertEqual('test', sagecipher.decrypt_string(sagecipher.encrypt_string('test')))

if __name__ == "__main__":
    sys.path[0:0] = [os.path.join(os.path.dirname(__file__), '..'),]
    unittest.main()
