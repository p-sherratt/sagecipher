#!/usr/bin/env python

import os
import re
import sys
import subprocess
import pytest

from sagecipher import Cipher, SshAgentKeyError


def test_header():
    cipher1 = Cipher()
    cipher2 = Cipher(cipher1.header)
    assert cipher1.header == cipher2.header


def test_no_keys():
    auth_sock = os.environ["SSH_AUTH_SOCK"]
    del os.environ["SSH_AUTH_SOCK"]
    with pytest.raises(SshAgentKeyError):
        Cipher()
    os.environ["SSH_AUTH_SOCK"] = auth_sock


def test_key_not_found():
    header = "-" * Cipher.HEADER_SIZE
    fingerprint = "AA:" * 15 + "AA"
    with pytest.raises(SshAgentKeyError):
        Cipher(header)
    with pytest.raises(SshAgentKeyError):
        Cipher(hex_fingerprint=fingerprint)


def test_inverse():
    cipher1 = Cipher()
    cipher2 = Cipher(cipher1.header)
    ciphertext = cipher1.encrypt(Cipher.pad(b"test"))
    plaintext = Cipher.unpad(cipher2.decrypt(ciphertext))
    assert plaintext == b"test"


def test_helper_inverse():
    assert "test" == Cipher.decrypt_string(Cipher.encrypt_string("test"))
