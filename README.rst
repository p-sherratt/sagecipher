sagecipher
==========

| |PyPI|
| |Codecov|
| |Build Status|

**sagecipher** (**s**\ sh **age**\ nt **cipher**) provides an AES
cipher, whose key is obtained by signing nonce data via SSH agent. The
cipher is illustrated in the diagram below.

Contents
--------

-  `Installation <#installation>`__
-  `Usage <#usage>`__
-  `Using sagecipher in a Python program <#using-in-python>`__
-  `Using the cli tool to provide on-demand decryption <#cli>`__

Installation
------------

.. code:: sh

    pip install sagecipher

Usage 
------

Before using, ``ssh-agent`` must be running with at least one ssh-key
available for producing cipher key material:

.. code:: sh

    $ source <(ssh-agent)
    Agent pid 3710

    $ ssh-add
    Enter passphrase for /home/somebody/.ssh/id_rsa:
    Identity added: /home/somebody/.ssh/id_rsa (/home/somebody/.ssh/id_rsa)

| If ``ssh-agent`` is not available or does not have any keys available,
  expect to see a
| ``sagecipher.cipher.SshAgentKeyError`` Exception:

.. code:: python

    >>> from sagecipher import *
    >>> cfail = SshAgentCipher()
    Traceback (most recent call last):
      File "<stdin>", line 1, in <module>
      File "sagecipher/cipher.py", line 101, in __init__
        signature = sign_via_agent(self.challenge, self.fingerprint)
      File "sagecipher/cipher.py", line 230, in sign_via_agent
        raise SshAgentKeyError(SshAgentKeyError.E_NO_KEYS)
    sagecipher.cipher.SshAgentKeyError: SSH agent is not running or no keys are available

Using sagecipher in a Python program 
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: python

    >>> from sagecipher import Cipher
    >>>
    >>> # Encrypts using the first SSH key available from SSH agent...
    >>> enc_text = Cipher.encrypt_string("hello, world")
    >>> text = Cipher.decrypt_string(enc_text)
    >>> text
    "hello, world"

Using the cli tool to provide on-demand decryption to other tools 
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Check ``sagecipher --help`` for usage. By default, the 'decrypt'
operation will create a FIFO file, and then start a loop to decrypt out
to the FIFO whenever it is opened.

.. code:: sh

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

.. |PyPI| image:: https://img.shields.io/pypi/v/sagecipher.svg
   :target: https://pypi.python.org/pypi/sagecipher
.. |Codecov| image:: https://img.shields.io/codecov/c/github/p-sherratt/sagecipher/master.svg
   :target: https://codecov.io/gh/p-sherratt/sagecipher
.. |Build Status| image:: https://travis-ci.org/p-sherratt/sagecipher.svg?branch=master
   :target: https://travis-ci.org/p-sherratt/sagecipher
