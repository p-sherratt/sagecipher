from os import path
from setuptools import setup, find_packages
import re

here = path.abspath(path.dirname(__file__))

with open(path.join(here, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="sagecipher",
    version="0.7.5",
    packages=["sagecipher"],
    author="Paul Sherratt",
    author_email="paul@paul.sh",
    url="https://github.com/p-sherratt/sagecipher",
    keywords="ssh-agent paramiko cipher cloginrc encryption keyring ansible vault",
    description="Uses SSH agent to encrypt/decrypt arbitrary data",
    long_description=long_description,
    long_description_content_type="text/markdown",
    license="Apache",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Telecommunications Industry",
        "Topic :: Security :: Cryptography",
        "Topic :: System :: Systems Administration",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3 :: Only",
    ],
    install_requires=[
        "paramiko",
        "pycryptodome",
        "click",
        "pyinotify",
        "keyring",
        "keyrings.alt",
    ],
    setup_requires=["pytest-runner"],
    tests_require=["pytest"],
    zip_safe=True,
    entry_points={
        "console_scripts": ["sagecipher = sagecipher.__main__:cli"],
        "keyring.backends": ["sagecipher = sagecipher.keyring"]
    },
)
