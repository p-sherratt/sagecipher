from os import path
from codecs import open
from setuptools import setup, find_packages
import re

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

__version__ = None
with open(path.join(here, 'sagecipher/__init__.py'), encoding='utf-8') as f:
    for line in f:
        v = re.match(r'^__version__\s*=\s*["\'](.*)["\']\s*$', line)
        if v:
            __version__ = v.group(1)
            break
if __version__ is None:
    raise Exception('Could not read version from __init__.py!')


setup(
    name="sagecipher",
    version=__version__,
    packages=['sagecipher'],
    author="Paul Sherratt",
    author_email="paul@paul.sh",
    url="https://github.com/p-sherratt/sagecipher",
    keywords="ssh-agent paramiko cipher cloginrc encryption",
    description="Cipher for remote containers derived from ssh-agent signed challenge data",
    long_description=long_description,
    license="Apache",
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Telecommunications Industry',
        'Topic :: Security :: Cryptography',
        'Topic :: System :: Systems Administration',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 2 :: Only',
    ],
    install_requires=['paramiko', 'pycrypto', 'click', 'pyinotify', 'passlib'],
    setup_requires=['pytest-runner'],
    tests_require=['pytest'],
    zip_safe=True,
    entry_points={
        'console_scripts': [
            'sagecipher = sagecipher.__main__:cli'
        ]
    }
)

