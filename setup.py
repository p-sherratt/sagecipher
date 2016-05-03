from os import path
from codecs import open
from setuptools import setup, find_packages
from sagecipher import __version__

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

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
    install_requires=['paramiko', 'pycrypto'],
    extras_require={
        ":python_version < '2.7.8'": ['passlib']
    },
    setup_requires=['pytest-runner'],
    tests_require=['pytest'],
    zip_safe=True,

)

