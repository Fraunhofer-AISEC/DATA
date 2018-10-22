# PyCrypto

This directory contains the DATA framework files to test the
Python Cryptography Toolkit ([PyCrypto](https://pypi.org/project/pycrypto/)). On Debian/Ubuntu,
the following packages are required to test PyCrypto:

```
sudo apt-get install python2.7 python2.7-dev python-virtualenv
```

Running `make` sets up a Python virtual environment and installs all necessary Python packages.
The enviroment can be removed with `make clean`.

