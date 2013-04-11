#!/usr/bin/env python

from distutils.core import setup

scripts = ['scripts/nfspysh']
try:
    import fuse
    scripts.append('scripts/nfspy')
except ImportError:
    print "python-fuse not detected, not installing nfspy."
    print "You can still use nfspysh for a ftp-like interface"
    pass

setup( name='NfSpy',
        version='1.0',
        description='ID-spoofing NFS client',
        author='Daniel Miller',
        author_email='bonsaiviking@gmail.com',
        url='https://github.com/bonsaiviking/NfSpy',
        packages=['nfspy'],
        scripts=scripts,
        )
