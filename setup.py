#!/usr/bin/env python

from distutils.core import setup

setup( name='NfSpy',
        version='1.0',
        description='ID-spoofing NFS client',
        author='Daniel Miller',
        author_email='bonsaiviking@gmail.com',
        url='https://github.com/bonsaiviking/nfspy',
        packages=['nfspy'],
        requires=['fuse'],
        scripts=['nfspy/nfspy.py'],
        )
