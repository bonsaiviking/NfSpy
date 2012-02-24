Installing NfSpy
================

NfSpy uses Python's distutils package, so installation is as simple as
    # setup.py install

Dependencies
------------

NfSpy uses the Python bindings for the
[FUSE library](http://fuse.sourceforge.net/). This is available in Ubuntu and
Debian as the _python-fuse_ package, on Fedora as _fuse-python_, or from the
[project homepage](http://sourceforge.net/apps/mediawiki/fuse/index.php?title=FusePython)

Other Versions
--------------

NfSpy uses some syntax that is not backwards compatible with versions of
Python before 2.6. For Python 2.4 compatibility, check out the [twofour
branch](https://github.com/bonsaiviking/NfSpy/tree/twofour), which should
work, but will not receive future updates

NfSpy was updated to NFSv3 on Fri Feb 24 2012. The [nfsv2
branch](https://github.com/bonsaiviking/NfSpy/tree/nfsv2) contains the
previous version, which supports NFSv2.
