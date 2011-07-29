#!/usr/bin/env python

# NFS-Fuse implementation with auth-spoofing
# by Daniel Miller

import sys
import rpc
import fuse
from errno import *
import socket
from time import time
from nfsclient import *
from mountclient import PartialMountClient, MOUNTPROG, MOUNTVERS
import os
from threading import Lock
from lrucache import LRU

fuse.fuse_python_api = (0, 2)

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
        FallbackTCPClient.__init__(self, host, MOUNTPROG, MOUNTVERS, port)


class FallbackUDPMountClient(PartialMountClient, FallbackUDPClient):
    def __init__(self, host, port=None):
        FallbackUDPClient.__init__(self, host, MOUNTPROG, MOUNTVERS, port)

class NFSStat(fuse.Stat):
    def __init__(self):
        self.st_mode = 0
        self.st_ino = 0
        self.st_dev = 0
        self.st_nlink = 0
        self.st_uid = 0
        self.st_gid = 0
        self.st_size = 0
        self.st_atime = 0
        self.st_mtime = 0
        self.st_ctime = 0

class EvilNFSClient(PartialNFSClient):
    def mkcred(self):
        self.cred = rpc.AUTH_UNIX, rpc.make_auth_unix(int(time()),
            socket.gethostname(), self.fuid, self.fgid, [])
        return self.cred

class EvilFallbackTCPNFSClient(EvilNFSClient, FallbackTCPClient):
    def __init__(self, host, port=None):
        FallbackTCPClient.__init__(self, host, NFS_PROGRAM, NFS_VERSION, port)

class EvilFallbackUDPNFSClient(EvilNFSClient, FallbackUDPClient):
    def __init__(self, host, port=None):
        FallbackUDPClient.__init__(self, host, NFS_PROGRAM, NFS_VERSION, port)

class NFSNode(object):
    def __init__(self):
        pass

class NFSFuse(fuse.Fuse):
    def __init__(self, *args, **kw):
        fuse.Fuse.__init__(self, *args, **kw)
        self.fuse_args.add("ro", True)
        self.authlock = Lock()
        self.cachetimeout = 120 # seconds
        self.cache = 1024
        self.mountport = "udp"
        self.nfsport = "udp"
        self.mcl = None
        self.handles = None

    def main(self):
        class FakeUmnt:
            """
            To avoid multiple calls to mountclient.Umnt, set self.mcl = FakeUmnt()
            """
            def Umnt(path):
                pass

        if hasattr(self,"server"):
            self.host, self.path = self.server.split(':',1);
        else:
            raise fuse.FuseError, "No server specified"

        if hasattr(self,"dirhandle"):
            self.mcl = FakeUmnt()
            self.rootdh = ''.join( map( lambda x: chr(int(x,16)),
                    self.dirhandle.split(':')))
        else:
            port = self.mountport.split('/',1)
            proto = "udp"
            if len(port) == 2:
                port, proto = port
            else:
                port = port[0]
            try:
                port = int(port)
            except ValueError:
                port = None
            try:
                if proto == "udp":
                    self.mcl = FallbackUDPMountClient(self.host, port)
                elif proto == "tcp":
                    self.mcl = FallbackTCPMountClient(self.host, port)
                else:
                    raise fuse.FuseError, "Invalid mount transport: %s" % proto
            except socket.error as e:
                sys.stderr.write("Problem mounting to %s:%s/%s: %s\n"
                        % (self.host, repr(port), proto, os.strerror(e.errno)))
                exit(1)

            status, dirhandle = self.mcl.Mnt(self.path)
            if status <> 0:
                raise IOError(status, os.strerror(status), self.path)
            if hasattr(self,"hide"):
                self.mcl.Umnt(self.path)
                self.mcl = FakeUmnt()
            self.rootdh = dirhandle

        port = self.nfsport.split('/',1)
        proto = "udp"
        if len(port) == 2:
            port, proto = port
        else:
            port = port[0]
        try:
            port = int(port)
        except ValueError:
            port = None
        try:
            if proto == "udp":
                self.ncl = EvilFallbackUDPNFSClient(self.host, port)
            elif proto == "tcp":
                self.ncl = EvilFallbackTCPNFSClient(self.host, port)
            else:
                raise fuse.FuseError, "Invalid NFS transport: %s" % proto
        except socket.error as e:
            sys.stderr.write("Problem establishing NFS to %s:%s/%s: %s\n"
                    % (self.host, repr(port), proto, os.strerror(e.errno)))
            exit(1)

        self.ncl.fuid = self.ncl.fgid = 0
        fattr = self.ncl.Getattr(self.rootdh)
        self.rootattr = fattr
        self.ncl.fuid = self.rootattr[3]
        self.ncl.fgid = self.rootattr[4]

        rest = self.ncl.Statfs(self.rootdh)
        self.tsize = rest[0]
        if not self.tsize:
            self.tsize = 4096
        self.handles = LRU(self.cache)

        if hasattr(self,"getroot"):
            handle, attr = self.gethandle("/..")
            while handle != self.rootdh:
                self.rootdh = handle
                self.rootattr = attr
                handle, attr = self.gethandle("/..")

        return fuse.Fuse.main(self)

    def fsinit(self):
        pass

    def _gethandle(self, path):
        dh = None
        fattr = None
        try:
            if path == "" or path == "/":
                dh = self.rootdh
                fattr = self.rootattr
            else:
                dh, fattr, cachetime = self.handles[path]
            # check that it isn't stale
            self.ncl.fuid = fattr[3]
            self.ncl.fgid = fattr[4]
            fattr = self.ncl.Getattr(dh)
        except (KeyError,NFSError) as e:
            if isinstance(e, KeyError) or e.errno() == NFSERR_STALE:
                if isinstance(e, NFSError):
                    del self.handles[path]
                tmppath, elem = path.rsplit("/",1)
                dh, fattr = self.gethandle(tmppath)
                self.ncl.fuid = fattr[3]
                self.ncl.fgid = fattr[4]
                dh, fattr = self.ncl.Lookup((dh, elem))
                self.ncl.fuid = fattr[3]
                self.ncl.fgid = fattr[4]
                self.handles[path] = (dh, fattr, time())
            else:
                raise
        return (dh, fattr)

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
            rest = self.ncl.Getattr(handle)
            fattr = rest
            self.handles[path] = (handle, fattr, time())
        except NFSError as e:
            no = e.errno()
            raise IOError(no, os.strerror(no), path)
        finally:
            self.authlock.release()
        st = NFSStat()
        st.st_mode, st.st_nlink, st.st_uid, st.st_gid, st.st_size \
            = fattr[1:6]
        st.st_atime = fattr[11][0]
        st.st_mtime = fattr[12][0]
        st.st_ctime = fattr[13][0]
        return st

    #'readlink'
    def readlink(self, path):
        if path == "/":
            return ''
        self.authlock.acquire()
        try:
            handle, fattr = self.gethandle(path)
            if fattr[0] != NFLNK:
                raise IOError(EINVAL, os.strerror(EINVAL), path)
            rest = self.ncl.Readlink(handle)
        except NFSError as e:
            no = e.errno()
            raise IOError(no, os.strerror(no), path)
        finally:
            self.authlock.release()
        return rest

    #'readdir'
    def readdir(self, path, offset):
        self.authlock.acquire()
        try:
            handle, fattr = self.gethandle(path)
            entries = (fuse.Direntry(dir[1]) for dir in self.ncl.Listdir(handle, self.tsize))
        except NFSError as e:
            no = e.errno()
            raise IOError(no, os.strerror(no), path)
        finally:
            self.authlock.release()
        return entries

    #'mknod'
    def mknod(self, path, mode, rdev):
        if rdev:
            raise IOError(ENOSYS, os.strerror(ENOSYS))
        dirpath, name = path.rsplit('/',1)
        handle = None
        fattr = None
        now = time()
        t = (int(now), 0)
        self.authlock.acquire()
        try:
            handle, fattr = self.gethandle(dirpath)
            handle, fattr = self.ncl.Create(
                    (handle, name, mode, fattr[3], fattr[4], 0, t, t))
        except NFSError as e:
            no = e.errno()
            raise IOError(no, os.strerror(no), path)
        finally:
            self.authlock.release()
        self.handles[path] = (handle, fattr, now)

    #'mkdir'
    def mkdir(self, path, mode):
        dirpath, name = path.rsplit('/',1)
        handle = None
        fattr = None
        self.authlock.acquire()
        now = time()
        t = (int(now), 0)
        try:
            handle, fattr = self.gethandle(dirpath)
            handle, fattr = self.ncl.Mkdir(
                    (handle, name, mode, fattr[3], fattr[4], 0, t, t))
        except NFSError as e:
            no = e.errno()
            raise IOError(no, os.strerror(no), path)
        finally:
            self.authlock.release()
        self.handles[path] = (handle, fattr, now)

    #'unlink'
    def unlink(self, path):
        dirpath, name = path.rsplit('/',1)
        handle = None
        fattr = None
        self.authlock.acquire()
        try:
            handle, _ = self.gethandle(dirpath)
            _, fattr = self.gethandle(path)
            if fattr[0] == NFDIR:
                raise IOError(EISDIR, os.strerror(EISDIR), path)
            self.ncl.Remove((handle, name))
        except NFSError as e:
            no = e.errno()
            raise IOError(no, os.strerror(no), path)
        finally:
            self.authlock.release()

    #'rmdir'
    def rmdir(self, path):
        dirpath, name = path.rsplit('/',1)
        handle = None
        fattr = None
        self.authlock.acquire()
        try:
            handle, _ = self.gethandle(dirpath)
            _, fattr = self.gethandle(path)
            if fattr[0] != NFDIR:
                raise IOError(ENOTDIR, os.strerror(ENOTDIR), path)
            self.ncl.Rmdir((handle, name))
        except NFSError as e:
            no = e.errno()
            raise IOError(no, os.strerror(no), path)
        finally:
            self.authlock.release()

    #'symlink'
    def symlink(self, target, name):
        dirpath, name = name.rsplit('/',1)
        handle = None
        fattr = None
        t = (int(time()), 0)
        self.authlock.acquire()
        try:
            handle, _ = self.gethandle(dirpath)
            self.ncl.Symlink((handle, name, target, 0777,
                self.ncl.fuid, self.ncl.fgid, 0, t, t))
        except NFSError as e:
            no = e.errno()
            raise IOError(no, os.strerror(no))
        finally:
            self.authlock.release()

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
                self.ncl.Rename((fromhandle, fromname, tohandle, toname))
            except NFSError as e:
                if e.value == NFSERR_ACCES:
                    self.gethandle(topath) #try different permissions
                    self.ncl.Rename((fromhandle, fromname, tohandle, toname))
                else:
                    raise e
        except NFSError as e:
            no = e.errno()
            raise IOError(no, os.strerror(no))
        finally:
            self.authlock.release()

    #'link'
    def link(self, target, name):
        dirpath, name = name.rsplit('/',1)
        fromhandle = None
        todir = None
        self.authlock.acquire()
        try:
            fromhandle, _ = self.gethandle(target)
            todir, _ = self.gethandle(dirpath)
            self.ncl.Link((fromhandle, todir, name))
        except NFSError as e:
            no = e.errno()
            raise IOError(no, os.strerror(no))
        finally:
            self.authlock.release()

    #'chmod'
    def chmod(self, path, mode):
        self.authlock.acquire()
        handle = None
        fattr = None
        try:
            handle, fattr = self.gethandle(path)
            fattr = self.ncl.Setattr((handle,
                (mode, -1, -1, -1, (-1,-1), (-1,-1)) ))
        except NFSError as e:
            no = e.errno()
            raise IOError(no, os.strerror(no))
        finally:
            self.authlock.release()
        self.handles[path] = (handle, fattr, time())

    #'chown'
    def chown(self, path, uid, gid):
        self.authlock.acquire()
        handle = None
        fattr = None
        try:
            handle, fattr = self.gethandle(path)
            fattr = self.ncl.Setattr((handle,
                (-1, uid, gid, -1, (-1, -1), (-1, -1)) ))
        except NFSError as e:
            no = e.errno()
            raise IOError(no, os.strerror(no))
        finally:
            self.authlock.release()
        self.handles[path] = (handle, fattr, time())

    #'truncate'
    def truncate(self, path, size):
        self.authlock.acquire()
        handle = None
        fattr = None
        try:
            handle, fattr = self.gethandle(path)
            fattr = self.ncl.Setattr((handle,
                (-1, -1, -1, size, (-1,-1), (-1,-1)) ))
        except NFSError as e:
            no = e.errno()
            raise IOError(no, os.strerror(no))
        finally:
            self.authlock.release()
        self.handles[path] = (handle, fattr, time())

    #'utime'
    def utime(self, path, times):
        atime, mtime = times
        self.authlock.acquire()
        handle = None
        fattr = None
        try:
            handle, fattr = self.gethandle(path)
            fattr = self.ncl.Setattr((handle,
                (-1, -1, -1, -1, (atime,0), (mtime,0)) ))
        except NFSError as e:
            no = e.errno()
            raise IOError(no, os.strerror(no))
        finally:
            self.authlock.release()
        self.handles[path] = (handle, fattr, time())

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
            fattr, data = self.ncl.Read((handle, offset, size, 0))
        except NFSError as e:
            no = e.errno()
            raise IOError(no, os.strerror(no), path)
        finally:
            self.authlock.release()
        self.handles[path] = (handle, fattr, time())
        return data

    #'write'
    def write(self, path, buf, offset):
        self.authlock.acquire()
        handle = None
        fattr = None
        size = 0
        try:
            handle, fattr = self.gethandle(path)
            size = fattr[5]
            fattr = self.ncl.Write((handle, 0, offset, 0, buf))
        except NFSError as e:
            no = e.errno()
            raise IOError(no, os.strerror(no), path)
        finally:
            self.authlock.release()
        self.handles[path] = (handle, fattr, time())
        return fattr[5] - size

    #'release'
    #'statfs'
    def statfs(self):
        st = fuse.StatVfs()
        rest = self.ncl.Statfs(self.rootdh)
        st.f_tsize, st.f_bsize, st.f_blocks, st.f_bfree, st.f_bavail = rest
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
        if uid <> 0 and gid <> 0:
            return 0
        elif gid <> 0:
            if mode & os.R_OK and rmode & 044:
                return 0
            elif mode & os.W_OK and rmode & 022:
                return 0
            elif mode & os.X_OK and rmode & 011:
                return 0
            else:
                raise IOError(EACCES, os.strerror(EACCES), path)
        elif uid <> 0:
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


class NFSStatVfs(fuse.StatVfs):
    def __init__(self, **kw):
        self.f_tsize = 0
        fuse.StatVfs.__init__(self, **kw)

def main():
    usage="""
NFSFuse: An NFS client with auth spoofing. Must be run as root.

""" + fuse.Fuse.fusage

    server = NFSFuse(version="%prog " + fuse.__version__,
        usage=usage, dash_s_do='setsingle')
    server.parser.add_option(mountopt='server',metavar='HOST:PATH',
        help='connect to server HOST:PATH')
    server.parser.add_option(mountopt='hide',action='store_true',help='Immediately unmount from the server, staying mounted on the client')
    # subbedopts doesn't support "default" kwarg. Leaving it in anyway for clarity, but it gets set in NFSFuse.main()
    server.parser.add_option(mountopt='cache',type="int",default=1024,help='Number of handles to cache')
    server.parser.add_option(mountopt='cachetimeout',type="int",default=120,help='Timeout on handle cache')
    server.parser.add_option(mountopt='mountport',metavar='PORT/TRANSPORT',default="udp",help='Specify port/transport for mount protocol, e.g. "635/udp"')
    server.parser.add_option(mountopt='dirhandle',metavar='00:AA:BB...',help='Use a colon-separated hex bytes representation of a directory handle instead of using mountd')
    server.parser.add_option(mountopt='getroot',action='store_true',help='Try to find the top-level directory of the export from the directory handle provided with "dirhandle"')
    server.parser.add_option(mountopt='nfsport',metavar='PORT/TRANSPORT',default="udp",help='Specify port/transport for NFS protocol, e.g. "2049/udp"')
    server.parse(values=server, errex=1)
    server.main()

if __name__ == '__main__':
    main()
