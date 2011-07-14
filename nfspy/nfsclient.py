# Modified from code distributed with Python 2.6
# NFS RPC client -- RFC 1094

import rpc
from rpc import UDPClient, TCPClient
from mountclient import FHSIZE, MountPacker, MountUnpacker
import errno
import os

NFS_PROGRAM = 100003
NFS_VERSION = 2

# enum stat
NFS_OK = 0
NFSERR_PERM=1
NFSERR_NOENT=2
NFSERR_IO=5
NFSERR_NXIO=6
NFSERR_ACCES=13
NFSERR_EXIST=17
NFSERR_NODEV=19
NFSERR_NOTDIR=20
NFSERR_ISDIR=21
NFSERR_FBIG=27
NFSERR_NOSPC=28
NFSERR_ROFS=30
NFSERR_NAMETOOLONG=63
NFSERR_NOTEMPTY=66
NFSERR_DQUOT=69
NFSERR_STALE=70
NFSERR_WFLUSH=99

class NFSError(Exception):
    lookup = {
        NFSERR_PERM        : errno.EPERM,
        NFSERR_NOENT       : errno.ENOENT,
        NFSERR_IO          : errno.EIO,
        NFSERR_NXIO        : errno.ENXIO,
        NFSERR_ACCES       : errno.EACCES,
        NFSERR_EXIST       : errno.EEXIST,
        NFSERR_NODEV       : errno.ENODEV,
        NFSERR_NOTDIR      : errno.ENOTDIR,
        NFSERR_ISDIR       : errno.EISDIR,
        NFSERR_FBIG        : errno.EFBIG,
        NFSERR_NOSPC       : errno.ENOSPC,
        NFSERR_ROFS        : errno.EROFS,
        NFSERR_NAMETOOLONG : errno.ENAMETOOLONG,
        NFSERR_NOTEMPTY    : errno.ENOTEMPTY,
        NFSERR_DQUOT       : errno.EDQUOT,
        NFSERR_STALE       : errno.ESTALE
    }
    def __init__(self,value=None):
        self.value = value
    def __str__(self):
        try:
            return os.strerror(lookup[self.value])
        except KeyError:
            return "NFS Error"
    def errno(self):
        return self.value

# enum ftype
NFNON = 0
NFREG = 1
NFDIR = 2
NFBLK = 3
NFCHR = 4
NFLNK = 5


class NFSPacker(MountPacker):

    def pack_sattrargs(self, sa):
        file, attributes = sa
        self.pack_fhandle(file)
        self.pack_sattr(attributes)

    def pack_sattr(self, sa):
        mode, uid, gid, size, atime, mtime = sa
        self.pack_uint(mode)
        self.pack_uint(uid)
        self.pack_uint(gid)
        self.pack_uint(size)
        self.pack_timeval(atime)
        self.pack_timeval(mtime)

    def pack_diropargs(self, da):
        dir, name = da
        self.pack_fhandle(dir)
        self.pack_string(name)

    def pack_readdirargs(self, ra):
        dir, cookie, count = ra
        self.pack_fhandle(dir)
        self.pack_uint(cookie)
        self.pack_uint(count)

    def pack_readargs(self, ra):
        file, offset, count, totalcount = ra
        self.pack_fhandle(file)
        self.pack_uint(offset)
        self.pack_uint(count)
        self.pack_uint(totalcount)

    def pack_writeargs(self, wa):
        file, beginoffset, offset, totalcount, data = wa
        self.pack_fhandle(file)
        self.pack_uint(beginoffset)
        self.pack_uint(offset)
        self.pack_uint(totalcount)
        self.pack_opaque(data)

    def pack_createargs(self, ca):
        dir, name, mode, uid, gid, size, atime, mtime = ca
        self.pack_fhandle(dir)
        self.pack_string(name)
        self.pack_uint(mode)
        self.pack_uint(uid)
        self.pack_uint(gid)
        self.pack_uint(size)
        self.pack_timeval(atime)
        self.pack_timeval(mtime)

    def pack_renameargs(self, ra):
        fromdir, fromname, todir, toname = ra
        self.pack_fhandle(fromdir)
        self.pack_string(fromname)
        self.pack_fhandle(todir)
        self.pack_string(toname)

    def pack_linkargs(self, la):
        fromhandle, todir, toname = la
        self.pack_fhandle(fromhandle)
        self.pack_fhandle(todir)
        self.pack_string(toname)

    def pack_symlinkargs(self, sa):
        fromdir, fromname, to, mode, uid, gid, size, atime, mtime = sa
        self.pack_fhandle(fromdir)
        self.pack_string(fromname)
        self.pack_string(to)
        self.pack_uint(mode)
        self.pack_uint(uid)
        self.pack_uint(gid)
        self.pack_uint(size)
        self.pack_timeval(atime)
        self.pack_timeval(mtime)

    def pack_timeval(self, tv):
        secs, usecs = tv
        self.pack_uint(secs)
        self.pack_uint(usecs)


class NFSUnpacker(MountUnpacker):

    def unpack_readdirres(self):
        status = self.unpack_enum()
        if status == NFS_OK:
            entries = self.unpack_list(self.unpack_entry)
            eof = self.unpack_bool()
            rest = (entries, eof)
        else:
            rest = None
        return (status, rest)

    def unpack_entry(self):
        fileid = self.unpack_uint()
        name = self.unpack_string()
        cookie = self.unpack_uint()
        return (fileid, name, cookie)

    def unpack_diropres(self):
        status = self.unpack_enum()
        if status == NFS_OK:
            fh = self.unpack_fhandle()
            fa = self.unpack_fattr()
            rest = (fh, fa)
        else:
            rest = None
        return (status, rest)

    def unpack_readres(self):
        status = self.unpack_enum()
        if status == NFS_OK:
            fa = self.unpack_fattr()
            data = self.unpack_opaque()
            rest = (fa, data)
        else:
            rest = None
        return (status, rest)

    def unpack_attrstat(self):
        status = self.unpack_enum()
        if status == NFS_OK:
            attributes = self.unpack_fattr()
        else:
            attributes = None
        return status, attributes

    def unpack_fattr(self):
        type = self.unpack_enum()
        mode = self.unpack_uint()
        nlink = self.unpack_uint()
        uid = self.unpack_uint()
        gid = self.unpack_uint()
        size = self.unpack_uint()
        blocksize = self.unpack_uint()
        rdev = self.unpack_uint()
        blocks = self.unpack_uint()
        fsid = self.unpack_uint()
        fileid = self.unpack_uint()
        atime = self.unpack_timeval()
        mtime = self.unpack_timeval()
        ctime = self.unpack_timeval()
        return (type, mode, nlink, uid, gid, size, blocksize, \
                rdev, blocks, fsid, fileid, atime, mtime, ctime)

    def unpack_timeval(self):
        secs = self.unpack_uint()
        usecs = self.unpack_uint()
        return (secs, usecs)

    def unpack_readlinkres(self):
        status = self.unpack_enum()
        if status == NFS_OK:
            path = self.unpack_string()
        else:
            path = None
        return status, path

    def unpack_statfsres(self):
        status = self.unpack_enum()
        if status == NFS_OK:
            tsize = self.unpack_uint()
            bsize = self.unpack_uint()
            blocks = self.unpack_uint()
            bfree = self.unpack_uint()
            bavail = self.unpack_uint()
            rest = ( tsize, bsize, blocks, bfree, bavail )
        else:
            rest = None
        return status, rest
import sys
def check_status(procedure):
    def wrapped(*args, **kwargs):
        ret = procedure(*args, **kwargs)
        if isinstance(ret, tuple):
            status, ret = ret
        else:
            status = ret
            ret = None
        if status <> NFS_OK:
            raise NFSError(status)
        else:
            return ret
    return wrapped

class NFSClient(UDPClient):
    def __init__(self, host):
        UDPClient.__init__(self, host, NFS_PROGRAM, NFS_VERSION)
    #def __init__(self, host):
        #raise RuntimeError, 'Must use UDPNFSClient or TCPNFSClient'

    def bindsocket(self):
        import os
        try:
            uid = os.getuid()
        except AttributeError:
            uid = 1
        if uid == 0:
            port = rpc.bindresvport(self.sock, '')
            # 'port' is not used
        else:
            self.sock.bind(('', 0))

    def addpackers(self):
        self.packer = NFSPacker()
        self.unpacker = NFSUnpacker('')

    def mkcred(self):
        if self.cred is None:
            self.cred = rpc.AUTH_UNIX, rpc.make_auth_unix_default()
        return self.cred

    @check_status
    def Getattr(self, fh):
        return self.make_call(1, fh, \
                self.packer.pack_fhandle, \
                self.unpacker.unpack_attrstat)

    @check_status
    def Setattr(self, sa):
        return self.make_call(2, sa, \
                self.packer.pack_sattrargs, \
                self.unpacker.unpack_attrstat)

    # Root() is obsolete

    @check_status
    def Lookup(self, da):
        return self.make_call(4, da, \
                self.packer.pack_diropargs, \
                self.unpacker.unpack_diropres)

    @check_status
    def Readlink(self, fh):
        return self.make_call(5, fh, \
            self.packer.pack_fhandle, \
            self.unpacker.unpack_readlinkres)

    @check_status
    def Read(self, ra):
        return self.make_call(6, ra, \
            self.packer.pack_readargs, \
            self.unpacker.unpack_readres)

    # NFSPROC_WRITECACHE() "to be used in the next protocol revision"

    @check_status
    def Write(self, wa):
        return self.make_call(8, wa, \
            self.packer.pack_writeargs, \
            self.unpacker.unpack_attrstat)

    @check_status
    def Create(self, ca):
        return self.make_call(9, ca, \
            self.packer.pack_createargs, \
            self.unpacker.unpack_diropres)

    @check_status
    def Remove(self, da):
        return self.make_call(10, da, \
            self.packer.pack_diropargs, \
            self.unpacker.unpack_enum)

    @check_status
    def Rename(self, ra):
        return self.make_call(11, ra, \
            self.packer.pack_renameargs, \
            self.unpacker.unpack_enum)

    @check_status
    def Link(self, la):
        return self.make_call(12, la, \
            self.packer.pack_linkargs, \
            self.unpacker.unpack_enum)

    @check_status
    def Symlink(self, sa):
        return self.make_call(13, sa, \
            self.packer.pack_symlinkargs, \
            self.unpacker.unpack_enum)

    @check_status
    def Mkdir(self, ca):
        return self.make_call(14, ca, \
            self.packer.pack_createargs, \
            self.unpacker.unpack_diropres)

    @check_status
    def Rmdir(self, da):
        return self.make_call(15, da, \
            self.packer.pack_diropargs, \
            self.unpacker.unpack_enum)

    @check_status
    def Readdir(self, ra):
        return self.make_call(16, ra, \
                self.packer.pack_readdirargs, \
                self.unpacker.unpack_readdirres)

    @check_status
    def Statfs(self, fh):
        return self.make_call(17, fh, \
            self.packer.pack_fhandle, \
            self.unpacker.unpack_statfsres)

    # Shorthand to get the entire contents of a directory
    def Listdir(self, dir, tsize):
        list = []
        ra = (dir, 0, tsize)
        while 1:
            entries, eof = self.Readdir(ra)
            last_cookie = None
            for fileid, name, cookie in entries:
                list.append((fileid, name))
                last_cookie = cookie
            if eof or last_cookie is None:
                break
            ra = (ra[0], last_cookie, ra[2])
        return list

class TCPNFSClient(TCPClient,NFSClient):
    def __init__(self, host):
        TCPClient.__init__(self, host, NFS_PROGRAM, NFS_VERSION)

class UDPNFSClient(UDPClient,NFSClient):
    def __init__(self, host):
        UDPClient.__init__(self, host, NFS_PROGRAM, NFS_VERSION)

def test():
    import sys
    if sys.argv[1:]: host = sys.argv[1]
    else: host = ''
    if sys.argv[2:]: filesys = sys.argv[2]
    else: filesys = None
    from mountclient import UDPMountClient, TCPMountClient
    mcl = TCPMountClient(host)
    if filesys is None:
        list = mcl.Export()
        for item in list:
            print item
        return
    sf = mcl.Mnt(filesys)
    print sf
    fh = sf[1]
    if fh:
        ncl = NFSClient(host)
        attrstat = ncl.Getattr(fh)
        print "gotattrs\n"
        print attrstat
        list = ncl.Listdir(fh, 4096)
        for item in list: print item
        mcl.Umnt(filesys)

if __name__ == '__main__':
    test()
