# Modified from code distributed with Python 2.6
# NFS RPC client -- RFC 1094

import rpc
from rpc import UDPClient, TCPClient
from mountclient import FHSIZE, MountPacker, MountUnpacker
import errno
import os

NFS_PROGRAM = 100003
NFS_VERSION = 2


class NFSError(Exception):
    # enum stat
    NFS3_OK              =  0
    NFS3ERR_PERM         =  1
    NFS3ERR_NOENT        =  2
    NFS3ERR_IO           =  5
    NFS3ERR_NXIO         =  6
    NFS3ERR_ACCES        =  13
    NFS3ERR_EXIST        =  17
    NFS3ERR_XDEV         =  18
    NFS3ERR_NODEV        =  19
    NFS3ERR_NOTDIR       =  20
    NFS3ERR_ISDIR        =  21
    NFS3ERR_INVAL        =  22
    NFS3ERR_FBIG         =  27
    NFS3ERR_NOSPC        =  28
    NFS3ERR_ROFS         =  30
    NFS3ERR_MLINK        =  31
    NFS3ERR_NAMETOOLONG  =  63
    NFS3ERR_NOTEMPTY     =  66
    NFS3ERR_DQUOT        =  69
    NFS3ERR_STALE        =  70
    NFS3ERR_REMOTE       =  71
    NFS3ERR_BADHANDLE    =  10001
    NFS3ERR_NOT_SYNC     =  10002
    NFS3ERR_BAD_COOKIE   =  10003
    NFS3ERR_NOTSUPP      =  10004
    NFS3ERR_TOOSMALL     =  10005
    NFS3ERR_SERVERFAULT  =  10006
    NFS3ERR_BADTYPE      =  10007
    NFS3ERR_JUKEBOX      =  10008

    lookup = {
        NFS3ERR_PERM         :  errno.EPERM,
        NFS3ERR_NOENT        :  errno.ENOENT,
        NFS3ERR_IO           :  errno.EIO,
        NFS3ERR_NXIO         :  errno.ENXIO,
        NFS3ERR_ACCES        :  errno.EACCES,
        NFS3ERR_EXIST        :  errno.EEXIST,
        NFS3ERR_XDEV         :  errno.EXDEV,
        NFS3ERR_NODEV        :  errno.ENODEV,
        NFS3ERR_NOTDIR       :  errno.ENOTDIR,
        NFS3ERR_ISDIR        :  errno.EISDIR,
        NFS3ERR_FBIG         :  errno.EFBIG,
        NFS3ERR_NOSPC        :  errno.ENOSPC,
        NFS3ERR_ROFS         :  errno.EROFS,
        NFS3ERR_MLINK        :  errno.EMLINK,
        NFS3ERR_NAMETOOLONG  :  errno.ENAMETOOLONG,
        NFS3ERR_NOTEMPTY     :  errno.ENOTEMPTY,
        NFS3ERR_DQUOT        :  errno.EDQUOT,
        NFS3ERR_STALE        :  errno.ESTALE,
        NFS3ERR_REMOTE       :  errno.EREMOTE,
        NFS3ERR_BADHANDLE    :  errno.EBADR,
        NFS3ERR_NOT_SYNC     :  errno.EREMCHG,
        NFS3ERR_BAD_COOKIE   :  errno.ESTALE,
        NFS3ERR_NOTSUPP      :  errno.EOPNOTSUPP,
        NFS3ERR_TOOSMALL     :  errno.ENOBUFS,
        NFS3ERR_SERVERFAULT  :  errno.EREMOTEIO,
        NFS3ERR_BADTYPE      :  errno.ESOCKTNOSUPPORT,
        NFS3ERR_JUKEBOX      :  errno.EAGAIN,
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

# enum ftype3
NF3NON   = 0
NF3REG   = 1
NF3DIR   = 2
NF3BLK   = 3
NF3CHR   = 4
NF3LNK   = 5
NF3SOCK = 6
NF3FIFO = 7

class NFSPacker(Mount3Packer):

    def pack_sattrargs(self, sa):
        file, attributes, guard = sa
        self.pack_fhandle(file)
        self.pack_sattr(attributes)
        self.pack_bool(guard[0])
        if guard[0]:
            self.pack_nfstime3(guard[1])

    def pack_sattr3(self, sa):
        mode, uid, gid, size, atime, mtime = sa
        for attr in (mode, uid, gid):
            self.pack_bool(attr[0])
            if attr[0]:
                self.pack_uint(attr[1])
        self.pack_bool(size[0])
        if size[0]:
            self.pack_uhyper(size[1])
        for t in (atime, mtime):
            self.pack_enum(t[0])
            if t[0]==2:
                self.pack_nfstime3(t[1])

    def pack_diropargs(self, da):
        dir, name = da
        self.pack_fhandle(dir)
        self.pack_string(name)

    def pack_accessargs(self, aa):
        fh, access = aa
        self.pack_fhandle(fh)
        self.pack_uint(access)

    def pack_readdirargs(self, ra):
        dir, cookie, cookieverf, count = ra
        self.pack_fhandle(dir)
        self.pack_uhyper(cookie)
        self.pack_opaque(cookieverf)
        self.pack_uint(count)

    def pack_readdirplusargs(self, ra):
        self.pack_readdirargs(ra[0:4])
        self.pack_uint(ra[4]) #maxcount

    def pack_readargs(self, ra):
        file, offset, count = ra
        self.pack_fhandle(file)
        self.pack_uhyper(offset)
        self.pack_uint(count)

    def pack_writeargs(self, wa):
        file, offset, count, stable, data = wa
        self.pack_fhandle(file)
        self.pack_uhyper(offset)
        self.pack_uint(count)
        self.pack_enum(stable)
        self.pack_opaque(data)

    def pack_createargs(self, ca):
        dir, name, how, sattr = ca
        self.pack_diropargs((dir, name))
        self.pack_enum(how)
        if how == 1 or how == 2:
            self.pack_sattr3(sattr)
        else: #how == 3
            self.pack_opaque(sattr) #createverf3

    def pack_specdata(self, spec):
        self.pack_uint(spec[0])
        self.pack_uint(spec[1])

    def pack_mknodargs(self, ma):
        dir, name, type, sattr, spec = ma
        self.pack_diropargs((dir, name))
        self.pack_enum(type)
        if type in (NF3CHR, NF3BLK):
            self.pack_sattr3(sattr)
            self.pack_specdata(spec)
        elif type in (NF3SOCK, NF3FIFO):
            self.pack_sattr3(sattr)

    def pack_mkdirargs(self, ma):
        dir, name, sattr = ma
        self.pack_diropargs((dir, name))
        self.pack_sattr3(sattr)

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
        fromdir, fromname, sattr, to = sa
        self.pack_diropargs((fromdir, fromname))
        self.pack_sattr3(sattr)
        self.pack_string(to)

    def pack_nfstime3(self, tv):
        secs, nsecs = tv
        self.pack_uint(secs)
        self.pack_uint(nsecs)


class NFSUnpacker(MountUnpacker):

    def unpack_readdirres(self):
        status = self.unpack_enum()
        attr = self.unpack_post_op_attr()
        if status == NFS_OK:
            verf = self.unpack_opaque()
            entries = self.unpack_list(self.unpack_entry)
            eof = self.unpack_bool()
            rest = (verf, entries, eof)
        else:
            rest = attr
        return (status, rest)
    
    def unpack_readdirplusres(self):
        status = self.unpack_enum()
        attr = self.unpack_post_op_attr()
        if status == NFS_OK:
            verf = self.unpack_opaque()
            entries = self.unpack_list(self.unpack_entryplus)
            eof = self.unpack_bool()
            rest = (verf, entries, eof)
        else:
            rest = attr
        return (status, rest)

    def unpack_entryplus(self):
        fileid = self.unpack_uhyper()
        name = self.unpack_string()
        cookie = self.unpack_uhyper()
        attr = self.unpack_post_op_attr()
        fh = self.unpack_post_op_fh()
        return (fileid, name, cookie, attr, fh)

    def unpack_entry(self):
        fileid = self.unpack_uhyper()
        name = self.unpack_string()
        cookie = self.unpack_uhyper()
        return (fileid, name, cookie)

    def unpack_diropres(self):
        status = self.unpack_enum()
        if status == NFS_OK:
            fh = self.unpack_fhandle()
            da = self.unpack_post_op_attr()
            fa = self.unpack_post_op_attr()
            rest = (fh, da, fa)
        else:
            rest = self.unpack_post_op_attr()
        return (status, rest)

    def unpack_post_op_fh(self):
        follows = self.unpack_bool()
        if follows:
            return self.unpack_fhandle()
        else:
            return None

    def unpack_createres(self):
        status = self.unpack_enum()
        if status == NFS_OK:
            fh = self.unpack_post_op_fh()
            fa = self.unpack_post_op_attr()
            dir_wcc = self.unpack_wcc_data()
            rest = (fh, fa, dir_wcc)
        else:
            rest = self.unpack_wcc_data()
        return (status, rest)

    def unpack_accessres(self):
        status = self.unpack_enum()
        attr = self.unpack_post_op_attr()
        access = None
        if status == NFS_OK:
            access = self.unpack_uint()
        return status, (attr, access)

    def unpack_readres(self):
        status = self.unpack_enum()
        fa = self.unpack_fattr()
        if status == NFS_OK:
            count = self.unpack_uint()
            eof = self.unpack_bool()
            data = self.unpack_opaque()
            rest = (fa, count, eof, data)
        else:
            rest = fa
        return status, rest

    def unpack_attrstat(self):
        status = self.unpack_enum()
        if status == NFS_OK:
            attributes = self.unpack_fattr()
        else:
            attributes = None
        return status, attributes

    def unpack_writeres(self):
        status = self.unpack_enum()
        wcc = self.unpack_wcc_data()
        if status == NFS_OK:
            count = self.unpack_uint()
            committed = self.unpack_enum()
            verf = self.unpack_opaque()
            rest = (wcc, count, committed, verf)
        else:
            rest = wcc
        return status, rest

    def unpack_wcc_attr():
        size = self.unpack_uhyper()
        mtime = self.unpack_nfstime3()
        ctime = self.unpack_nfstime3()
        return size, mtime, ctime

    def unpack_pre_op_attr(self):
        if self.unpack_bool():
            return self.unpack_wcc_attr()
        else:
            return None

    def unpack_post_op_attr(self):
        if self.unpack_bool():
            return self.unpack_fattr()
        else:
            return None

    def unpack_wcc_data(self):
        before = self.unpack_pre_op_attr()
        after = self.unpack_post_op_attr()
        return (before, after)

    def unpack_wccstat(self):
        status = self.unpack_enum()
        wcc = self.unpack_wcc_data()
        return status, wcc

    def unpack_renameres(self):
        status = self.unpack_enum()
        wccf= self.unpack_wcc_data()
        wcct = self.unpack_wcc_data()
        return status, (wccf, wcct)

    def unpack_linkres(self):
        status = self.unpack_enum()
        attr = self.unpack_post_op_attr()
        wcc = self.unpack_wcc_data()
        return status, (attr, wcc)

    def unpack_commitres(self):
        status = self.unpack_enum()
        wcc = self.unpack_wcc_data()
        if status == NFS_OK:
            verf = self.unpack_opaque()
            rest = (wcc, verf)
        else:
            rest = wcc
        return status, rest

    def unpack_specdata3(self):
        specdata1 = self.unpack_uint()
        specdata2 = self.unpack_uint()
        return (specdata1, specdata2)

    def unpack_fattr(self):
        type = self.unpack_enum()
        mode = self.unpack_uint()
        nlink = self.unpack_uint()
        uid = self.unpack_uint()
        gid = self.unpack_uint()
        size = self.unpack_uhyper()
        used = self.unpack_uhyper()
        rdev = self.unpack_specdata3()
        fsid = self.unpack_uhyper()
        fileid = self.unpack_uhyper()
        atime = self.unpack_nfstime3()
        mtime = self.unpack_nfstime3()
        ctime = self.unpack_nfstime3()
        return (type, mode, nlink, uid, gid, size, used, \
                rdev, fsid, fileid, atime, mtime, ctime)

    def unpack_nfstime3(self):
        secs = self.unpack_uint()
        nsecs = self.unpack_uint()
        return (secs, nsecs)

    def unpack_readlinkres(self):
        status = self.unpack_enum()
        attr = self.unpack_post_op_attr()
        path = None
        if status == NFS_OK:
            path = self.unpack_string()
        return status, (attr, path)

    def unpack_fsstatres(self):
        status = self.unpack_enum()
        attr = self.unpack_post_op_attr()
        if status == NFS_OK:
            tbytes = self.unpack_uhyper()
            fbytes = self.unpack_uhyper()
            abytes = self.unpack_uhyper()
            tfiles = self.unpack_uhyper()
            ffiles = self.unpack_uhyper()
            afiles = self.unpack_uhyper()
            invarsec = self.unpack_uint()
            rest = ( attr, tbytes, fbytes, abytes,
                    tfiles, ffiles, afiles, invarsec )
        else:
            rest = attr
        return status, rest

    def unpack_fsinfores(self):
        status = self.unpack_enum()
        attr = self.unpack_post_op_attr()
        if status == NFS_OK:
            rtmax = self.unpack_uint()
            rtpref = self.unpack_uint()
            rtmult = self.unpack_uint()
            wtmax = self.unpack_uint()
            wtpref = self.unpack_uint()
            wtmult = self.unpack_uint()
            dtpref = self.unpack_uint()
            maxfilesize = self.unpack_uhyper()
            delta = self.unpack_nfstime3()
            props = self.unpack_uint()
            rest = ( attr, rtmax, rtpref, rtmult, wtmax, wtpref,
                    wtmult, dtpref, maxfilesize, delta, props)
        else:
            rest = attr
        return status, rest

    def unpack_pathconfres(self):
        status = self.unpack_enum()
        attr = self.unpack_post_op_attr()
        if status == NFS_OK:
            linkmax = self.unpack_uint()
            name_max = self.unpack_uint()
            no_trunc = self.unpack_bool()
            chown_restricted = self.unpack_bool()
            case_insensitive = self.unpack_bool()
            case_preserving = self.unpack_bool()
            rest = (attr, linkmax, name_max, no_trunc,
                    chown_restricted, case_insensitive, case_preserving)
        else:
            rest = attr
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

class UDPNFSClient(UDPClient):
    def __init__(self, host):
        UDPClient.__init__(self, host, NFS_PROGRAM, NFS_VERSION)

class TCPNFSClient(TCPClient):
    def __init__(self, host):
        TCPClient.__init__(self, host, NFS_PROGRAM, NFS_VERSION)

class PartialNFSClient:
    def __init__(self, host):
        raise RuntimeError, 'Must use UDPNFSClient or TCPNFSClient'

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
                self.unpacker.unpack_wcc_data)

    # Root() is obsolete

    @check_status
    def Lookup(self, da):
        return self.make_call(3, da, \
                self.packer.pack_diropargs, \
                self.unpacker.unpack_diropres)

    @check_status
    def Access(self, aa):
        return self.make_call(4, aa,
                self.packer.pack_accessargs,
                self.unpacker.unpack_accessres)

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
        return self.make_call(7, wa, \
            self.packer.pack_writeargs, \
            self.unpacker.unpack_writeres)

    @check_status
    def Create(self, ca):
        return self.make_call(8, ca, \
            self.packer.pack_createargs, \
            self.unpacker.unpack_createres)

    @check_status
    def Mkdir(self, ca):
        return self.make_call(9, ca, \
            self.packer.pack_mkdirargs, \
            self.unpacker.unpack_createres)

    @check_status
    def Symlink(self, sa):
        return self.make_call(10, sa, \
            self.packer.pack_symlinkargs, \
            self.unpacker.unpack_createres)

    @check_status
    def Mknod(self, ma):
        return self.make_call(11, ma,
            self.packer.pack_mknodargs,
            self.unpacker.unpack_createres)

    @check_status
    def Remove(self, da):
        return self.make_call(12, da, \
            self.packer.pack_diropargs, \
            self.unpacker.unpack_wccstat)

    @check_status
    def Rmdir(self, da):
        return self.make_call(13, da, \
            self.packer.pack_diropargs, \
            self.unpacker.unpack_wccstat)

    @check_status
    def Rename(self, ra):
        return self.make_call(14, ra, \
            self.packer.pack_renameargs, \
            self.unpacker.unpack_renameres)

    @check_status
    def Link(self, la):
        return self.make_call(15, la, \
            self.packer.pack_linkargs, \
            self.unpacker.unpack_linkres)

    @check_status
    def Readdir(self, ra):
        return self.make_call(16, ra, \
                self.packer.pack_readdirargs, \
                self.unpacker.unpack_readdirres)

    @check_status
    def Readdirplus(self, ra):
        return self.make_call(17, ra,
                self.packer.pack_readdirplusargs,
                self.unpacker.unpack_readdirplusres)

    @check_status
    def Fsstat(self, fh):
        return self.make_call(18, fh, \
            self.packer.pack_fhandle, \
            self.unpacker.unpack_fsstatres)

    @check_status
    def Fsinfo(self, fh):
        return self.make_call(19, fh, \
            self.packer.pack_fhandle, \
            self.unpacker.unpack_fsinfores)

    @check_status
    def Pathconf(self, fh):
        return self.make_call(20, fh,
            self.packer.pack_fhandle,
            self.unpacker.unpack_pathconfres)

    @check_status
    def Commit(self, ca):
        return self.make_call(21, ca,
            self.packer.pack_readargs,
            self.unpacker.unpack_commitres)

    # Shorthand to get the entire contents of a directory
    def Listdir(self, dir, tsize):
        list = []
        ra = (dir, 0, tsize)
        while 1:
            attr, entries, eof = self.Readdir(ra)
            last_cookie = None
            for fileid, name, cookie in entries:
                list.append((fileid, name))
                last_cookie = cookie
            if eof or last_cookie is None:
                break
            ra = (ra[0], last_cookie, ra[2])
        return list

class TCPNFSClient(TCPClient,PartialNFSClient):
    def __init__(self, host):
        TCPClient.__init__(self, host, NFS_PROGRAM, NFS_VERSION)

class UDPNFSClient(UDPClient,PartialNFSClient):
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
        ncl = UDPNFSClient(host)
        attrstat = ncl.Getattr(fh)
        print "gotattrs\n"
        print attrstat
        list = ncl.Listdir(fh, 4096)
        for item in list: print item
        mcl.Umnt(filesys)

if __name__ == '__main__':
    test()
