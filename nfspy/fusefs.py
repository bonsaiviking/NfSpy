import fuse
from nfspy import NfSpy, NFSStat

fuse.fuse_python_api = (0, 2)

class NFSFuse(NfSpy, fuse.Fuse):
    def __init__(self, *args, **kw):
        fuse.Fuse.__init__(self, *args, **kw)
        self.fuse_args.add("ro", True)
        NfSpy.__init__(self)

    def main(self, *args, **kwargs):

        return fuse.Fuse.main(self, *args, **kwargs)

    def fsinit(self):
        try:
            NfSpy.fsinit(self)
        except RuntimeError as e:
            raise fuse.FuseError, e.message

    def getattr(self, path):
        st = NfSpy.getattr(self, path)
        ret = fuse.Stat()
        ret.st_mode = st.st_mode
        ret.st_ino = st.st_ino
        ret.st_dev = st.st_dev
        ret.st_nlink = st.st_nlink
        ret.st_uid = st.st_uid
        ret.st_gid = st.st_gid
        ret.st_size = st.st_size
        ret.st_atime = st.st_atime
        ret.st_mtime = st.st_mtime
        ret.st_ctime = st.st_ctime
        return ret

    def readdir(self, path, offset):
        return (fuse.Direntry(dir[1]) for dir in NfSpy.readdir(self, path, offset))

    def statfs(self):
        ret_st = fuse.StatVfs()
        st = NfSpy.statfs(self)
        ret_st.f_tsize = ret_st.f_bsize = st.f_bsize
        ret_st.f_blocks = st.f_blocks
        ret_st.f_bfree = st.f_bfree
        ret_st.f_bavail = st.f_bavail
        ret_st.f_files = st.f_files
        ret_st.f_ffree = st.f_ffree
        ret_st.f_favail = st.f_favail
        return ret_st

def main(nfsFuseClass):
    usage="""
NFSFuse: An NFS client with auth spoofing. Must be run as root.

""" + fuse.Fuse.fusage

    server = nfsFuseClass(version="%prog " + fuse.__version__,
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
    server.parser.add_option(mountopt='fakename',metavar='HOSTNAME',default=None,help='try to fake your hostname')
    server.parse(values=server, errex=1)
    return server.main()

if __name__ == '__main__':
    main(NFSFuse)
