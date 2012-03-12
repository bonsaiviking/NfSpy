import unittest
import nfspy

class NfSpyTestCase(unittest.TestCase):
    class NfSpyNonFuse(nfspy.NFSFuse):
        def main(self, *args, **kwargs):
            return self
    def setUp(self):
        self.fuseobj = nfspy.main(NfSpyTestCase.NfSpyNonFuse)
        self.fuseobj.fsinit()

    def test0_statfs(self):
        st = self.fuseobj.statfs()

    def test1_mkdir(self):
        pass

    def test1_mknod(self):
        pass

    def test1_symlink(self):
        pass

    def test1_link(self):
        pass

    def test1_write(self):
        pass

    def test2_access(self):
        pass

    def test2_gethandle(self):
        pass

    def test2_readlink(self):
        pass

    def test2_readdir(self):
        pass

    def test2_read(self):
        pass

    def test3_unlink(self):
        pass

    def test3_rmdir(self):
        pass

    def test3_rename(self):
        pass

    def test3_chmod(self):
        pass

    def test3_chown(self):
        pass

    def test3_truncate(self):
        pass

    def test3_utime(self):
        pass

    def tearDown(self):
        self.fuseobj.fsdestroy()

if (__name__=='__main__'):
    unittest.main(argv=['NfSpyTestCase'])
