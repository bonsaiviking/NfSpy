all: lrucache.pyc mountclient.pyc nfsclient.pyc rpc.pyc

%.pyc: nfsfuse.py lrucache.py mountclient.py nfsclient.py rpc.py
	python $< --help

install: nfsfuse.py all
	cp *.pyc /usr/local/lib/python2.6/site-packages/
	ln -s `pwd`/$< /usr/local/bin/nfsfuse

clean:
	rm -f *.pyc
