all: clean ct_monitor

# Tidy up files created by compiler/linker.
clean:
	rm -f ct_monitor

ct_monitor:
	GOPATH=/home/rob/go go build -ldflags "-X main.build_date=`date -u +%Y-%m-%d.%H:%M:%S` -X main.svn_revision=`svnversion -n`" ct_monitor.go processor_main.go
