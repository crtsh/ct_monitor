all: clean ct_monitor

# Tidy up files created by compiler/linker.
clean:
	rm -f ct_monitor

ct_monitor:
	GOPATH=/home/rob/go go build ct_monitor.go processor_main.go
