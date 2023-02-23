all: clean ct_monitor

ct_monitor:
	go build -o $@ -ldflags "$(shell ~/go/bin/govvv -flags | sed 's/main/github.com\/crtsh\/ct_monitor\/config/g')"

clean:
	rm -f ct_monitor
