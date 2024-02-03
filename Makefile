all: clean ct_monitor

ct_monitor:
	go build -o $@ -ldflags "-X github.com/crtsh/ct_monitor/config.BuildTimestamp=`date --utc +%Y-%m-%dT%H:%M:%SZ`"

clean:
	rm -f ct_monitor
