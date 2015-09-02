all: clean ct_monitor

# C Compiler name and flags
CC = gcc
CCFLAGS = -O3 -ansi -pedantic -Wall -Wno-long-long -D_DEFAULT_SOURCE -D_GNU_SOURCE
COMPILE = $(CC) $(CCFLAGS) -c
LINK = gcc

# Rule for compiling a source file to a .o object file.
.c.o:
	$(COMPILE) -o $@ $<

# Tidy up files created by compiler/linker.
clean:
	rm -f *.o *~ ct_monitor

ct_monitor: ct_monitor.o
	$(LINK) -o $@ $< -lcrypto -lpq -lcurl -ljson-c
	rm $<
