CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=c99 -D_DEFAULT_SOURCE -D_DARWIN_C_SOURCE
LDLIBS  = -lpcap

netdump: netdump.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LDLIBS)

clean:
	rm -f netdump

.PHONY: clean
