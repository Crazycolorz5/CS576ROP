CFLAGS_V= -z -noexecstack
CFLAGS=-fno-stack-protector -g -O1 -Wno-format-security -Wno-format -U_FORTIFY_SOURCE -Wall
TARGETS=vuln_prog.bin
CC=gcc

# all: $(MAKE) clean && $(MAKE) $(TARGETS)
all: clean $(TARGETS)

vuln_prog.bin : vuln_prog.c
	$(CC) -m32 $(CFLAGS_V) $(CFLAGS) -o $@ $<

clean:
	rm -rf *.bin $(TARGETS)
