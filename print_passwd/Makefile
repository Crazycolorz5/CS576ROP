CFLAGS=-fno-stack-protector -O0 #-mpreferred-stack-boundary=2 

all:
	gcc $(CFLAGS) -c passwd.s && ld passwd.o -o passwd

clean:
	rm -rf passwd *.o
