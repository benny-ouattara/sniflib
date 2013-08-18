CFLAGS = -Wall -g

clean:
	rm -rf sniffer
	rm -rf test

all:
	#cc sniffer.c -o sniffer -lpcap
	cc testsniffer.c sniffer.c -o test -lpcap