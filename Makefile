CC?=gcc
CFLAGS=-Wall -O3
LIBS=-lnet -lpcap -lresolv -lpthread
IN_FILE=dns_spoofer.c
OUT_FILE=dns_spoofer

build:
	$(CC) $(CFLAGS) $(IN_FILE) -o $(OUT_FILE) $(LIBS)
	
clean:
	rm -f $(OUT_FILE)
