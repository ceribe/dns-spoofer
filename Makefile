build:
	gcc -Wall ./dns_spoofer.c -o ./dns_spoofer -lnet -lpcap
clean:
	rm -f ./dns_spoofer