build:
	gcc -Wall ./dns_spoofer.c -o ./dns_spoofer -lnet
clean:
	rm -f ./dns_spoofer