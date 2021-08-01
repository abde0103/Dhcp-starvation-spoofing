#ifndef HEADER_H_
#define HEADER_H_

#define HAVE_GETOPT_H

#include <stdio.h>
#include <locale.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <getopt.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <features.h>
#define usage printf
/**** Common definitions ****/
#define STATE_OK 0
#define STATE_WARNING 1
#define STATE_CRITICAL 2
#define STATE_UNKNOWN -1
#define OK 0
#define ERROR -1
#define FALSE 0
#define TRUE 1
#define LINKTYPE_NULL 0
#define LINKTYPE_ETH 1
#define LINKTYPE_WIFI 127

/**** DHCP definitions ****/
#define MAX_DHCP_CHADDR_LENGTH 16
#define MAX_DHCP_SNAME_LENGTH 64
#define MAX_DHCP_FILE_LENGTH 128
#define MAX_DHCP_OPTIONS_LENGTH 312

typedef struct dhcp_packet_struct
{
  u_int8_t op;                                  /* packet type */
  u_int8_t htype;                               /* type of hardware address for this machine (Ethernet, etc) */
  u_int8_t hlen;                                /* length of hardware address (of this machine) */
  u_int8_t hops;                                /* hops */
  u_int32_t xid;                                /* random transaction id number - chosen by this machine */
  u_int16_t secs;                               /* seconds used in timing */
  u_int16_t flags;                              /* flags */
  struct in_addr ciaddr;                        /* IP address of this machine (if we already have one) */
  struct in_addr yiaddr;                        /* IP address of this machine (offered by the DHCP server) */
  struct in_addr siaddr;                        /* IP address of DHCP server */
  struct in_addr giaddr;                        /* IP address of DHCP relay */
  unsigned char chaddr[MAX_DHCP_CHADDR_LENGTH]; /* hardware address of this machine */
  char sname[MAX_DHCP_SNAME_LENGTH];            /* name of DHCP server */
  char file[MAX_DHCP_FILE_LENGTH];              /* boot file name (used for diskless booting?) */
  char options[MAX_DHCP_OPTIONS_LENGTH];        /* options */
} dhcp_packet;

struct iphdr
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
  unsigned int ihl : 4;
  unsigned int version : 4;
#elif __BYTE_ORDER == __BIG_ENDIAN
  unsigned int version : 4;
  unsigned int ihl : 4;
#else
#error "Please fix <bits/endian.h>"
#endif
  u_int8_t tos;
  u_int16_t tot_len;
  u_int16_t id;
  u_int16_t frag_off;
  u_int8_t ttl;
  u_int8_t protocol;
  u_int16_t check;
  u_int32_t saddr;
  u_int32_t daddr;
  /*The options start here. */
};

//ethernet header

#define ETH_ALEN 6 /* Octets in one ethernet addr	 */

typedef struct dhcp_offer_struct
{
  struct in_addr server_address;  /* address of DHCP server that sent this offer */
  struct in_addr offered_address; /* the IP address that was offered to us */
  u_int32_t lease_time;           /* lease time in seconds */
  u_int32_t renewal_time;         /* renewal time in seconds */
  u_int32_t rebinding_time;       /* rebinding time in seconds */
  struct dhcp_offer_struct *next;
} dhcp_offer;

typedef struct requested_server_struct
{
  struct in_addr server_address;
  struct requested_server_struct *next;
} requested_server;

struct udphdr
{
  u_int16_t source;
  u_int16_t dest;
  u_int16_t len;
  u_int16_t check;
};

#define BOOTREQUEST 1
#define BOOTREPLY 2

#define DHCPDISCOVER 1
#define DHCPOFFER 2
#define DHCPREQUEST 3
#define DHCPDECLINE 4
#define DHCPACK 5
#define DHCPNACK 6
#define DHCPRELEASE 7

#define DHCP_OPTION_MESSAGE_TYPE 53
#define DHCP_OPTION_HOST_NAME 12
#define DHCP_OPTION_BROADCAST_ADDRESS 28
#define DHCP_OPTION_REQUESTED_ADDRESS 50
#define DHCP_OPTION_LEASE_TIME 51
#define DHCP_OPTION_RENEWAL_TIME 58
#define DHCP_OPTION_REBINDING_TIME 59

#define DHCP_INFINITE_TIME 0xFFFFFFFF

#define DHCP_BROADCAST_FLAG 32768

#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68

#define ETHERNET_HARDWARE_ADDRESS 1        /* used in htype field of dhcp packet */
#define ETHERNET_HARDWARE_ADDRESS_LENGTH 6 /* length of Ethernet hardware addresses */

char *network_interface_name;
char *server_ip;
struct sockaddr_in source, dest;
FILE *logfile;

int get_hardware_address(int, char *);

int send_dhcp_discover(int);
int get_dhcp_discover(int);
int send_dhcp_offer(int);
int get_dhcp_offer(int);

int get_results(void);
void PrintData(const u_char *, int);
int create_dhcp_socket(void);
int close_dhcp_socket(int);
int send_dhcp_packet(void *, int, int, struct sockaddr_in *);
int receive_dhcp_packet(void *, int, int, int, struct sockaddr_in *);
int set_up_connection();
int set_up_first_connection();
void print_udp_packet(const u_char *, int);
unsigned short checksum(unsigned short *ptr, int nbytes);
#endif