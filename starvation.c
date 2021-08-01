#include "header.h"

int main(int argc, char **argv)
{

	if (argc >= 2)
	{
		network_interface_name = argv[1];
	}
	else
	{
		network_interface_name = "enp0s8";
		printf("\nInterface autoset to enp0s8 \n");
	}
	if (argc >= 3)
		server_ip = argv[2];

	int result;
	srand(42);
	int count = 0;
	int dhcp_socket;
	dhcp_socket = set_up_first_connection();
	while (1)
	{
		sleep(4);
		printf("#############  Begin DHCP procedure number %d\n", count);
		result = set_up_connection(dhcp_socket);
		printf("\n%d\n", result);
		++count;
	}
	return 0;
}