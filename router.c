#include "skel.h"

int main(int argc, char *argv[])
{
	packet m;
	int rc;
	struct in_addr addr;

	struct table* rtable = create_table(route);
	if (!rtable) {
		fprintf(stderr, "Cannot allocate memory for routing table.\n");
		return -1;
	}

	if (read_route_table(rtable, "rtable.txt") != READ_SUCCES) {
		fprintf(stderr, "Error while read the rtable!\n");
		return -2;
	}

	sort_route_table(rtable);
	init();

	fprintf(stdout, "Waiting for packets...\n");
	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");
		/* Students will write code here */
		fprintf(stdout, "Packet received!\n");
		struct ether_header* eth_hdr = (struct ether_header*)m.payload;

		uint32_t protocol = htons(eth_hdr->ether_type);
		fprintf(stdout, "\tProtocol type: %x, IP:%x, ARP:%x\n", protocol, ETHERTYPE_IP, ETHERTYPE_ARP);

		if (protocol == ETHERTYPE_IP) {
			printf("\tIt's an IP packet..\n");
			struct iphdr* ip_hdr =
				(struct iphdr*)(m.payload + sizeof(struct ether_header));

			addr.s_addr = ip_hdr->saddr;
			printf("\tcoming from: %s\n", inet_ntoa(addr));
		} else if (protocol == ETHERTYPE_ARP) {
			printf("\tIt's an ARP packet!\n");
		}
	}

	return 0;
}
