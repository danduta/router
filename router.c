#include "skel.h"

int main(int argc, char *argv[])
{
	packet m;
	int rc;
	struct in_addr addr;

	struct table* rtable = create_table(route);
	struct table* arp_table = create_table(arp);

	if (!rtable || !arp_table) {
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
			struct ether_arp* arp_hdr =
				(struct ether_arp*)(m.payload + sizeof(struct ether_header));

			uint8_t op = htons((arp_hdr->ea_hdr).ar_op);
			if (op == ARPOP_REQUEST) {
				/* ARP Request */
				printf("\tIt's an ARP Request!\n");
				// addr.s_addr = htonl(*((uint32_t*)arp_hdr->arp_tpa));

				/* Looking for router's MAC address */
				struct in_addr* router_iface_ip = malloc(sizeof(struct in_addr));

				printf("\trouter ip: %s\n", get_interface_ip(m.interface));
				addr.s_addr = *((uint32_t*)arp_hdr->arp_tpa);
				printf("\ttarget: %s\n", inet_ntoa(addr));


				// if (htonl(inet_aton(get_interface_ip(
				// 	m.interface), router_iface_ip)) == addr.s_addr)
				// 	{
				if (strcmp(get_interface_ip(m.interface), inet_ntoa(addr)) == 0) {

					printf("got here\n");
					uint32_t aux = *(uint32_t*)(arp_hdr->arp_tpa);
					*(uint32_t*)(arp_hdr->arp_tpa) = *(uint32_t*)(arp_hdr->arp_spa);
					*(uint32_t*)(arp_hdr->arp_spa) = aux;

					for (size_t i = 0; i < 6; i++) {
						arp_hdr->arp_tha[i] = arp_hdr->arp_sha[i];
						eth_hdr->ether_dhost[i] = arp_hdr->arp_sha[i];
					}

					get_interface_mac(m.interface, eth_hdr->ether_shost);
					get_interface_mac(m.interface, arp_hdr->arp_sha);

					arp_hdr->ea_hdr.ar_op = htons(ARPOP_REPLY);
				}

				free(router_iface_ip);
				send_packet(m.interface, &m);
			} else if (op == ARPOP_REPLY) {
				/* ARP Reply */
				printf("\tIt's an ARP reply!\n");
			}
		}
	}

	return 0;
}
