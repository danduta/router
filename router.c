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

	for (int i = 0; i < 4; i++) {
		printf("Router interface: %d ip %s\n", i, get_interface_ip(i));
	}

	fprintf(stdout, "Waiting for packets...\n");
	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");
		fprintf(stdout, "Packet received!\n");

		struct ether_header* eth_hdr = (struct ether_header*)m.payload;
		/* Check protocol type */
		uint32_t protocol = htons(eth_hdr->ether_type);
		/* IP */
		if (protocol == ETHERTYPE_IP) {
			struct iphdr* ip_hdr =
				(struct iphdr*)(m.payload + sizeof(struct ether_header));
			struct icmphdr* icmp_hdr = (struct icmphdr*)(m.payload 	+
				sizeof(struct ether_header) + sizeof(struct iphdr));

			fprintf (stdout, "\tIt's an IP packet coming on interface %d ip %s!\n",
							m.interface, get_interface_ip(m.interface));
			addr.s_addr = ip_hdr->daddr;
			printf("\ttarget ip: %s\n", inet_ntoa(addr));

			uint32_t target = ip_hdr->daddr;
			struct in_addr* router_ip = malloc(sizeof(struct in_addr));
			inet_aton(get_interface_ip(m.interface), router_ip);
			uint32_t router = router_ip->s_addr;

			if (	target == router &&
						ip_hdr->protocol == 1 &&
						icmp_hdr->type == ICMP_ECHO) {
				/* ICMP Echo request */
				printf("\tIt's an ICMP Echo request to the router!\n");
				/* Update ICMP type to ECHOREPLY */
				icmp_hdr->type = htons(ICMP_ECHOREPLY);
				/* Switch destination and source IP in IP header */
				uint32_t aux = ip_hdr->saddr;
				ip_hdr->saddr = ip_hdr->daddr;
				ip_hdr->daddr = aux;
				/* Update source and destination MAC in the Ethernet header */
				for (size_t i = 0; i < 6; i++) {
					eth_hdr->ether_dhost[i] = eth_hdr->ether_shost[i];
				}
				get_interface_mac(m.interface, eth_hdr->ether_shost);

				send_packet(m.interface, &m);
			} else {
				/* Look for destination address in the rtable */
				int i;
				if ((i = get_next_hop(rtable, htonl(ip_hdr->daddr))) < 0) {
					/* Destination not present in the rtable */
					fprintf(stderr, "Prefix not found!\n");
					continue;
				}
				printf("lalala\n");

				printf("table[%d]\n", i);
		    addr.s_addr = ((struct cell*)rtable->tbl)[i].prefix;
		    printf("\tinteger prefix: %u\n", addr.s_addr);
		    addr.s_addr = ntohl(addr.s_addr);
		    printf("\tprefix: %s\n", inet_ntoa(addr));
		    addr.s_addr = ((struct cell*)rtable->tbl)[i].next_hop;
		    addr.s_addr = ntohl(addr.s_addr);
		    printf("\tnext_hop: %s\n", inet_ntoa(addr));
		    addr.s_addr = ((struct cell*)rtable->tbl)[i].mask;
		    addr.s_addr = ntohl(addr.s_addr);
		    printf("\tmask: %s\n", inet_ntoa(addr));
		    printf("\tinterface: %ld\n", ((struct cell*)rtable->tbl)[i].interface);
			}
		/* ARP */
		} else if (protocol == ETHERTYPE_ARP) {
			struct ether_arp* arp_hdr =
				(struct ether_arp*)(m.payload + sizeof(struct ether_header));

			uint8_t op = htons((arp_hdr->ea_hdr).ar_op);
			if (op == ARPOP_REQUEST) {
				/* ARP Request */
			 	fprintf (stdout, "\tIt's an ARP Request coming on interface %d ip %s!\n",
								m.interface, get_interface_ip(m.interface));
				addr.s_addr = *(uint32_t*)(arp_hdr->arp_tpa);
				printf("\ttarget ip: %s\n", inet_ntoa(saddr));

				uint32_t target = *(uint32_t*)(arp_hdr->arp_tpa);
				struct in_addr* router_ip = malloc(sizeof(struct in_addr));
				inet_aton(get_interface_ip(m.interface), router_ip);
				uint32_t router = router_ip->s_addr;

				if (target == router) {
					fprintf(stdout, "\tARP Request is targetting router\n");
					/* Switch target and source IP */
					uint32_t aux = *(uint32_t*)(arp_hdr->arp_tpa);
					*(uint32_t*)(arp_hdr->arp_tpa) = *(uint32_t*)(arp_hdr->arp_spa);
					*(uint32_t*)(arp_hdr->arp_spa) = aux;
					/* Copy source MAC in the target MAC */
					for (size_t i = 0; i < 6; i++) {
						arp_hdr->arp_tha[i] = arp_hdr->arp_sha[i];
						eth_hdr->ether_dhost[i] = arp_hdr->arp_sha[i];
					}
					/* Update source MAC to be the router's */
					get_interface_mac(m.interface, eth_hdr->ether_shost);
					get_interface_mac(m.interface, arp_hdr->arp_sha);
					/* Update request type */
					arp_hdr->ea_hdr.ar_op = htons(ARPOP_REPLY);
					/* Send back ARP Reply*/
					send_packet(m.interface, &m);
				}
			} else if (op == ARPOP_REPLY) {
				/* ARP Reply */
				printf("\tIt's an ARP reply!\n");
			}
		}
	}

	return 0;
}
