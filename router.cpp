#include "skel.h"
#include "table.h"
#include <queue>

using namespace std;

int main(int argc, char *argv[])
{
	packet m;
	int rc;
	struct in_addr addr;

	struct table* rtable = create_table(route);
	struct table* arp_table = create_table(arp);
	queue<packet> q;

	if (!rtable || !arp_table) {
		fprintf(stderr, "Cannot allocate memory for routing table.\n");
		return -1;
	}

	if (read_route_table(rtable, "rtable.txt") != READ_SUCCES) {
		fprintf(stderr, "Error while read the rtable!\n");
		return -2;
	}

	sort_table(rtable, route);
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
			struct in_addr* router_ip = (struct in_addr*)malloc(sizeof(struct in_addr));
			inet_aton(get_interface_ip(m.interface), router_ip);
			uint32_t router = router_ip->s_addr;

			uint8_t reply_type = 0xff;
			int index;

			if (	target == router &&
						ip_hdr->protocol == 1 &&
						icmp_hdr->type == ICMP_ECHO) {
				/* ICMP Echo request to the router*/
				reply_type = ICMP_ECHOREPLY;
				printf("\tIt's an ICMP Echo request to the router! %u\n", ICMP_ECHOREPLY);
			} else if (ip_hdr->ttl <= 1) {
				/* Compare TTL */
				reply_type = ICMP_TIME_EXCEEDED;
				printf("\tTTL exceeded! %u\n", ICMP_TIME_EXCEEDED);
			} else if ((index = get_next_hop(rtable, htonl(ip_hdr->daddr))) < 0) {
				/* Look for next hop */
				reply_type = ICMP_DEST_UNREACH;
				printf("\tNot found in rtable! %u\n", ICMP_DEST_UNREACH);
			} else {
				/* It's a valid packet */
				/* Try to forward packet */
				while (	index > 0 &&
								((struct route_cell*)rtable->tbl)[index].prefix ==
									((struct route_cell*)rtable->tbl)[index-1].prefix &&
								((struct route_cell*)rtable->tbl)[index].mask <
									((struct route_cell*)rtable->tbl)[index-1].mask)
				{
					/* Longest prefix match */
					printf("STILL LOOKING...\n");
					index--;
				}
				printf("\tFINAL ENTRY:\n");
				print_route_entry(stdout, rtable, index);
				/* Put router's physical address in the eth header */
				m.interface = ((struct route_cell*)rtable->tbl)[index].interface;
				get_interface_mac(m.interface, eth_hdr->ether_shost);
				/* Put the packet in the queue */
				q.push(m);

				int arp_index;
				uint32_t next_hop = ((struct route_cell*)rtable->tbl)[index].next_hop;

				if ((arp_index = find_entry(arp_table, next_hop, arp)) < 0) {
					/* Entry not foudn in ARP table */
					/* Enqueue packet to send when ARP Reply is received */
					struct ether_arp* arp_hdr =
						(struct ether_arp*)(m.payload + sizeof(struct ether_header));
					/* Update source MAC and set destination to broadcast */
					get_interface_mac(m.interface, eth_hdr->ether_shost);
					get_interface_mac(m.interface, arp_hdr->arp_sha);

					for (size_t i = 0; i < 6; i++) {
						eth_hdr->ether_dhost[i] = 0xff;
						arp_hdr->arp_tha[i] = 		0x00;
					}
					/* Update Ethernet protocol type */
					eth_hdr->ether_type = 			ntohs(ETHERTYPE_ARP);
					/* Create ARP header */
					(arp_hdr->ea_hdr).ar_hrd = 	ntohs(ARPHRD_ETHER);
					(arp_hdr->ea_hdr).ar_pro = 	ntohs(ETHERTYPE_IP);
					(arp_hdr->ea_hdr).ar_hln = 	6;
					(arp_hdr->ea_hdr).ar_pln = 	4;
					(arp_hdr->ea_hdr).ar_op = 	ntohs(ARPOP_REQUEST);

					*(uint32_t*)(arp_hdr->arp_spa) =	router;
					*(uint32_t*)(arp_hdr->arp_tpa) =	target;
					/* Update package length */
					m.len = sizeof(struct ether_header) + sizeof(struct ether_arp);
					/* Send packet */
					send_packet(m.interface, &m);
					continue;
				}
				/* Update destination MAC */
				for (size_t i = 0; i < 6; i++) {
					eth_hdr->ether_dhost[i] = ((struct arp_cell*)arp_table->tbl)[arp_index].mac[i];
				}
			}

			if (reply_type == ICMP_ECHOREPLY) {
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

				icmp_hdr->checksum = 0;
				icmp_hdr->checksum =
					checksum(icmp_hdr, m.len - sizeof(struct ether_header) - sizeof(struct iphdr));
			} else if (reply_type != 0xff) {
				/* Sending back ICMP message */
				printf("\tSending back ICMP message with type: %u\n", reply_type);
				/* Update ICMP type to ECHOREPLY */
				icmp_hdr->type = reply_type;
				icmp_hdr->code = 0;
				/* Change protocol to ICMP */
				ip_hdr->protocol = 1;
				/* Switch destination and source IP in IP header */
				uint32_t aux = ip_hdr->saddr;
				ip_hdr->saddr = ip_hdr->daddr;
				ip_hdr->daddr = aux;
				/* Update source and destination MAC in the Ethernet header */
				for (size_t i = 0; i < 6; i++) {
					eth_hdr->ether_dhost[i] = eth_hdr->ether_shost[i];
				}
				get_interface_mac(m.interface, eth_hdr->ether_shost);
				/* Update IP and packet length */
				ip_hdr->tot_len = htons(2 * sizeof(struct iphdr) +
																sizeof(struct icmphdr) + 8);

				m.len = sizeof(struct ether_header) +
								2 * sizeof(struct iphdr) +
								sizeof(struct icmphdr) + 8;
				/* Update checksums */
				ip_hdr->check = 0;
				ip_hdr->check = checksum(ip_hdr, sizeof(struct iphdr));
				icmp_hdr->checksum = 0;
				icmp_hdr->checksum = checksum(icmp_hdr, sizeof(struct icmphdr) + sizeof(struct iphdr) + 8);
				/* Send packet */
			}

			send_packet(m.interface, &m);
		/* ARP */
		} else if (protocol == ETHERTYPE_ARP) {
			struct ether_arp* arp_hdr =
				(struct ether_arp*)(m.payload + sizeof(struct ether_header));

			uint8_t op = htons((arp_hdr->ea_hdr).ar_op);

			fprintf (stdout, "\tIt's an ARP %d coming on interface %d ip %s!\n", op,
							m.interface, get_interface_ip(m.interface));
			addr.s_addr = *(uint32_t*)(arp_hdr->arp_tpa);
			printf("\ttarget ip: %s\n", inet_ntoa(addr));

			if (op == ARPOP_REQUEST) {
				/* ARP Request */
				uint32_t target = *(uint32_t*)(arp_hdr->arp_tpa);
				struct in_addr* router_ip = (struct in_addr*)malloc(sizeof(struct in_addr));
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
				uint32_t source = htonl(*(uint32_t*)arp_hdr->arp_spa);
				int index;

				if ((index = find_entry(arp_table, source, arp)) < 0) {
					struct arp_cell new_entry;
					/* Copy IP and mac of sender in the ARP table */
					new_entry.ip = source;
					for (size_t i = 0; i < 6; i++) {
						new_entry.mac[i] = arp_hdr->arp_sha[i];
					}

					add_entry(arp_table, &new_entry, arp);
					
					packet front = q.front();
					struct iphdr* ip_hdr =
						(struct iphdr*)(front.payload + sizeof(struct ether_header));
					uint32_t front_target = htonl(ip_hdr->daddr);
					uint32_t target = source;
					while(front_target == target) {
						q.pop();

						m.interface = front.interface;
						m.len = front.len;
						memcpy(m.payload, front.payload, m.len);

						for (size_t i = 0; i < 6; i++) {
							eth_hdr->ether_dhost[i] = new_entry.mac[i];
						}

						send_packet(m.interface, &m);

						front = q.front();
						ip_hdr = (struct iphdr*)(front.payload + sizeof(struct ether_header));
						front_target = htonl(ip_hdr->daddr);
					}
				}
			}
		}
	}

	return 0;
}
