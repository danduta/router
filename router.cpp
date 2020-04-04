#include "skel.h"
#include "table.h"
#include <queue>

using namespace std;

#define IP_WRNG_CHECK 	0xef
#define IP_VALID_PKT 	0xff

#define ETHD_S 			sizeof(struct ether_header)
#define IPHD_S 			sizeof(struct iphdr)
#define ICMPHD_S 		sizeof(struct icmphdr)
#define ARPHD_S 		sizeof(struct ether_arp)

/*
 * struct used for the return value of check_packet().
 * It contains the index of the next_hop or the ICMP
 * error type that should be sent back to the host.
 */
typedef struct validity_pair {
	int index;
	uint8_t reply_type;
} vld;

vld check_pkt(	packet m,
				struct table* rtable,
				uint32_t target,
				uint32_t router)
{
	struct iphdr* ip_hdr = (struct iphdr*)(m.payload + ETHD_S);
	struct icmphdr* icmp_hdr = (struct icmphdr*)(m.payload 	+ ETHD_S + IPHD_S);

	vld pkt_validity;
	pkt_validity.index = get_next_hop(rtable, htonl(ip_hdr->daddr));
	pkt_validity.reply_type = IP_VALID_PKT;

	uint16_t ip_checksum;
	uint16_t old_ip_checksum = ip_hdr->check;
	ip_hdr->check = 0;
	ip_checksum = checksum(ip_hdr, IPHD_S);

	if (target == router &&
		ip_hdr->protocol == 1 &&
		icmp_hdr->type == ICMP_ECHO) {
		/* ICMP Echo request to the router*/
		pkt_validity.reply_type = ICMP_ECHOREPLY;
		fprintf(stdout, "\tIt's an ICMP Echo request to the router!\n");
	} else if (ip_hdr->ttl <= 1) {
		/* Compare TTL */
		pkt_validity.reply_type = ICMP_TIME_EXCEEDED;
		fprintf(stdout, "\tTTL exceeded!n");
	} else if (pkt_validity.index < 0) {
		/* Host unreachable */
		pkt_validity.reply_type = ICMP_DEST_UNREACH;
		fprintf(stdout, "\tNot found in rtable!\n");
	} else if (ip_checksum != old_ip_checksum) {
		pkt_validity.reply_type = IP_WRNG_CHECK;
	}

	return pkt_validity;
}

void update_packet(packet& m)
{
	struct iphdr* ip_hdr = (struct iphdr*)(m.payload + ETHD_S);
	(ip_hdr->ttl)--;
	ip_hdr->check = 0;
	ip_hdr->check = checksum(ip_hdr, IPHD_S);
}


void create_icmp_packet(packet &m, char* payload, uint8_t icmp_type)
{	
	/* Returns the length of the new packet */
	struct ether_header* eth_hdr = (struct ether_header*)payload;
	struct iphdr* ip_hdr = (struct iphdr*)(payload + ETHD_S);
	struct icmphdr* icmp_hdr = (struct icmphdr*)(payload + ETHD_S + IPHD_S);
	/* Sending back ICMP message */
	printf("\tSending back ICMP message with type: %u\n", icmp_type);
	/* Update ICMP type to ECHOREPLY */
	icmp_hdr->type = 	icmp_type;
	icmp_hdr->code = 	0;
	/* Change protocol to ICMP */
	ip_hdr->protocol = 	IPPROTO_ICMP;
	/* Switch destination and source IP in IP header */
	uint32_t aux = 		ip_hdr->saddr;
	ip_hdr->saddr = 	ip_hdr->daddr;
	ip_hdr->daddr = 	aux;
	/* Update source and destination MAC in the Ethernet header */
	copy_mac(eth_hdr->ether_dhost, eth_hdr->ether_shost);
	get_interface_mac(m.interface, eth_hdr->ether_shost);
	/* Update IP and packet length */
	if (icmp_type != ICMP_ECHOREPLY) {
		ip_hdr->tot_len = 	htons(2 * IPHD_S + ICMPHD_S + 8);
		m.len = 			ETHD_S + 2 * IPHD_S + ICMPHD_S + 8;
	}
	/* Update checksums */
	ip_hdr->check = 	0;
	ip_hdr->check = 	checksum(ip_hdr, IPHD_S);
	icmp_hdr->checksum = 	0;
	icmp_hdr->checksum = 	checksum(icmp_hdr, ICMPHD_S + IPHD_S + 8);
}

void create_arp_packet(	packet &m,
						char* payload,
						uint8_t arpop,
						uint32_t target,
						uint32_t router)
{
	struct ether_header* eth_hdr = (struct ether_header*)payload;
	struct ether_arp* arp_hdr = (struct ether_arp*)(payload + ETHD_S);

	if (arpop == ARPOP_REQUEST) {
		/* Update source MAC and set destination to broadcast */
		get_interface_mac(m.interface, eth_hdr->ether_shost);
		get_interface_mac(m.interface, arp_hdr->arp_sha);
		for (size_t i = 0; i < 6; i++) {
			eth_hdr->ether_dhost[i] = 	0xff;
			arp_hdr->arp_tha[i] = 		0x00;
		}
		/* Update Ethernet protocol type */
		eth_hdr->ether_type = 			ntohs(ETHERTYPE_ARP);
		/* Create ARP header */
		(arp_hdr->ea_hdr).ar_hrd = 		ntohs(ARPHRD_ETHER);
		(arp_hdr->ea_hdr).ar_pro = 		ntohs(ETHERTYPE_IP);
		(arp_hdr->ea_hdr).ar_hln = 		6;
		(arp_hdr->ea_hdr).ar_pln = 		4;
		(arp_hdr->ea_hdr).ar_op = 		ntohs(ARPOP_REQUEST);

		*(uint32_t*)(arp_hdr->arp_spa) =	router;
		*(uint32_t*)(arp_hdr->arp_tpa) =	target;
		/* Update package length */
		m.len = ETHD_S + ARPHD_S;
	} else if (arpop == ARPOP_REPLY) {
		uint32_t aux = 						*(uint32_t*)(arp_hdr->arp_tpa);
		*(uint32_t*)(arp_hdr->arp_tpa) = 	*(uint32_t*)(arp_hdr->arp_spa);
		*(uint32_t*)(arp_hdr->arp_spa) = 	aux;
		/* Copy source MAC in the target MAC */
		copy_mac(arp_hdr->arp_tha, arp_hdr->arp_sha);
		copy_mac(eth_hdr->ether_dhost, arp_hdr->arp_sha);
		/* Update source MAC to be the router's */
		get_interface_mac(m.interface, eth_hdr->ether_shost);
		get_interface_mac(m.interface, arp_hdr->arp_sha);
		/* Update request type */
		arp_hdr->ea_hdr.ar_op = 			htons(ARPOP_REPLY);
	}
}

int main(int argc, char *argv[])
{
	packet m;
	int rc;

	struct table* rtable = create_table(route);
	struct table* arp_table = create_table(arp);
	queue<packet> q;

	uint8_t router_physical[6];
	uint8_t broadcast[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

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
		fprintf(stdout, "Router interface: %d ip %s\n", i, get_interface_ip(i));
	}

	fprintf(stdout, "Waiting for packets...\n");
	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");
		fprintf(stdout, "Packet received!\n");

		struct ether_header* eth_hdr = (struct ether_header*)m.payload;

		get_interface_mac(m.interface, router_physical);
		/* Check if packet was meant for router */
		if (memcmp(eth_hdr->ether_dhost, router_physical, 6) &&
			memcmp(eth_hdr->ether_dhost, broadcast, 6) &&
			memcmp(eth_hdr->ether_shost, router_physical, 6) == 0) {
			fprintf(stdout, "Packet not for router!\n");
			continue;
		}
		
		/* Check protocol type */
		uint32_t protocol = htons(eth_hdr->ether_type);
		if (protocol == ETHERTYPE_IP) {
			struct iphdr* ip_hdr = (struct iphdr*)(m.payload + ETHD_S);

			uint32_t target = ip_hdr->daddr;

			struct in_addr* router_ip;
			router_ip = (struct in_addr*)malloc(sizeof(struct in_addr));
			inet_aton(get_interface_ip(m.interface), router_ip);
			uint32_t router = router_ip->s_addr;

			vld pkt_validity = check_pkt(m, rtable, target, router);

			if (pkt_validity.reply_type == IP_WRNG_CHECK) {
				/* Drop packets with wrong checksums */
				continue;
			} else if (pkt_validity.reply_type == IP_VALID_PKT) {
				/* 
				 * It's a valid packet.
				 * Try to forward the packet.
				 */
				printf("\tNext hop:\n");
				print_route_entry(stdout, rtable, pkt_validity.index);
				/* Put router's physical address in the eth header */
				get_interface_mac(m.interface, eth_hdr->ether_shost);
				/* Update packet interface to know where to send it later */
				m.interface = get_entry_interface(rtable, pkt_validity.index);
				/* Put the packet in the queue */
				q.push(m);

				int arp_index;
				uint32_t next_hop = get_entry_next_hop(rtable, pkt_validity.index);

				if ((arp_index = find_entry(arp_table, next_hop, arp)) < 0) {
					/* Send packet */
					create_arp_packet(	m, m.payload,
										ARPOP_REQUEST,
										target, router);
					send_packet(m.interface, &m);
					continue;
				}
				/* Update destination MAC */
				copy_mac(eth_hdr->ether_dhost, get_mac(arp_table, arp_index));
				update_packet(m);
			} else {
				create_icmp_packet(m, m.payload, pkt_validity.reply_type);
			}
			send_packet(m.interface, &m);
		} else if (protocol == ETHERTYPE_ARP) {
			struct ether_arp* arp_hdr =
				(struct ether_arp*)(m.payload + ETHD_S);

			uint32_t target = *(uint32_t*)(arp_hdr->arp_tpa);
			struct in_addr* router_ip;
			router_ip = (struct in_addr*)malloc(sizeof(struct in_addr));
			inet_aton(get_interface_ip(m.interface), router_ip);
			uint32_t router = router_ip->s_addr;

			uint8_t op = htons((arp_hdr->ea_hdr).ar_op);

			if (op == ARPOP_REQUEST && target == router) {
				create_arp_packet(m, m.payload, ARPOP_REPLY, target, router);
				send_packet(m.interface, &m);
			} else if (op == ARPOP_REPLY) {
				uint32_t source = htonl(*(uint32_t*)arp_hdr->arp_spa);
				int index;

				if ((index = find_entry(arp_table, source, arp)) < 0) {
					struct arp_cell new_entry;
					/* Copy IP and mac of sender in the ARP table */
					new_entry.ip = source;
					copy_mac(new_entry.mac, arp_hdr->arp_sha);

					add_entry(arp_table, &new_entry, arp);
					
					packet front = q.front();
					struct iphdr* ip_hdr =
						(struct iphdr*)(front.payload + ETHD_S);
					uint32_t front_target = htonl(ip_hdr->daddr);
					uint32_t target = source;

					while (front_target == target) {
						q.pop();

						m.interface = front.interface;
						m.len = front.len;
						memcpy(m.payload, front.payload, m.len);
						copy_mac(eth_hdr->ether_dhost, new_entry.mac);

						send_packet(m.interface, &m);

						front = q.front();
						ip_hdr = (struct iphdr*)(front.payload + ETHD_S);
						front_target = htonl(ip_hdr->daddr);
					}
				}
			}
		}
	}

	free(rtable->tbl);
	free(arp_table->tbl);
	free(rtable);
	free(arp_table);

	return 0;
}
