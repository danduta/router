#ifndef TABLE_H
#define TABLE_H

#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

#define TABLE_INITIAL_SIZE 256

#define ADD_SUCCESS 0
#define ADD_FAIL 1

#define READ_SUCCES 0
#define READ_FAIL 1

struct route_cell {
	uint32_t prefix;
	uint32_t next_hop;
	uint32_t mask;
	size_t interface;
};

struct arp_cell {
	uint32_t ip;
	char mac[6];
};

struct table {
  void* tbl;
	size_t size;
	size_t curr;
};

enum cell_types {
	route = sizeof(struct route_cell),
	arp = sizeof(struct arp_cell)
};

struct table* create_table(size_t cell_size);
int add_entry(struct table* table, void* cell, size_t cell_type);

int read_route_table(struct table* table, const char* in);
void sort_table(struct table* table, size_t cell_type);
int get_next_hop(struct table* table, uint32_t destination);
int find_entry(struct table* table, uint32_t destination, size_t cell_type);
void print_route_table(struct table* table);
void print_route_entry(struct table* table, size_t index);
uint16_t checksum(void *vdata, size_t length);

#endif
