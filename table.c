#include "table.h"

struct table* create_table(size_t cell_type) {
  struct table* table;

  table = (struct table*)malloc(sizeof(struct table));

  if (!table) {
    return NULL;
  }

  table->tbl = (struct route_cell*)malloc(TABLE_INITIAL_SIZE * cell_type);

  if (!table->tbl) {
    return NULL;
  }

  table->size = TABLE_INITIAL_SIZE;
  table->curr = 0;

  return table;
}

void parse_entry(uint32_t* addr, struct route_cell* entry) {
  entry->prefix = htonl(addr[0]);
  entry->next_hop = htonl(addr[1]);
  entry->mask = htonl(addr[2]);
  entry->interface = addr[3];
}

int read_route_table(struct table* table, const char* in) {
  fprintf(stdout, "Reading table...\n");

  struct route_cell* entry = (struct route_cell*)malloc(sizeof(struct route_cell));
  struct in_addr* addr = (struct in_addr*)malloc(sizeof(struct in_addr));
  uint32_t entry_fields[4];

  if (!addr || !entry || !table || !table->tbl) {
    return READ_FAIL;
  }

  FILE* fin = fopen(in, "r");
  char buffer[256];

  if (!fin) {
    return READ_FAIL;
  }

  while (fgets(buffer, 256, fin)
          && strcmp("", buffer)
          && strcmp("\n", buffer)) {

    char* tok = strtok(buffer, " ");
    int field = 0;
    printf("%d, %s\n", table->curr, buffer);
    while (tok) {
      if (field < 3) {
        inet_aton(tok, addr);
      } else {
        addr->s_addr = atoi(tok);
      }
      entry_fields[field] = addr->s_addr;
      tok = strtok(NULL, " ");
      field++;
    }

    parse_entry(entry_fields, entry);
    if (add_entry(table, entry, route) != ADD_SUCCESS) {
      free(entry);
      free(addr);
      return READ_FAIL;
    }
  }

  free(entry);
  free(addr);
  fprintf(stdout, "Successfully read the rtable!\n");
  return READ_SUCCES;
}

int add_entry(struct table* table, void* cell, size_t cell_type) {
  if (!table || !table->tbl) {
    return ADD_FAIL;
  }

  if (table->curr == table->size - 1) {
    int new_size = 2 * table->size * cell_type;
    table->tbl = realloc(table->tbl, new_size);

    if (!table->tbl) {
      return ADD_FAIL;
    }

    table->size *= 2;
  }

  if (cell_type == route) {
    ((struct route_cell*)table->tbl)[++(table->curr)] = *(struct route_cell*)cell;
  } else if (cell_type == arp) {
    ((struct arp_cell*)table->tbl)[++(table->curr)] = *(struct arp_cell*)cell;
  }

  if (cell_type == arp) {

  }

  return ADD_SUCCESS;
}

int compare_route_entries(const void* e1, const void* e2) {
  return (((struct route_cell*)e1)->prefix == ((struct route_cell*)e2)->prefix?
            ((struct route_cell*)e1)->mask - ((struct route_cell*)e2)->mask :
            (uint32_t)((struct route_cell*)e1)->prefix - (uint32_t)((struct route_cell*)e2)->prefix);
}

int compare_arp_entries(const void* e1, const void* e2) {
  return  ((uint32_t)((struct arp_cell*)e1)->ip -
          (uint32_t)((struct arp_cell*)e2)->ip);
}

void sort_table(struct table* table, size_t cell_type) {
  fprintf(stdout, "Sorting table...\n");
  if (!table || !table->tbl) {
    return;
  }

  if (cell_type == route) {
    qsort(table->tbl, table->curr, cell_type, compare_route_entries);
  } else if (cell_type == arp) {
    qsort(table->tbl, table->curr, cell_type, compare_arp_entries);
  }

  fprintf(stdout, "Table sorted!\n");
}

int get_next_hop(struct table* table, uint32_t destination) {
  int low = 0, hi = table->curr;

  while (low <= hi) {
    size_t mid = low + ((hi - low) / 2);

    uint32_t possible_prefix =
      destination & ((struct route_cell*)table->tbl)[mid].mask;
    uint32_t prefix = ((struct route_cell*)table->tbl)[mid].prefix;

    if (prefix == possible_prefix) {
      return mid;
    } else if (possible_prefix < prefix) {
      hi = mid - 1;
    } else {
      low = mid + 1;
    }
  }

  return -1;
}

int find_entry(struct table* table, uint32_t destination, size_t cell_type) {
  // int low = 0, hi = table->curr;
  //
  // while (low <= hi) {
  //   size_t mid = low + ((hi - low) / 2);
  //   uint32_t match;
  //
  //   if (cell_type == route) {
  //     match = ((struct route_cell*)table->tbl)[mid].prefix;
  //   } else if (cell_type == arp) {
  //     match = ((struct arp_cell*)table->tbl)[mid].ip;
  //   }
  //
  //   if (destination == match) {
  //     return mid;
  //   } else if (destination < match) {
  //     hi = mid - 1;
  //   } else {
  //     low = mid + 1;
  //   }
  // }
  for (size_t i = 0; i < table->curr; i++) {
    if (cell_type == route) {
      if (((struct route_cell*)table->tbl)[i].prefix == destination) {
        return i;
      }
    } else if (cell_type == arp) {
      if (((struct arp_cell*)table->tbl)[i].ip == destination) {
        return i;
      }
    }
  }

  return -1;
}

void print_route_table(struct table* table) {
  printf("Routing table:\n");
  for (size_t i = 0; i < table->curr; i++) {
    print_route_entry(table, i);
  }
}

void print_route_entry(struct table* table, size_t i) {
  struct in_addr addr;
  printf("table[%ld]\n", i);
  addr.s_addr = ((struct route_cell*)table->tbl)[i].prefix;
  printf("\tinteger prefix: %u\n", addr.s_addr);
  addr.s_addr = ntohl(addr.s_addr);
  printf("\tprefix: %s\n", inet_ntoa(addr));
  addr.s_addr = ((struct route_cell*)table->tbl)[i].next_hop;
  addr.s_addr = ntohl(addr.s_addr);
  printf("\tnext_hop: %s\n", inet_ntoa(addr));
  addr.s_addr = ((struct route_cell*)table->tbl)[i].mask;
  addr.s_addr = ntohl(addr.s_addr);
  printf("\tmask: %s\n", inet_ntoa(addr));
  printf("\tinterface: %ld\n", ((struct route_cell*)table->tbl)[i].interface);
}

uint16_t checksum(void *vdata, size_t length) {
	// Cast the data pointer to one that can be indexed.
	char* data=(char*)vdata;

	// Initialise the accumulator.
	uint64_t acc=0xffff;

	// Handle any partial block at the start of the data.
	unsigned int offset=((uintptr_t)data)&3;
	if (offset) {
		size_t count=4-offset;
		if (count>length) count=length;
		uint32_t word=0;
		memcpy(offset+(char*)&word,data,count);
		acc+=ntohl(word);
		data+=count;
		length-=count;
	}

	// Handle any complete 32-bit blocks.
	char* data_end=data+(length&~3);
	while (data!=data_end) {
		uint32_t word;
		memcpy(&word,data,4);
		acc+=ntohl(word);
		data+=4;
	}
	length&=3;

	// Handle any partial block at the end of the data.
	if (length) {
		uint32_t word=0;
		memcpy(&word,data,length);
		acc+=ntohl(word);
	}

	// Handle deferred carries.
	acc=(acc&0xffffffff)+(acc>>32);
	while (acc>>16) {
		acc=(acc&0xffff)+(acc>>16);
	}

	// If the data began at an odd byte address
	// then reverse the byte order to compensate.
	if (offset&1) {
		acc=((acc&0xff00)>>8)|((acc&0x00ff)<<8);
	}

	// Return the checksum in network byte order.
	return htons(~acc);
}
