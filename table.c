#include "table.h"

struct table* create_table(size_t cell_type)
{
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

void parse_entry(uint32_t* addr, struct route_cell* entry)
{
  entry->prefix = htonl(addr[0]);
  entry->next_hop = htonl(addr[1]);
  entry->mask = htonl(addr[2]);
  entry->interface = addr[3];
}

int read_route_table(struct table* table, const char* in)
{
  fprintf(stdout, "Reading table...\n");

  struct route_cell* entry;
  entry = (struct route_cell*)malloc(sizeof(struct route_cell));
  struct in_addr* addr;
  addr = (struct in_addr*)malloc(sizeof(struct in_addr));

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

int add_entry(struct table* table, void* cell, size_t cell_type)
{
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
    struct route_cell entry = *(struct route_cell*)cell;
    ((struct route_cell*)table->tbl)[(table->curr)++] = entry;
  } else if (cell_type == arp) {
    struct arp_cell entry = *(struct arp_cell*)cell;
    ((struct arp_cell*)table->tbl)[(table->curr)++] = entry;
  }

  return ADD_SUCCESS;
}

int compare_route_entries(const void* e1, const void* e2)
{
  return (((struct route_cell*)e1)->prefix == ((struct route_cell*)e2)->prefix?
          ((struct route_cell*)e2)->mask - ((struct route_cell*)e1)->mask :
          ((struct route_cell*)e1)->prefix - ((struct route_cell*)e2)->prefix);
}

int compare_arp_entries(const void* e1, const void* e2)
{
  return (((struct arp_cell*)e1)->ip - ((struct arp_cell*)e2)->ip);
}

void sort_table(struct table* table, size_t cell_type)
{
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

int get_next_hop(struct table* table, uint32_t destination)
{
  int low = 0, hi = table->curr;

  while (low <= hi) {
    size_t mid = low + ((hi - low) / 2);

    uint32_t possible_prefix =
      destination & ((struct route_cell*)table->tbl)[mid].mask;
    uint32_t prefix = ((struct route_cell*)table->tbl)[mid].prefix;

    if (prefix == possible_prefix) {
      /* Longest prefix match */
      while (	mid > 0 &&
            ((struct route_cell*)table->tbl)[mid].prefix ==
              ((struct route_cell*)table->tbl)[mid-1].prefix &&
            ((struct route_cell*)table->tbl)[mid].mask <
              ((struct route_cell*)table->tbl)[mid-1].mask)
      {
        mid--;
      }
      return mid;
    } else if (possible_prefix < prefix) {
      hi = mid - 1;
    } else {
      low = mid + 1;
    }
  }

  return -1;
}

size_t find_entry(struct table* table, uint32_t destination, size_t cell_type)
{
  for (size_t i = 0; i < table->curr; i++) {
    uint32_t possible_prefix =
      destination & ((struct route_cell*)table->tbl)[i].mask;
    uint32_t prefix = ((struct route_cell*)table->tbl)[i].prefix;

    if (cell_type == route) {
      if (prefix == possible_prefix) {
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

void print_route_table(struct table* table)
{
  FILE* out = fopen("rtable_out.txt", "w");

  fprintf(out, "Routing table:\n");
  for (size_t i = 0; i < table->curr; i++) {
    print_route_entry(out, table, i);
  }

  fclose(out);
}

void print_route_entry(FILE* out, struct table* table, size_t i)
{
  struct in_addr addr;
  fprintf(out, "\t\ttable[%ld]\n", i);
  addr.s_addr = ((struct route_cell*)table->tbl)[i].prefix;
  addr.s_addr = ntohl(addr.s_addr);
  fprintf(out, "\tPrefix: %s, ", inet_ntoa(addr));
  addr.s_addr = ((struct route_cell*)table->tbl)[i].next_hop;
  addr.s_addr = ntohl(addr.s_addr);
  fprintf(out, "Next_hop: %s, ", inet_ntoa(addr));
  addr.s_addr = ((struct route_cell*)table->tbl)[i].mask;
  addr.s_addr = ntohl(addr.s_addr);
  fprintf(out, "Mask: %s, ", inet_ntoa(addr));
  fprintf(out, "Interface: %ld\n", ((struct route_cell*)table->tbl)[i].interface);
}

uint16_t checksum(void *vdata, size_t length)
{
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

uint32_t get_entry_prefix(struct table* table, size_t index)
{
  return ((struct route_cell*)table->tbl)[index].prefix;
}
uint32_t get_entry_next_hop(struct table* table, size_t index)
{
  return ((struct route_cell*)table->tbl)[index].next_hop;
}
uint32_t get_entry_mask(struct table* table, size_t index)
{
  return ((struct route_cell*)table->tbl)[index].mask;
}

size_t get_entry_interface(struct table* table, size_t index)
{
  return ((struct route_cell*)table->tbl)[index].interface;
}

uint8_t* get_mac(struct table* table, size_t index)
{
  return ((struct arp_cell*)table->tbl)[index].mac;
}

void copy_mac(uint8_t destination[], uint8_t source[])
{
	for (size_t i = 0; i < 6; i++) {
		destination[i] = source[i];
	}
}