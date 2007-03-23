#ifndef BGPQ3_H_
#define BGPQ3_H_

#include "sx_prefix.h"
#include "sx_slentry.h"

typedef enum { 
	V_CISCO = 0,
	V_JUNIPER
} bgpq_vendor_t;

typedef enum { 
	T_NONE = 0,
	T_ASPATH,
	T_OASPATH,
	T_PREFIXLIST
} bgpq_gen_t;

struct bgpq_expander { 
	struct sx_radix_tree* tree;
	unsigned char asnumbers[8192];
	struct sx_slentry* macroses;
	int family;
	char* sources;
	int asnumber, aswidth;
	char* name;
	bgpq_vendor_t vendor;
	bgpq_gen_t    generation;
};

int bgpq_expander_init(struct bgpq_expander* b, int af);
int bgpq_expander_add_asset(struct bgpq_expander* b, char* set);
int bgpq_expander_add_as(struct bgpq_expander* b, char* as);
int bgpq_expander_add_prefix(struct bgpq_expander* b, char* prefix);

int bgpq_expand(struct bgpq_expander* b);

int bgpq3_print_prefixlist(FILE* f, struct bgpq_expander* b);
int bgpq3_print_aspath(FILE* f, struct bgpq_expander* b);


#endif
	
