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
	T_PREFIXLIST,	
	T_EACL
} bgpq_gen_t;

struct bgpq_prequest { 
	struct bgpq_prequest* next;
	char request[128];
	int (*callback)(char*, void*);
	void *udata;
};

struct bgpq_expander { 
	struct sx_radix_tree* tree;
	struct sx_slentry* macroses;
	struct sx_slentry* rsets;
	int family;
	char* sources;
	int asnumber, aswidth;
	char* name;
	bgpq_vendor_t vendor;
	bgpq_gen_t    generation;
	int identify;
	unsigned char asn32;
	unsigned char* asn32s[65536];
	struct bgpq_prequest* firstpipe, *lastpipe;
	int piped;
};


int bgpq_expander_init(struct bgpq_expander* b, int af);
int bgpq_expander_add_asset(struct bgpq_expander* b, char* set);
int bgpq_expander_add_rset(struct bgpq_expander* b, char* set);
int bgpq_expander_add_as(struct bgpq_expander* b, char* as);
int bgpq_expander_add_prefix(struct bgpq_expander* b, char* prefix);

int bgpq_expand(struct bgpq_expander* b);

int bgpq3_print_prefixlist(FILE* f, struct bgpq_expander* b);
int bgpq3_print_eacl(FILE* f, struct bgpq_expander* b);
int bgpq3_print_aspath(FILE* f, struct bgpq_expander* b);
int bgpq3_print_oaspath(FILE* f, struct bgpq_expander* b);

#ifndef HAVE_STRLCPY
size_t strlcpy(char* dst, const char* src, size_t size);
#endif

#endif
	
