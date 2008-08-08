#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "bgpq3.h"
#include "sx_report.h"

int
bgpq3_print_cisco_aspath(FILE* f, struct bgpq_expander* b)
{ 
	int nc=0, i, j;
	fprintf(f,"no ip as-path access-list %s\n", b->name?b->name:"NN");
	if(b->asn32s[0][b->asnumber/8]&(0x80>>(b->asnumber%8))) { 
		fprintf(f,"ip as-path access-list %s permit ^%i(_%i)*$\n",
			b->name?b->name:"NN",b->asnumber,b->asnumber);
	};
	for(i=0;i<8192;i++) { 
		for(j=0;j<8;j++) { 
			if(b->asn32s[0][i]&(0x80>>j)) { 
				if(i*8+j==b->asnumber) continue;
				if(!nc) { 
					fprintf(f,"ip as-path access-list %s permit"
						" ^%i(_[0-9]+)*_(%i", b->name?b->name:"NN", 
						b->asnumber,i*8+j);
				} else { 
					fprintf(f,"|%i",i*8+j);
				}
				nc++;
				if(nc==b->aswidth) { 
					fprintf(f,")$\n");
					nc=0;
				};
			};
		};
	};
	if(nc) fprintf(f,")$\n");
	return 0;
};
int
bgpq3_print_cisco_oaspath(FILE* f, struct bgpq_expander* b)
{ 
	int nc=0, i, j;
	fprintf(f,"no ip as-path access-list %s\n", b->name?b->name:"NN");
	if(b->asn32s[0][b->asnumber/8]&(0x80>>(b->asnumber%8))) { 
		fprintf(f,"ip as-path access-list %s permit ^(_%i)*$\n",
			b->name?b->name:"NN",b->asnumber);
	};
	for(i=0;i<8192;i++) { 
		for(j=0;j<8;j++) { 
			if(b->asn32s[0][i]&(0x80>>j)) { 
				if(i*8+j==b->asnumber) continue;
				if(!nc) { 
					fprintf(f,"ip as-path access-list %s permit"
						" ^(_[0-9]+)*_(%i", b->name?b->name:"NN", 
						i*8+j);
				} else { 
					fprintf(f,"|%i",i*8+j);
				}
				nc++;
				if(nc==b->aswidth) { 
					fprintf(f,")$\n");
					nc=0;
				};
			};
		};
	};
	if(nc) fprintf(f,")$\n");
	return 0;
};
		
int
bgpq3_print_juniper_aspath(FILE* f, struct bgpq_expander* b)
{ 
	int nc=0, lineNo=0, i, j, k;
	fprintf(f,"policy-options {\nreplace:\n as-path-group %s {\n", 
		b->name?b->name:"NN");

	if(b->asn32s[b->asnumber/65536] && 
		b->asn32s[b->asnumber/65535][(b->asnumber%65536)/8]&
		(0x80>>(b->asnumber%8))) { 
		fprintf(f,"  as-path a%i \"^%u(%u)*$\";\n", lineNo, b->asnumber,
			b->asnumber);
		lineNo++;
	};
	for(k=0;k<65536;k++) { 
		if(!b->asn32s[k]) continue;
		for(i=0;i<8192;i++) { 
			for(j=0;j<8;j++) { 
				if(b->asn32s[k][i]&(0x80>>j)) { 
					if(k*65536+i*8+j==b->asnumber) continue;
					if(!nc) { 
						fprintf(f,"  as-path a%i \"^%u(.)*(%u",
							lineNo,b->asnumber,k*65536+i*8+j);
					} else { 
						fprintf(f,"|%u",k*65536+i*8+j);
					};
					nc++;
					if(nc==b->aswidth) { 
						fprintf(f,")$\";\n");
						nc=0;
						lineNo++;
					};
				};
			};
		};
	};
	if(nc) fprintf(f,")$\";\n");
	fprintf(f," }\n}\n");
	return 0;
};

int
bgpq3_print_juniper_oaspath(FILE* f, struct bgpq_expander* b)
{ 
	int nc=0, lineNo=0, i, j, k;
	fprintf(f,"policy-options {\nreplace:\n as-path-group %s {\n", 
		b->name?b->name:"NN");

	if(b->asn32s[b->asnumber/65536] && 
		b->asn32s[b->asnumber/65536][(b->asnumber%65536)/8]&
		(0x80>>(b->asnumber%8))) { 
		fprintf(f,"  as-path a%i \"^%u(%u)*$\";\n", lineNo, b->asnumber,
			b->asnumber);
		lineNo++;
	};
	for(k=0;k<65536;k++) { 
		if(!b->asn32s[k]) continue;

		for(i=0;i<8192;i++) { 
			for(j=0;j<8;j++) { 
				if(b->asn32s[k][i]&(0x80>>j)) { 
					if(k*65536+i*8+j==b->asnumber) continue;
					if(!nc) { 
						fprintf(f,"  as-path a%i \"^(.)*(%u",
							lineNo,k*65536+i*8+j);
					} else { 
						fprintf(f,"|%u",k*65536+i*8+j);
					}
					nc++;
					if(nc==b->aswidth) { 
						fprintf(f,")$\";\n");
						nc=0;
						lineNo++;
					};
				};
			};
		};
	};
	if(nc) fprintf(f,")$\";\n");
	fprintf(f," }\n}\n");
	return 0;
};

int
bgpq3_print_aspath(FILE* f, struct bgpq_expander* b)
{ 
	if(b->vendor==V_JUNIPER) { 
		return bgpq3_print_juniper_aspath(f,b);
	} else if(b->vendor==V_CISCO) { 
		return bgpq3_print_cisco_aspath(f,b);
	} else { 
		sx_report(SX_FATAL,"Unknown vendor %i\n", b->vendor);
	};
	return 0;
};

int
bgpq3_print_oaspath(FILE* f, struct bgpq_expander* b)
{ 
	if(b->vendor==V_JUNIPER) { 
		return bgpq3_print_juniper_oaspath(f,b);
	} else if(b->vendor==V_CISCO) { 
		return bgpq3_print_cisco_oaspath(f,b);
	} else { 
		sx_report(SX_FATAL,"Unknown vendor %i\n", b->vendor);
	};
	return 0;
};

void
bgpq3_print_jprefix(struct sx_radix_node* n, void* ff)
{ 
	char prefix[128];
	FILE* f=(FILE*)ff;
	if(n->isGlue) return;
	if(!f) f=stdout;
	sx_prefix_snprintf(&n->prefix,prefix,sizeof(prefix));
	fprintf(f,"    %s;\n",prefix);
};

void
bgpq3_print_jrfilter(struct sx_radix_node* n, void* ff)
{ 
	char prefix[128];
	FILE* f=(FILE*)ff;
	if(n->isGlue) goto checkSon;
	if(!f) f=stdout;
	sx_prefix_snprintf(&n->prefix,prefix,sizeof(prefix));
	if(!n->isAggregate) { 
		fprintf(f,"    route-filter %s exact;\n", prefix);
	} else { 
		if(n->aggregateLow>n->prefix.masklen) { 
			fprintf(f,"    route-filter %s prefix-length-range /%u-/%u;\n", 
				prefix,n->aggregateLow,n->aggregateHi);
		} else { 
			fprintf(f,"    route-filter %s upto /%u;\n", prefix,n->aggregateHi);
		};
	};
checkSon:
	if(n->son)
		bgpq3_print_jrfilter(n->son, ff);
};
		

static char* bname=NULL;

void
bgpq3_print_cprefix(struct sx_radix_node* n, void* ff)
{ 
	char prefix[128];
	FILE* f=(FILE*)ff;
	if(!f) f=stdout;
	if(n->isGlue) goto checkSon;
	sx_prefix_snprintf(&n->prefix,prefix,sizeof(prefix));
	if(n->isAggregate) { 
		if(n->aggregateLow>n->prefix.masklen) { 
			fprintf(f,"%s prefix-list %s permit %s ge %u le %u\n",
				n->prefix.family==AF_INET?"ip":"ipv6",bname?bname:"NN",prefix,
				n->aggregateLow,n->aggregateHi);
		} else { 
			fprintf(f,"%s prefix-list %s permit %s le %u\n",
				n->prefix.family==AF_INET?"ip":"ipv6",bname?bname:"NN",prefix,
				n->aggregateHi);
		};
	} else { 
		fprintf(f,"%s prefix-list %s permit %s\n",
			(n->prefix.family==AF_INET)?"ip":"ipv6",bname?bname:"NN",prefix);
	};
checkSon:
	if(n->son) 
		bgpq3_print_cprefix(n->son,ff);
};

void
bgpq3_print_ceacl(struct sx_radix_node* n, void* ff)
{ 
	char prefix[128];
	FILE* f=(FILE*)ff;
	char* c;
	uint32_t netmask=0xfffffffful;
	if(!f) f=stdout;
	if(n->isGlue) goto checkSon;
	sx_prefix_snprintf(&n->prefix,prefix,sizeof(prefix));
	c=strchr(prefix,'/');
	if(c) *c=0;

	if(n->prefix.masklen==32) { 
		netmask=0;
	} else { 
	 	netmask<<=(32-n->prefix.masklen);
		netmask&=0xfffffffful;
	};
	netmask=htonl(netmask);

	if(n->isAggregate) { 
		unsigned long mask=0xfffffffful, wildaddr, wild2addr, wildmask;
		int masklen=n->aggregateLow;
		wildaddr=0xfffffffful>>n->prefix.masklen;
		if(n->aggregateHi==32) { 
			wild2addr=0;
		} else { 
			wild2addr=0xfffffffful>>n->aggregateHi;
		};
		wildaddr=wildaddr&(~wild2addr);

		if(masklen==32) mask=0xfffffffful;
		else mask=0xfffffffful & (0xfffffffful<<(32-masklen));

		if(n->aggregateHi==32) wild2addr=0;
		else wild2addr=0xfffffffful>>n->aggregateHi;
		wildmask=(0xfffffffful>>n->aggregateLow)&(~wild2addr);

		mask=htonl(mask);
		wildaddr=htonl(wildaddr);
		wildmask=htonl(wildmask);

		if(wildaddr) { 
			fprintf(f," permit ip %s ", inet_ntoa(n->prefix.addr.addr));
			fprintf(f,"%s ", inet_ntoa(*(struct in_addr*)&wildaddr));
		} else { 
			fprintf(f," permit ip host %s ",inet_ntoa(n->prefix.addr.addr));
		};

		if(wildmask) { 
			fprintf(f,"%s ", inet_ntoa(*(struct in_addr*)&mask));
			fprintf(f,"%s\n", inet_ntoa(*(struct in_addr*)&wildmask));
		} else { 
			fprintf(f,"host %s\n", inet_ntoa(*(struct in_addr*)&mask));
		};
	} else { 
		fprintf(f," permit ip host %s host %s\n",prefix,
			inet_ntoa(*(struct in_addr*)&netmask));
	};
checkSon:
	if(n->son) 
		bgpq3_print_ceacl(n->son,ff);
};

int
bgpq3_print_juniper_prefixlist(FILE* f, struct bgpq_expander* b)
{ 
	fprintf(f,"policy-options {\nreplace:\n prefix-list %s {\n",
		b->name?b->name:"NN");
	sx_radix_tree_foreach(b->tree,bgpq3_print_jprefix,f);
	fprintf(f," }\n}\n");
	return 0;
};

int
bgpq3_print_juniper_routefilter(FILE* f, struct bgpq_expander* b)
{ 
	char* c;
	if(b->name && (c=strchr(b->name,'/'))) { 
		*c=0;
		fprintf(f,"policy-options {\n policy-statement %s {\n  term %s {\n"
			"replace:\n   from {\n", b->name, c+1);
		if(b->match) 
			fprintf(f,"    %s;\n",b->match);
	} else { 
		fprintf(f,"policy-options {\n policy-statement %s { \n"
			"replace:\n  from {\n", b->name?b->name:"NN");
		if(b->match) 
			fprintf(f,"    %s;\n",b->match);
	};
	sx_radix_tree_foreach(b->tree,bgpq3_print_jrfilter,f);
	if(c) { 
		fprintf(f, "   }\n  }\n }\n}\n");
	} else { 
		fprintf(f, "  }\n }\n}\n");
	};
	return 0;
};

int
bgpq3_print_cisco_prefixlist(FILE* f, struct bgpq_expander* b)
{ 
	bname=b->name;
	fprintf(f,"no %s prefix-list %s\n",
		(b->family==AF_INET)?"ip":"ipv6",bname?bname:"NN");
	sx_radix_tree_foreach(b->tree,bgpq3_print_cprefix,f);
	return 0;
};

int
bgpq3_print_cisco_eacl(FILE* f, struct bgpq_expander* b)
{ 
	bname=b->name;
	fprintf(f,"no ip access-list extended %s\n", bname?bname:"NN");
	fprintf(f,"ip access-list extended %s\n", bname?bname:"NN");
	sx_radix_tree_foreach(b->tree,bgpq3_print_ceacl,f);
	return 0;
};

int
bgpq3_print_prefixlist(FILE* f, struct bgpq_expander* b)
{ 
	switch(b->vendor) { 
		case V_JUNIPER: return bgpq3_print_juniper_prefixlist(f,b);
		case V_CISCO: return bgpq3_print_cisco_prefixlist(f,b);
	};
	return 0;
};

int
bgpq3_print_eacl(FILE* f, struct bgpq_expander* b)
{ 
	switch(b->vendor) { 
		case V_JUNIPER: return bgpq3_print_juniper_routefilter(f,b);
		case V_CISCO: return bgpq3_print_cisco_eacl(f,b);
	};
	return 0;
};
