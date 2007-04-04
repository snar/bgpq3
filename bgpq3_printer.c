#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdio.h>

#include "bgpq3.h"
#include "sx_report.h"

int
bgpq3_print_cisco_aspath(FILE* f, struct bgpq_expander* b)
{ 
	int nc=0, i, j;
	fprintf(f,"no ip as-path access-list %s\n", b->name?b->name:"NN");
	if(b->asnumbers[b->asnumber/8]&(0x80>>(b->asnumber%8))) { 
		fprintf(f,"ip as-path access-list %s permit ^%i(_%i)*$\n",
			b->name?b->name:"NN",b->asnumber,b->asnumber);
	};
	for(i=0;i<sizeof(b->asnumbers);i++) { 
		for(j=0;j<8;j++) { 
			if(b->asnumbers[i]&(0x80>>j)) { 
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
	if(b->asnumbers[b->asnumber/8]&(0x80>>(b->asnumber%8))) { 
		fprintf(f,"ip as-path access-list %s permit ^(_%i)*$\n",
			b->name?b->name:"NN",b->asnumber);
	};
	for(i=0;i<sizeof(b->asnumbers);i++) { 
		for(j=0;j<8;j++) { 
			if(b->asnumbers[i]&(0x80>>j)) { 
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
	int nc=0, lineNo=0, i, j;
	fprintf(f,"policy-options {\nreplace:\n as-path-group %s {\n", 
		b->name?b->name:"NN");

	if(b->asnumbers[b->asnumber/8]&(0x80>>(b->asnumber%8))) { 
		fprintf(f,"  as-path a%i \"^%i(%i)*$\";\n", lineNo, b->asnumber,
			b->asnumber);
		lineNo++;
	};
	for(i=0;i<sizeof(b->asnumbers);i++) { 
		for(j=0;j<8;j++) { 
			if(b->asnumbers[i]&(0x80>>j)) { 
				if(i*8+j==b->asnumber) continue;
				if(!nc) { 
					fprintf(f,"  as-path a%i \"^%i(.)*(%i",
						lineNo,b->asnumber,i*8+j);
				} else { 
					fprintf(f,"|%i",i*8+j);
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
	if(nc) fprintf(f,")$\";\n");
	fprintf(f," }\n}\n");
	return 0;
};

int
bgpq3_print_juniper_oaspath(FILE* f, struct bgpq_expander* b)
{ 
	int nc=0, lineNo=0, i, j;
	fprintf(f,"policy-options {\nreplace:\n as-path-group %s {\n", 
		b->name?b->name:"NN");

	if(b->asnumbers[b->asnumber/8]&(0x80>>(b->asnumber%8))) { 
		fprintf(f,"  as-path a%i \"^%i(%i)*$\";\n", lineNo, b->asnumber,
			b->asnumber);
		lineNo++;
	};
	for(i=0;i<sizeof(b->asnumbers);i++) { 
		for(j=0;j<8;j++) { 
			if(b->asnumbers[i]&(0x80>>j)) { 
				if(i*8+j==b->asnumber) continue;
				if(!nc) { 
					fprintf(f,"  as-path a%i \"^(.)*(%i",
						lineNo,i*8+j);
				} else { 
					fprintf(f,"|%i",i*8+j);
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

static char* bname=NULL;

void
bgpq3_print_cprefix(struct sx_radix_node* n, void* ff)
{ 
	char prefix[128];
	FILE* f=(FILE*)ff;
	if(n->isGlue) return;
	if(!f) f=stdout;
	sx_prefix_snprintf(&n->prefix,prefix,sizeof(prefix));
	fprintf(f,"ip prefix-list %s permit %s\n",bname?bname:"NN",prefix);
};

int
bgpq3_print_juniper_prefixlist(FILE* f, struct bgpq_expander* b)
{ 
	fprintf(f,"policy-options {\nreplace:\n prefix-list %s {\n",
		b->name?b->name:"NN");
	sx_radix_tree_foreach(b->tree,bgpq3_print_jprefix,f);
	fprintf(f,"  }\n}\n");
	return 0;
};

int
bgpq3_print_cisco_prefixlist(FILE* f, struct bgpq_expander* b)
{ 
	bname=b->name;
	fprintf(f,"no ip prefix-list %s\n", bname);
	sx_radix_tree_foreach(b->tree,bgpq3_print_cprefix,f);
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
