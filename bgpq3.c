#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "bgpq3.h"
#include "sx_report.h"

extern int debug_expander;
extern int debug_aggregation;
extern int pipelining;

int
usage(int ecode)
{ 
	printf("\nUsage: bgpq3 [-h] [-S sources] [-P|E|G <num>|f <num>] [-36A]"
		" [-R len] <OBJECTS>...\n");
	printf(" -3        : assume that your device is asn32-safe\n"); 
	printf(" -6        : generate IPv6 prefix-lists (IPv4 by default)\n");
	printf(" -A        : try to aggregate prefix-lists as much as possible"
		" (Cisco only)\n");
	printf(" -d        : generate some debugging output\n");
	printf(" -E        : generate extended access-list(Cisco) or "
		"route-filter(Juniper)\n");
	printf(" -f number : generate input as-path access-list\n");
	printf(" -G number : generate output as-path access-list\n");
	printf(" -h        : this help\n");
	printf(" -J        : generate config for JunOS (Cisco IOS by default)\n");
	printf(" -l        : use specified name for generated access/prefix/.."
		" list\n");
	printf(" -P        : generate prefix-list (default)\n");
	printf(" -R len    : allow specific routes up to masklen specified\n");
	printf(" -S sources: use only specified sources (default:"
		" RADB,RIPE,APNIC)\n");
	printf(" -T        : disable pipelining (experimental, faster mode)\n");
	printf("\n" PACKAGE_NAME " version: " PACKAGE_VERSION "\n");
	printf("Copyright(c) Alexandre Snarskii <snar@paranoia.ru> 2007, 2008\n\n");
	exit(ecode);
};

void
exclusive()
{ 
	fprintf(stderr,"-E, -f <asnum>, -G <asnum> and -P are mutually "
		"exclusive\n");
	exit(1);
};

int
parseasnumber(struct bgpq_expander* expander, char* optarg)
{ 
	char* eon=NULL;
	expander->asnumber=strtoul(optarg,&eon,10);
	if(expander->asnumber<0 || expander->asnumber>(65535ul*65535)) { 
		sx_report(SX_FATAL,"Invalid AS number: %s\n", optarg);
		exit(1);
	};
	if(eon && *eon=='.') { 
		/* -f 3.3, for example */
		uint32_t loas=strtoul(eon+1,&eon,10);
		if(expander->asnumber>65535) { 
			/* should prevent incorrect numbers like 65537.1 */
			sx_report(SX_FATAL,"Invalid AS number: %s\n", optarg);
			exit(1);
		};
		if(loas<0 || loas>65536) { 
			sx_report(SX_FATAL,"Invalid AS number: %s\n", optarg);
			exit(1);
		};
		if(eon && *eon) { 
			sx_report(SX_FATAL,"Invalid symbol in AS number: %c (%s)\n",
				*eon, optarg);
			exit(1);
		};
		expander->asnumber=(expander->asnumber<<16)+loas;
	} else if(eon && *eon) { 
		sx_report(SX_FATAL,"Invalid symbol in AS number: %c (%s)\n",
			*eon, optarg);
		exit(1);
	};
	return 0;
};

int
main(int argc, char* argv[])
{ 
	int c;
	struct bgpq_expander expander;
	int af=AF_INET;
	int widthSet=0, aggregate=0, refine=0;

	bgpq_expander_init(&expander,af);
	expander.sources=getenv("IRRD_SOURCES");

	while((c=getopt(argc,argv,"36AdEhS:Jf:l:W:PR:G:T"))!=EOF) { 
	switch(c) { 
		case '3': 
			expander.asn32=1;
			break;
		case '6': af=AF_INET6;
			expander.family=AF_INET6;
			expander.tree->family=AF_INET6;
			break;
		case 'A': 
			if(aggregate) debug_aggregation++;
			aggregate=1;
			break;
		case 'd': debug_expander++;
			break;
		case 'E': if(expander.generation) exclusive();
			expander.generation=T_EACL;
			break;
		case 'J': expander.vendor=V_JUNIPER;
			break;
		case 'f': 
			if(expander.generation) exclusive();
			expander.generation=T_ASPATH;
			parseasnumber(&expander,optarg);
			break;
		case 'G': 
			if(expander.generation) exclusive();
			expander.generation=T_OASPATH;
			parseasnumber(&expander,optarg);
			break;
		case 'P': 
			if(expander.generation) exclusive();
			expander.generation=T_PREFIXLIST;
			break;
		case 'R': 
			refine=strtoul(optarg,NULL,10);
			if(!refine) { 
				sx_report(SX_FATAL,"Invalid refine length: %s\n", optarg);
				exit(1);
			};
			break;
		case 'l': expander.name=optarg;
			break;
		case 'T': pipelining=0;
			break;
		case 'S': expander.sources=optarg;
			break;
		case 'W': expander.aswidth=atoi(optarg);
			if(expander.aswidth<1) { 
				sx_report(SX_FATAL,"Invalid as-width: %s\n", optarg);
				exit(1);
			};
			widthSet=1;
			break;
		case 'h': usage(0);
		default : usage(1);
	};
	};

	argc-=optind;
	argv+=optind;

	if(!widthSet) { 
		if(expander.generation==T_ASPATH) { 
			if(expander.vendor==V_CISCO) { 
				expander.aswidth=4;
			} else if(expander.vendor==V_JUNIPER) { 
				expander.aswidth=8;
			};
		} else if(expander.generation==T_OASPATH) { 
			if(expander.vendor==V_CISCO) { 
				expander.aswidth=5;
			} else if(expander.vendor==V_JUNIPER) { 
				expander.aswidth=8;
			};
		};
	};

	if(!expander.generation) { 
		expander.generation=T_PREFIXLIST;
	};

	if(expander.vendor==V_CISCO && expander.asn32 && 
		expander.generation<T_PREFIXLIST) { 
		sx_report(SX_FATAL,"Sorry, AS32-safety is not yet ready for Cisco\n");
	};

	if(!expander.asn32 && expander.asnumber>=65536) { 
		expander.asnumber=23456;
	};

	if(aggregate && expander.vendor==V_JUNIPER && 
		expander.generation==T_PREFIXLIST) { 
		sx_report(SX_FATAL, "Sorry, aggregation (-A) does not work in"
			" Juniper prefix-lists\n");
		exit(1);
	};
	if(aggregate && expander.generation<T_PREFIXLIST) { 
		sx_report(SX_FATAL, "Sorry, aggregation (-A) used only for prefix-"
			"lists, extended access-lists and route-filters\n");
		exit(1);
	};

	if(refine) { 
		if(expander.family==AF_INET6 && (refine>128)) { 
			sx_report(SX_FATAL, "Invalid value for refinement: %u (1-128 for"
				" IPv6)\n", refine);
		} else if(expander.family==AF_INET && refine>32) { 
			sx_report(SX_FATAL, "Invalid value for refinement: %u (1-32 for"
				" IPv4)\n", refine);
		};
		if(expander.vendor==V_JUNIPER && expander.generation==T_PREFIXLIST) { 
			sx_report(SX_FATAL, "Sorry, more-specific filter (-R %u) "
				"is not supported for Juniper prefix-lists\n", refine);
		};
		if(expander.generation<T_PREFIXLIST) { 
			sx_report(SX_FATAL, "Sorry, more-specific filter (-R %u) "
				"supported only with prefix-list generation\n", refine);
		};
	};


	if(!argv[0]) usage(1);

	while(argv[0]) { 
		if(!strncasecmp(argv[0],"AS-",3)) { 
			bgpq_expander_add_asset(&expander,argv[0]);
		} else if(!strncasecmp(argv[0],"AS",2)) { 
			char* c;
			if((c=strchr(argv[0],':'))) { 
				if(!strncasecmp(c+1,"AS-",3)) { 
					bgpq_expander_add_asset(&expander,argv[0]);
				} else if(!strncasecmp(c+1,"RS-",3)) { 
					bgpq_expander_add_rset(&expander,argv[0]);
				} else { 
					SX_DEBUG(debug_expander,"Unknown sub-as object %s\n",
						argv[0]);
				};
			} else { 
				bgpq_expander_add_as(&expander,argv[0]);
			};
		} else { 
			if(!bgpq_expander_add_prefix(&expander,argv[0]))
				exit(1);
		};
		argv++;
		argc--;
	};

	if(!bgpq_expand(&expander)) { 
		exit(1);
	};

	if(aggregate) 
		sx_radix_tree_aggregate(expander.tree);

	if(refine) 
		sx_radix_tree_refine(expander.tree,refine);

	switch(expander.generation) { 
		default    :
		case T_NONE: sx_report(SX_FATAL,"Unreachable point... call snar\n");
			exit(1);
		case T_ASPATH: bgpq3_print_aspath(stdout,&expander);
			break;
		case T_OASPATH: bgpq3_print_oaspath(stdout,&expander);
			break;
		case T_PREFIXLIST: bgpq3_print_prefixlist(stdout,&expander);
			break;
		case T_EACL: bgpq3_print_eacl(stdout,&expander);
			break;
	};

	return 0;
};
			
