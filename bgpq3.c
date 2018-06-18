#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
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
extern int expand_as23456;
extern int expand_special_asn;

int
usage(int ecode)
{
	printf("\nUsage: bgpq3 [-h host[:port]] [-S sources] [-P|E|G <num>|f <num>]"
		" [-2346ABbDJjXd] [-R len] <OBJECTS>...\n");
	printf(" -2        : allow routes belonging to as23456 (transition-as) "
		"(default: false)\n");
	printf(" -3        : assume that your device is asn32-safe\n");
	printf(" -4        : generate IPv4 prefix-lists (default)\n");
	printf(" -6        : generate IPv6 prefix-lists (IPv4 by default)\n");
	printf(" -A        : try to aggregate Cisco prefix-lists or Juniper "
			"route-filters\n             as much as possible\n");
	printf(" -B        : generate OpenBGPD output (Cisco IOS by default)\n");
	printf(" -b        : generate BIRD output (Cisco IOS by default)\n");
	printf(" -d        : generate some debugging output\n");
	printf(" -D        : use asdot notation in as-path (Cisco only)\n");
	printf(" -E        : generate extended access-list(Cisco), "
		"route-filter(Juniper) or\n"
		"             [ip|ipv6]-prefix-list (Nokia)\n");
	printf(" -f number : generate input as-path access-list\n");
	printf(" -F fmt    : generate output in user-defined format\n");
	printf(" -G number : generate output as-path access-list\n");
	printf(" -h host   : host running IRRD software (whois.radb.net by "
		"default)\n"
		"             (use host:port to specify alternate port)\n");
	printf(" -J        : generate config for JunOS (Cisco IOS by default)\n");
	printf(" -j        : generate JSON output (Cisco IOS by default)\n");
	printf(" -M match  : extra match conditions for JunOS route-filters\n");
	printf(" -m len    : maximum prefix length (default: 32 for IPv4, "
		"128 for IPv6)\n");
	printf(" -L depth  : limit recursion depth (default: unlimited)\n"),
	printf(" -l name   : use specified name for generated access/prefix/.."
		" list\n");
	printf(" -N        : generate config for Nokia SR OS (Cisco IOS by default)\n");
	printf(" -P        : generate prefix-list (default, just for backward"
		" compatibility)\n");
	printf(" -R len    : allow more specific routes up to specified masklen\n");
	printf(" -r len    : allow more specific routes from masklen specified\n");
	printf(" -S sources: use only specified sources (recommended:"
		" RADB,RIPE,APNIC)\n");
	printf(" -s        : generate sequence numbers in prefix-lists (IOS only)\n");
	printf(" -T        : disable pipelining (experimental, faster mode)\n");
	printf(" -V        : generate config for Vyatta/VyOS/EdgeOS (Cisco IOS by default)\n");
	printf(" -W len    : specify max-entries on as-path line (use 0 for "
		"infinity)\n");
	printf(" -X        : generate config for IOS XR (Cisco IOS by default)\n");
	printf("\n" PACKAGE_NAME " version: " PACKAGE_VERSION "\n");
	printf("Copyright(c) Alexandre Snarskii <snar@snar.spb.ru> 2007-2017\n\n");
	exit(ecode);
};

void
exclusive()
{
	fprintf(stderr,"-E, -f <asnum>, -G <asnum> and -P are mutually "
		"exclusive\n");
	exit(1);
};

void
vendor_exclusive()
{
	fprintf(stderr, "-b (BIRD), -B (OpenBGPD), -F (formatted), -J (JunOS), "
		"-j (JSON), -N (NOKIA SR OS), -X (IOS XR) -V (Vyatta) options are mutually exclusive\n");
	exit(1);
};

int
parseasnumber(struct bgpq_expander* expander, char* optarg)
{
	char* eon=NULL;
	expander->asnumber=strtoul(optarg,&eon,10);
	if(expander->asnumber<1 || expander->asnumber>(65535ul*65535)) {
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
		if(loas<1 || loas>65535) {
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
	int af=AF_INET, selectedipv4 = 0, exceptmode = 0;
	int widthSet=0, aggregate=0, refine=0, refineLow=0;
	unsigned long maxlen=0;

	bgpq_expander_init(&expander,af);
	if (getenv("IRRD_SOURCES"))
		expander.sources=getenv("IRRD_SOURCES");

	while((c=getopt(argc,argv,"2346a:AbBdDEF:S:jJf:l:L:m:M:NVW:Ppr:R:G:Th:Xsz"))
		!=EOF) {
	switch(c) {
		case '2':
			expand_as23456=1;
			break;
		case '3':
			expander.asn32=1;
			break;
		case '4':
			/* do nothing, expander already configured for IPv4 */
			if (expander.family == AF_INET6) {
				sx_report(SX_FATAL, "-4 and -6 are mutually exclusive\n");
				exit(1);
			};
			selectedipv4=1;
			break;
		case '6':
			if (selectedipv4) {
				sx_report(SX_FATAL, "-4 and -6 are mutually exclusive\n");
				exit(1);
			};
			af=AF_INET6;
			expander.family=AF_INET6;
			expander.tree->family=AF_INET6;
			break;
		case 'a':
			parseasnumber(&expander,optarg);
			break;
		case 'A':
			if(aggregate) debug_aggregation++;
			aggregate=1;
			break;
		case 'b':
			if(expander.vendor) vendor_exclusive();
			expander.vendor=V_BIRD;
			break;
		case 'B':
			if(expander.vendor) vendor_exclusive();
			expander.vendor=V_OPENBGPD;
			expander.asn32=1;
			break;
		case 'd': debug_expander++;
			break;
		case 'D': expander.asdot=1;
			break;
		case 'E': if(expander.generation) exclusive();
			expander.generation=T_EACL;
			break;
		case 'F': if(expander.vendor) exclusive();
			expander.vendor=V_FORMAT;
			expander.format=optarg;
			break;
		case 'h': {
			char* d=strchr(optarg, ':');
			expander.server=optarg;
			if(d) {
				*d=0;
				expander.port=d+1;
			};
			break;
		};
		case 'J': if(expander.vendor) vendor_exclusive();
			expander.vendor=V_JUNIPER;
			break;
		case 'j': if(expander.vendor) vendor_exclusive();
			expander.vendor=V_JSON;
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
		case 'p':
			expand_special_asn=1;
			break;
		case 'P':
			if(expander.generation) exclusive();
			expander.generation=T_PREFIXLIST;
			break;
		case 'r':
			refineLow=strtoul(optarg,NULL,10);
			if(!refineLow) {
				sx_report(SX_FATAL,"Invalid refineLow value: %s\n", optarg);
				exit(1);
			};
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
		case 'L': expander.maxdepth=strtol(optarg, NULL, 10);
			if (expander.maxdepth < 1) {
				sx_report(SX_FATAL, "Invalid maximum recursion (-L): %s\n",
					optarg);
				exit(1);
			};
			break;
		case 'm': maxlen=strtoul(optarg, NULL, 10);
			if (!maxlen) {
				sx_report(SX_FATAL, "Invalid maxlen (-m): %s\n", optarg);
				exit(1);
			};
			break;
		case 'M': {
			char* c, *d;
			expander.match=strdup(optarg);
			c=d=expander.match;
			while(*c) {
				if(*c=='\\') {
					if(*(c+1)=='n') {
						*d='\n';
						d++;
						c+=2;
					} else if(*(c+1)=='r') {
						*d='\r';
						d++;
						c+=2;
					} else if(*(c+1)=='t') {
						*d='\t';
						d++;
						c+=2;
					} else if(*(c+1)=='\\') {
						*d='\\';
						d++;
						c+=2;
					} else {
						sx_report(SX_FATAL, "Unsupported escape \%c (0x%2.2x) "
							"in '%s'\n", isprint(*c)?*c:20, *c, optarg);
						exit(1);
					};
				} else {
					if(c!=d) {
						*d=*c;
					};
					d++;
					c++;
				};
			};
			*d=0;
			};
			break;
		case 'N': if(expander.vendor) vendor_exclusive();
			expander.vendor=V_NOKIA;
			break;
		case 'T': pipelining=0;
			break;
		case 's': expander.sequence=1;
			break;
		case 'S': expander.sources=optarg;
			break;
		case 'V': if(expander.vendor) vendor_exclusive();
			expander.vendor=V_VYATTA;
                        break;
		case 'W': expander.aswidth=atoi(optarg);
			if(expander.aswidth<0) {
				sx_report(SX_FATAL,"Invalid as-width: %s\n", optarg);
				exit(1);
			};
			widthSet=1;
			break;
		case 'X': if(expander.vendor) vendor_exclusive();
			expander.vendor=V_CISCO_XR;
			break;
		case 'z':
			if(expander.generation) exclusive();
			expander.generation=T_ROUTE_FILTER_LIST;
			break;
		default : usage(1);
	};
	};

	argc-=optind;
	argv+=optind;

	if(!widthSet) {
		if(expander.generation==T_ASPATH) {
			if(expander.vendor==V_CISCO) {
				expander.aswidth=4;
			} else if(expander.vendor==V_CISCO_XR) {
				expander.aswidth=6;
			} else if(expander.vendor==V_JUNIPER) {
				expander.aswidth=8;
			} else if(expander.vendor==V_BIRD) {
				expander.aswidth=10;
			} else if(expander.vendor==V_NOKIA) {
				expander.aswidth=8;
			};
		} else if(expander.generation==T_OASPATH) {
			if(expander.vendor==V_CISCO) {
				expander.aswidth=5;
			} else if(expander.vendor==V_CISCO_XR) {
				expander.aswidth=7;
			} else if(expander.vendor==V_JUNIPER) {
				expander.aswidth=8;
			} else if(expander.vendor==V_NOKIA) {
				expander.aswidth=8;
			};
		};
	};

	if(!expander.generation) {
		expander.generation=T_PREFIXLIST;
	};

	if(expander.vendor==V_CISCO_XR && expander.generation!=T_PREFIXLIST &&
		expander.generation!=T_ASPATH && expander.generation!=T_OASPATH) {
		sx_report(SX_FATAL, "Sorry, only prefix-sets and as-paths "
			"supported for IOS XR\n");
	};
	if(expander.vendor==V_BIRD && expander.generation!=T_PREFIXLIST &&
		expander.generation!=T_ASPATH) {
		sx_report(SX_FATAL, "Sorry, only prefix-lists and as-paths supported "
			"for BIRD output\n");
	};
	if(expander.vendor==V_JSON && expander.generation!=T_PREFIXLIST &&
		expander.generation!=T_ASPATH) {
		sx_report(SX_FATAL, "Sorry, only prefix-lists and as-paths supported "
			"for JSON output\n");
	};
	if(expander.vendor==V_FORMAT && expander.generation!=T_PREFIXLIST)
		sx_report(SX_FATAL, "Sorry, only prefix-lists supported in formatted "
			"output\n");
	if(expander.vendor==V_FORMAT && (refine || refineLow)) {
		sx_report(SX_FATAL, "Sorry, formatted output (-F <fmt>) in not "
			"compatible with -R/-r options\n");
		exit(1);
	};
	if(expander.generation==T_ROUTE_FILTER_LIST && expander.vendor!=V_JUNIPER) {
		sx_report(SX_FATAL, "Route-filter-lists (-z) supported for Juniper (-J)"
			" output only\n");
	};

	if(expander.asdot && expander.vendor!=V_CISCO) {
		sx_report(SX_FATAL,"asdot notation supported only for Cisco, "
			"other formats use asplain only\n");
	};

	if(!expander.asn32 && expander.asnumber>65535) {
		expander.asnumber=23456;
	};

	if(aggregate && expander.vendor==V_JUNIPER &&
		expander.generation==T_PREFIXLIST) {
		sx_report(SX_FATAL, "Sorry, aggregation (-A) does not work in"
			" Juniper prefix-lists\nYou can try route-filters (-E) "
			"or route-filter-lists (-z) instead of prefix-lists "
			"(-P, default)\n");
		exit(1);
	};

	if(aggregate && expander.vendor==V_FORMAT) {
		sx_report(SX_FATAL, "Sorry, aggregation (-A) is not compatible with "
			"formatted output (-F <fmt>)\n");
		exit(1);
	};

	if(aggregate && expander.vendor==V_NOKIA) {
		sx_report(SX_FATAL, "Sorry, aggregation (-A) is not supported on "
			"Nokia equipment (-N)\n");
		exit(1);
	};

	if(expander.vendor==V_VYATTA && expander.generation!=T_PREFIXLIST &&
		expander.generation!=T_ASPATH && expander.generation!=T_OASPATH) {
		sx_report(SX_FATAL, "Sorry, only prefix-sets and as-paths "
			"supported for Vyatta output\n");
	};

	if(aggregate && expander.generation<T_PREFIXLIST) {
		sx_report(SX_FATAL, "Sorry, aggregation (-A) used only for prefix-"
			"lists, extended access-lists and route-filters\n");
		exit(1);
	};

	if (expander.sequence && expander.vendor!=V_CISCO) {
		sx_report(SX_FATAL, "Sorry, prefix-lists sequencing (-s) supported"
			" only for IOS\n");
		exit(1);
	};

	if (expander.sequence && expander.generation<T_PREFIXLIST) {
		sx_report(SX_FATAL, "Sorry, prefix-lists sequencing (-s) can't be "
			" used for non prefix-list\n");
		exit(1);
	};

	if(refineLow && !refine) {
		if(expander.family == AF_INET)
			refine = 32;
		else
			refine = 128;
	};

	if (refineLow && refineLow > refine) {
		sx_report(SX_FATAL, "Incompatible values for -r %u and -R %u\n",
			refineLow, refine);
	};

	if(refine || refineLow) {
		if(expander.family==AF_INET6 && refine>128) {
			sx_report(SX_FATAL, "Invalid value for refine(-R): %u (1-128 for"
				" IPv6)\n", refine);
		} else if(expander.family==AF_INET6 && refineLow>128) {
			sx_report(SX_FATAL, "Invalid value for refineLow(-r): %u (1-128 for"
				" IPv6)\n", refineLow);
		} else if(expander.family==AF_INET && refine>32) {
			sx_report(SX_FATAL, "Invalid value for refine(-R): %u (1-32 for"
				" IPv4)\n", refine);
		} else if(expander.family==AF_INET && refineLow>32) {
			sx_report(SX_FATAL, "Invalid value for refineLow(-r): %u (1-32 for"
				" IPv4)\n", refineLow);
		};

		if(expander.vendor==V_JUNIPER && expander.generation==T_PREFIXLIST) {
			if(refine) {
				sx_report(SX_FATAL, "Sorry, more-specific filters (-R %u) "
					"is not supported for Juniper prefix-lists.\n"
					"Use router-filters (-E) or route-filter-lists (-z) "
					"instead\n", refine);
			} else {
				sx_report(SX_FATAL, "Sorry, more-specific filters (-r %u) "
					"is not supported for Juniper prefix-lists.\n"
					"Use route-filters (-E) or route-filter-lists (-z) "
					"instead\n", refineLow);
			};
		};

		if(expander.vendor==V_NOKIA) {
			if(refine) {
				sx_report(SX_FATAL, "Sorry, more-specific filters (-R %u) "
					"not supported on Nokia (-N)\n", refine);
			} else {
				sx_report(SX_FATAL, "Sorry, more-specific filters (-r %u) "
					"not supported on Nokia (-N)\n", refineLow);
			};
		};

		if(expander.generation<T_PREFIXLIST) {
			if(refine) {
				sx_report(SX_FATAL, "Sorry, more-specific filter (-R %u) "
		 			"supported only with prefix-list generation\n", refine);
			} else {
				sx_report(SX_FATAL, "Sorry, more-specific filter (-r %u) "
					"supported only with prefix-list generation\n", refineLow);
			};
		};
	};

	if(maxlen) {
		if((expander.family==AF_INET6 && maxlen>128) ||
			(expander.family==AF_INET  && maxlen>32)) {
			sx_report(SX_FATAL, "Invalid value for max-prefixlen: %lu (1-128 "
				"for IPv6, 1-32 for IPv4)\n", maxlen);
			exit(1);
		} else if((expander.family==AF_INET6 && maxlen<128) ||
			(expander.family==AF_INET  && maxlen<32)) {
			/* inet6/128 and inet4/32 does not make sense - all routes will
			 * be accepted, so save some CPU cycles :) */
			expander.maxlen = maxlen;
		};
	} else if (expander.family==AF_INET) {
		expander.maxlen = 32;
	} else if (expander.family==AF_INET6) {
		expander.maxlen = 128;
	};

	if(expander.generation==T_EACL && expander.vendor==V_CISCO &&
		expander.family==AF_INET6) {
		sx_report(SX_FATAL,"Sorry, ipv6 access-lists not supported for Cisco"
			" yet.\n");
	};

	if(expander.match != NULL && (expander.vendor != V_JUNIPER ||
		expander.generation != T_EACL)) {
		sx_report(SX_FATAL, "Sorry, extra match conditions (-M) can be used "
			"only with Juniper route-filters\n");
	};

	if((expander.generation==T_ASPATH || expander.generation==T_OASPATH) &&
		af != AF_INET) {
		sx_report(SX_FATAL, "Sorry, -6 makes no sense with as-path (-f/-G) "
			"generation\n");
	};

	if(!argv[0])
		usage(1);

	while(argv[0]) {
		if(!strcmp(argv[0], "EXCEPT")) {
			exceptmode = 1;
		} else if (exceptmode) {
			bgpq_expander_add_stop(&expander,argv[0]);
		} else if(!strncasecmp(argv[0],"AS-",3)) {
			bgpq_expander_add_asset(&expander,argv[0]);
		} else if(!strncasecmp(argv[0],"RS-",3)) {
			bgpq_expander_add_rset(&expander,argv[0]);
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
			char* c = strchr(argv[0], '^');
			if (!c && !bgpq_expander_add_prefix(&expander,argv[0])) {
				sx_report(SX_ERROR, "Unable to add prefix %s (bad prefix or "
					"address-family)\n", argv[0]);
				exit(1);
			} else if (c && !bgpq_expander_add_prefix_range(&expander,argv[0])){
				sx_report(SX_ERROR, "Unable to add prefix-range %s (bad range "
					"or address-family)\n", argv[0]);
				exit(1);
			};
		};
		argv++;
		argc--;
	};

	if(!bgpq_expand(&expander)) {
		exit(1);
	};

	if(refine)
		sx_radix_tree_refine(expander.tree,refine);

	if(refineLow)
		sx_radix_tree_refineLow(expander.tree, refineLow);

	if(aggregate)
		sx_radix_tree_aggregate(expander.tree);

	switch(expander.generation) {
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
		case T_ROUTE_FILTER_LIST:
			bgpq3_print_route_filter_list(stdout, &expander);
			break;
	};

	return 0;
};

