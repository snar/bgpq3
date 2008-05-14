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

int
usage(int ecode)
{ 
	printf("Usage: bgpq3 [-h] [-S sources] [-P|G <number>|f <number>] [-6]"
		" <OBJECTS>...\n");
	printf(" -6        : generate IPv6 access/prefix-lists\n");
	printf(" -d        : generate some debugging output\n");
	printf(" -f number : generate input as-path access-list\n");
	printf(" -G number : generate output as-path access-list\n");
	printf(" -h        : this help\n");
	printf(" -J        : use Juniper replace formatted output\n");
	printf(" -l        : use specified name for generated access/prefix/.."
		" list\n");
	printf(" -P        : generate prefix-list (default)\n");
	printf(" -S sources: use only specified sources (default:"
		" RADB,RIPE,APNIC)\n");
	printf("\nCopyright(c) Alexandre Snarskii <snar@paranoia.ru>,2007,2008\n\n");
	exit(ecode);
};

void
exclusive()
{ 
	fprintf(stderr,"-f <asnum>, -G <asnum> and -P are mutually exclusive\n");
	exit(1);
};

int
main(int argc, char* argv[])
{ 
	int c;
	struct bgpq_expander expander;
	int af=AF_INET;
	int widthSet=0;

	bgpq_expander_init(&expander,af);
	expander.sources=getenv("IRRD_SOURCES");

	while((c=getopt(argc,argv,"6dhS:Jf:l:W:PG:"))!=EOF) { 
	switch(c) { 
		case '6': af=AF_INET6;
			expander.family=AF_INET6;
			expander.tree->family=AF_INET6;
			break;
		case 'd': debug_expander++;
			break;
		case 'J': expander.vendor=V_JUNIPER;
			break;
		case 'f': expander.asnumber=atoi(optarg);
			if(expander.asnumber<0 || expander.asnumber>65535) { 
				sx_report(SX_FATAL,"Invalid AS number: %s\n", optarg);
				exit(1);
			};
			if(expander.generation) exclusive();
			expander.generation=T_ASPATH;
			break;
		case 'G': expander.asnumber=atoi(optarg);
			if(expander.asnumber<0 || expander.asnumber>65535) { 
				sx_report(SX_FATAL,"Invalid AS number: %s\n", optarg);
				exit(1);
			};
			if(expander.generation) exclusive();
			expander.generation=T_OASPATH;
			break;
		case 'P': 
			if(expander.generation) exclusive();
			expander.generation=T_PREFIXLIST;
			break;
		case 'l': expander.name=optarg;
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

	if(!argv[0]) usage(1);

	while(argv[0]) { 
		if(!strncasecmp(argv[0],"AS-",3)) { 
			bgpq_expander_add_asset(&expander,argv[0]);
		} else if(!strncasecmp(argv[0],"AS",2)) { 
			if(strchr(argv[0],':')) { 
				bgpq_expander_add_asset(&expander,argv[0]);
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

	switch(expander.generation) { 
		case T_NONE: sx_report(SX_FATAL,"Unreachable point... call snar\n");
			exit(1);
		case T_ASPATH: bgpq3_print_aspath(stdout,&expander);
			break;
		case T_OASPATH: bgpq3_print_oaspath(stdout,&expander);
			break;
		case T_PREFIXLIST: bgpq3_print_prefixlist(stdout,&expander);
	};

	return 0;
};
			
