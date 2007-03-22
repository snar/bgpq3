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

int
usage(int ecode)
{ 
	printf("Usage: bgpq3 [-h] [-S sources] <OBJECTS>...\n");
	printf(" -h  : this help\n");
	printf(" -J  : use Juniper replace formatted output\n");
	printf(" -l  : use specified name for generated access/prefix/.. list\n");
	printf(" -S sources: use only specified sources (default:"
		" RADB,RIPE,APNIC)\n");
	exit(ecode);
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

	while((c=getopt(argc,argv,"6hS:Jf:l:W:P"))!=EOF) { 
	switch(c) { 
		case '6': af=AF_INET6;
			expander.family=AF_INET6;
			break;
		case 'J': expander.vendor=V_JUNIPER;
			break;
		case 'f': expander.asnumber=atoi(optarg);
			if(expander.asnumber<0 || expander.asnumber>65535) { 
				sx_report(SX_FATAL,"Invalid AS number: %s\n", optarg);
				exit(1);
			};
			expander.generation=T_ASPATH;
			break;
		case 'P': expander.generation=T_PREFIXLIST;
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

	if(!argv[0]) usage(1);

	while(argv[0]) { 
		if(!strncasecmp(argv[0],"AS-",3)) { 
			bgpq_expander_add_asset(&expander,argv[0]);
		} else if(!strncasecmp(argv[0],"AS",2)) { 
			bgpq_expander_add_as(&expander,argv[0]);
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
		case T_ASPATH: bgpq3_print_aspath(stdout,&expander);
			break;
		case T_PREFIXLIST: bgpq3_print_prefixlist(stdout,&expander);
		default : 
			break;
	};

	return 0;
};
			
