#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/socket.h>

#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "bgpq3.h"
#include "sx_report.h"

int debug_expander=1;

int
bgpq_expander_init(struct bgpq_expander* b, int af)
{ 
	if(!af) af=AF_INET;
	if(!b) return 0;

	memset(b,0,sizeof(struct bgpq_expander));
	
	b->tree=sx_radix_tree_new(af);
	if(!b->tree) goto fixups;

	b->family=af;
	b->sources="ripe,radb,apnic";
	b->name="UNKNOWN";
	b->aswidth=8;

	return 1;
fixups:
	/* if(b->tree) XXXXXXXXXXXXX sx_radix_tree_destroy(b->tree); */
	b->tree=NULL;
	free(b);
	return 0;
};

int
bgpq_expander_add_asset(struct bgpq_expander* b, char* as)
{ 
	struct sx_slentry* le;
	if(!b || !as) return 0;
	le=sx_slentry_new(as);
	if(!le) return 0;
	if(!b->macroses) { 
		b->macroses=le;
	} else { 
		struct sx_slentry* ln=b->macroses;
		while(ln->next) ln=ln->next;
		ln->next=le;
	};
	return 1;
};

int
bgpq_expander_add_as(struct bgpq_expander* b, char* as)
{ 
	char* eoa;
	uint32_t asno;

	if(!b || !as) return 0;

	asno=strtoul(as+2,&eoa,10);
	if(eoa && (*eoa!='.' && *eoa!=0)) { 
		sx_report(SX_ERROR,"Invalid symbol in AS number: '%c' in %s\n", 
			*eoa, as);
		return 0;
	};

	if(*eoa=='.') { 
		sx_report(SX_ERROR,"32-bit as numbers is not supported yet (%s)\n",as);
		return 0;
	};

	if(asno<1 || asno>65535) { 
		sx_report(SX_ERROR,"Invalid AS number in %s\n", as);
		return 0;
	};

	b->asnumbers[asno/8]|=(0x80>>(asno%8));

	return 1;
};

int
bgpq_expander_add_prefix(struct bgpq_expander* b, char* prefix)
{ 
	struct sx_prefix p;
	if(!sx_prefix_parse(&p,b->family,prefix)) { 
		sx_report(SX_ERROR,"Unable to parse prefix %s\n", prefix);
		return 0;
	};
	sx_radix_tree_insert(b->tree,&p);
	return 0;
};

int
bgpq_expanded_macro(char* as, void* udata)
{ 
	struct bgpq_expander* ex=(struct bgp_expander*)udata;
	if(!ex) return 0;
	bgpq_expander_add_as(ex,as);
	return 1;
};

int
bgpq_expanded_prefix(char* as, void* udata)
{ 
	struct bgpq_expander* ex=(struct bgp_expander*)udata;
	if(!ex) return 0;
	bgpq_expander_add_prefix(ex,as);
	return 1;
};

int
bgpq_expand_radb(int fd, int (*callback)(char*, void*), void* udata,
	char* fmt, ...)
{ 
	char request[128];
	va_list ap;
	int ret;

	va_start(ap,fmt);
	vsnprintf(request,sizeof(request),fmt,ap);
	va_end(ap);

	SX_DEBUG(debug_expander,"expander: sending '%s'\n", request);

	write(fd,request,strlen(request));
	memset(request,0,sizeof(request));
nread:
	ret=read(fd,request,sizeof(request)-1);
	if(ret<0) { 
		sx_report(SX_ERROR,"Error reading data from radb: %s\n", 
			strerror(errno));
		exit(1);
	};
	if(ret==0) { 
		sx_report(SX_ERROR,"Connection with radb closed inexpeced\n");
		exit(1);
	};
	SX_DEBUG(debug_expander>2,"expander: initially got %i bytes, '%s'\n",
		ret,request);
	if(ret==1 && request[0]=='\n') goto nread;
	if(request[0]=='A') { 
		char* eon, *c;
		long togot=strtol(request+1,&eon,10);
		char  recvbuffer[togot+128];
		char* recvto;
		if(eon && *eon!='\n') { 
			sx_report(SX_ERROR,"Number ends at wrong character: '%c'(%s)\n"
				,*eon,request);
			exit(1);
		};
		eon++;
		memset(recvbuffer,0,togot+128);
		memcpy(recvbuffer,eon,ret-(eon-request));
		recvto=recvbuffer+ret-(eon-request);
		togot-=ret-(eon-request);
		while(togot>0) { 
			ret=read(fd,recvto,togot);
			if(ret<0) { 
				sx_report(SX_ERROR,"Error reading data: %s\n", 
					strerror(errno));
				exit(1);
			};
			if(ret==0) { 
				sx_report(SX_ERROR,"Server unexpectedly closed the"
					" connection\n");
				exit(1);
			};
			togot-=ret;
			recvto+=ret;
		};
		if(togot==0) { 
			memset(request,0,sizeof(request));
			ret=read(fd,request,sizeof(request)-1);
			if(ret>0) { 
				if(request[0]!='C') { 
					sx_report(SX_ERROR,"Wrong character after reply: %s\n",
						request);
					exit(0);
				};
			} else { 
				if(ret==0) { 
					sx_report(SX_ERROR,"Server inexpectedly closed"
						" connection\n");
					exit(0);
				} else { 
					sx_report(SX_ERROR,"Error reading data from server:"
						" %s\n",
						strerror(errno));
				};
			};
		} else { 
			/* togot < 0, initially. */
			if(recvto[togot]=='C') { 
				/* ok, finised */
			} else if(recvto[togot]=='D') { 
				/* nodata */
			} else if(recvto[togot]=='E') { 
			} else if(recvto[togot]=='F') { 
				sx_report(SX_FATAL,"Error from server: %s", recvto+togot);
				exit(1);
			};
			recvto[togot]=0;
		};
		for(c=recvbuffer; c<recvto;) { 
			size_t spn=strcspn(c," \n");
			if(spn) c[spn]=0;
			if(c[0]==0) break;
			if(callback) callback(c,udata);
			c+=spn+1;
		};
	} else if(request[0]=='C') { 
		/* no data */
	} else if(request[0]=='D') { 
		/* ... */
	} else if(request[0]=='E') { 
		/* XXXXXX */
	} else if(request[0]=='F') { 
		/* XXXXXX */
	} else { 
		sx_report(SX_ERROR,"Wrong reply: %s\n", request);
		exit(0);
	};
	return 0;
};

int
bgpq_expand(struct bgpq_expander* b)
{ 
	int fd=-1, err;
	struct sx_slentry* mc;
	struct addrinfo hints, *res=NULL, *rp;
	memset(&hints,0,sizeof(struct addrinfo));

	hints.ai_socktype=SOCK_STREAM;

	err=getaddrinfo("whois.radb.net","43",&hints,&res);
	if(err) { 
		sx_report(SX_ERROR,"Unable to resolve whois.radb.net: %s\n",
			gai_strerror(err));
		exit(1);
	};

	for(rp=res; rp; rp=rp->ai_next) { 
		fd=socket(rp->ai_family,rp->ai_socktype,0);
		if(fd==-1) { 
			if(errno==EPROTONOSUPPORT) continue;
			sx_report(SX_ERROR,"Unable to create socket: %s\n", 
				strerror(errno));
			exit(1);
		};
		err=connect(fd,rp->ai_addr,rp->ai_addrlen);
		if(err) { 
			shutdown(fd,SHUT_RDWR);
			close(fd);
			fd=-1;
			continue;
		};
		break;
	};
	freeaddrinfo(res);

	if(fd==-1) { 
		/* all our attempts to connect failed */
		sx_report(SX_ERROR,"All attempts to connect failed\n");
		exit(1);
	};

	write(fd,"!!\n",3);

	if(b->sources && b->sources[0]!=0) { 
		char sources[128];
		snprintf(sources,sizeof(sources),"!s%s\n", b->sources);
		write(fd,sources,strlen(sources));
	};

	for(mc=b->macroses;mc;mc=mc->next) { 
		bgpq_expand_radb(fd,bgpq_expanded_macro,b,"!i%s,1\n",mc->text);
	};
	if(b->generation>=T_PREFIXLIST) { 
		int i, j;
		for(i=0;i<sizeof(b->asnumbers);i++) { 
			for(j=0;j<8;j++) { 
				if(b->asnumbers[i]&(0x80>>j)) { 
					bgpq_expand_radb(fd,bgpq_expanded_prefix,b,"!gas%i\n",
						i*8+j);
				};
			};
		};
	};
				
	write(fd,"!q\n",3);
	shutdown(fd,SHUT_RDWR);
	close(fd);
	return 1;
};

