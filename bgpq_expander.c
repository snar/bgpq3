#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/socket.h>

#include <ctype.h>
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

int debug_expander=0;
int pipelining=0;

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
	b->name="NN";
	b->aswidth=8;
	b->asn32s[0]=malloc(8192);

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
		if(b->asn32 || b->generation>=T_PREFIXLIST) { 
			uint32_t asn1=strtoul(eoa+1,&eoa,10);
			if(eoa && *eoa!=0) { 
				sx_report(SX_ERROR,"Invalid symbol in AS number: '%c' in %s\n",
					*eoa, as);
				return 0;
			};
			if(asn1<1 || asn1>65535) { 
				sx_report(SX_ERROR,"Invalid AS number in %s\n", as);
				return 0;
			};
			if(!b->asn32s[asno]) { 
				b->asn32s[asno]=malloc(8192);
				if(!b->asn32s[asno]) { 
					sx_report(SX_FATAL, "Unable to allocate 8192 bytes: %s."
						" Unable to add asn32 %s to future expansion\n", 
						strerror(errno), as);
					return 0;
				};
				memset(b->asn32s[asno],0,8192);
			};
			b->asn32s[asno][asn1/8]|=(0x80>>(asn1%8));
		} else if(!b->asn32) { 
			b->asn32s[0][23456/8]|=(0x80>>(23456%8));
		};
		return 0;
	};

	if(asno<1 || asno>65535) { 
		sx_report(SX_ERROR,"Invalid AS number in %s\n", as);
		return 0;
	};

	b->asn32s[0][asno/8]|=(0x80>>(asno%8));

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
	return 1;
};

int
bgpq_expanded_macro(char* as, void* udata)
{ 
	struct bgpq_expander* ex=(struct bgpq_expander*)udata;
	if(!ex) return 0;
	bgpq_expander_add_as(ex,as);
	return 1;
};

int
bgpq_expanded_prefix(char* as, void* udata)
{ 
	struct bgpq_expander* ex=(struct bgpq_expander*)udata;
	if(!ex) return 0;
	bgpq_expander_add_prefix(ex,as);
	return 1;
};

int
bgpq_expanded_v6prefix(char* prefix, void* udata)
{ 
	struct bgpq_expander* ex=(struct bgpq_expander*)udata;
	if(!ex) return 0;
	bgpq_expander_add_prefix(ex,prefix);
	return 1;
};

int
bgpq_expand_ripe(FILE* f, int (*callback)(char*, void*), void* udata,
	char* fmt, ...)
{
	char  request[128];
	char* otype=NULL, *object=NULL, *origin=NULL;
	int sawNL=0, nObjects=0;
	va_list ap;
	struct bgpq_expander* b=(struct bgpq_expander*)udata;

	if(!f) { 
		sx_report(SX_FATAL,"Invalid argments\n");
		exit(1);
	};

	va_start(ap,fmt);
	vsnprintf(request,sizeof(request),fmt,ap);
	va_end(ap);

	SX_DEBUG(debug_expander,"expander(ripe): sending '%s'\n", request);
	fseek(f,0,SEEK_END);
	fwrite(request,1,strlen(request),f);
	fflush(f);

	sawNL=0;
	fseek(f,0,SEEK_END);
	while(fgets(request,sizeof(request),f)) { 
		fseek(f,0,SEEK_END);
		if(request[0]=='\n') { 
			if(b->family==AF_INET && otype && !strcmp(otype,"route")) { 
				SX_DEBUG(debug_expander,"expander(ripe): got route: %s\n",
					object);
				callback(object,udata);
			} else if(b->family==AF_INET6 && otype&&!strcmp(otype,"route6")) { 
				SX_DEBUG(debug_expander,"expander(ripe): got route6: %s\n",
					object);
				callback(object,udata);
			};
			if(otype) free(otype); otype=NULL;
			if(object) free(object); object=NULL;
			if(origin) free(origin); origin=NULL;
			nObjects++;
			sawNL++;
			if(sawNL==2) { 
				/* ok, that's end of input */
				return nObjects;
			};
		} else { 
			sawNL=0;
			if(!otype) { 
				/* that's the first line of object */
				char* c=strchr(request,':');
				if(c) { 
					*c=0;
					otype=strdup(request);
					c++;
					while((isspace((int)*c))) c++;
					object=strdup(c);
					c=strchr(object,'\n');
					if(c) *c=0;
				};
			} else if(!strncmp(request,"origin",6)) { 
				if(origin) free(origin);
				origin=strdup(request);
			};
		};
	};
	if(feof(f)) { 
		sx_report(SX_FATAL,"EOF from server\n");
	} else { 
		sx_report(SX_FATAL,"Error reading server: %s\n", strerror(errno));
	};
	return 0;
};

int
bgpq_pipeline(FILE* f, int (*callback)(char*, void*), void* udata,
	char* fmt, ...)
{ 
	char request[128];
	int ret;
	struct bgpq_prequest* bp=NULL;
	struct bgpq_expander* d=(struct bgpq_expander*)udata;
	va_list ap;
	va_start(ap,fmt);
	vsnprintf(request,sizeof(request),fmt,ap);
	va_end(ap);

	SX_DEBUG(debug_expander,"expander: sending '%s'\n", request);

	bp=malloc(sizeof(struct bgpq_prequest));
	if(!bp) { 
		sx_report(SX_FATAL,"Unable to allocate %i bytes: %s\n", 
			sizeof(struct bgpq_prequest),strerror(errno));
		exit(1);
	};
	memset(bp,0,sizeof(bp));

	ret=fwrite(request,1,strlen(request),f);
	fseek(f,0,SEEK_END);

	if(ret!=strlen(request)) { 
		sx_report(SX_FATAL,"Partial write to radb, only %i bytes written: %s\n",
			ret,strerror(errno));
		exit(1);
	};

	strlcpy(bp->request,request,sizeof(bp->request));
	bp->callback=callback;
	bp->udata=udata;

	if(d->lastpipe) { 
		d->lastpipe->next=bp;
		d->lastpipe=bp;
	} else { 
		d->firstpipe=d->lastpipe=bp;
	};
	d->piped++;

	return 0;
};

int
bgpq_pipeline_dequeue(FILE* f, struct bgpq_expander* b)
{ 
	while(b->piped>0) { 
		char request[128];
		struct bgpq_prequest* pipe;
		memset(request,0,sizeof(request));
		if(!fgets(request,sizeof(request),f)) { 
			if(ferror(f)) { 
				sx_report(SX_FATAL,"Error reading data from RADB: %s\n", 
					strerror(errno));
			} else { 
				sx_report(SX_FATAL,"EOF from RADB\n");
			};
			exit(1);
		};

		if(request[0]=='A') { 
			char* eon, *c;
			unsigned long togot=strtoul(request+1,&eon,10);
			char recvbuffer[togot+2];

			if(eon && *eon!='\n') { 
				sx_report(SX_ERROR,"A-code finished with wrong char '%c'(%s)\n",
					*eon,request);
				exit(1);
			};
			if(fgets(recvbuffer,togot+1,f)==NULL) { 
				if(ferror(f)) { 
					sx_report(SX_FATAL,"Error reading RADB: %s\n", 
						strerror(errno));
				} else { 
					sx_report(SX_FATAL,"EOF from RADB\n");
				};
				exit(1);
			};

			for(c=recvbuffer; c<recvbuffer+togot;) { 
				size_t spn=strcspn(c," \n");
				if(spn) c[spn]=0;
				if(c[0]==0) break;
				if(b->firstpipe->callback) { 
					b->firstpipe->callback(c,b->firstpipe->udata);
				};
				c+=spn+1;
			};

			/* Final code */
			if(fgets(recvbuffer,togot,f)==NULL) { 
				if(ferror(f)) { 
					sx_report(SX_FATAL,"Error reading RADB: %s\n", 
						strerror(errno));
				} else { 
					sx_report(SX_FATAL,"EOF from RADB\n");
				};
				exit(1);
			};
		} else if(request[0]=='C') { 
			/* No data */
		} else if(request[0]=='D') { 
			/* .... */
		} else if(request[0]=='E') { 
			/* XXXXX */
		} else if(request[0]=='F') { 
			/* XXXXX */
		} else { 
			sx_report(SX_ERROR,"Wrong reply: %s to %s\n", request, 
				b->firstpipe->request);
		};

		pipe=b->firstpipe;
		b->firstpipe=b->firstpipe->next;
		b->piped--;
		free(pipe);
				
	};
	return 0;
};

int
bgpq_expand_radb(FILE* f, int (*callback)(char*, void*), void* udata,
	char* fmt, ...)
{ 
	char request[128];
	va_list ap;
	int ret;

	va_start(ap,fmt);
	vsnprintf(request,sizeof(request),fmt,ap);
	va_end(ap);

	SX_DEBUG(debug_expander,"expander: sending '%s'\n", request);

	ret=fwrite(request,1,strlen(request),f);
	fseek(f,0,SEEK_END);
	if(ret!=strlen(request)) { 
		sx_report(SX_FATAL,"Partial write to radb, only %i bytes written: %s\n",
			ret,strerror(errno));
		exit(1);
	};
	memset(request,0,sizeof(request));
	if(!fgets(request,sizeof(request),f)) { 
		if(ferror(f)) { 
			sx_report(SX_FATAL,"Error reading data from radb: %s\n", 
				strerror(errno));
			exit(1);
		};
		sx_report(SX_FATAL,"EOF from radb\n");
		exit(1);
	};
	SX_DEBUG(debug_expander>2,"expander: initially got %i bytes, '%s'\n",
		strlen(request),request);
	if(request[0]=='A') { 
		char* eon, *c;
		long togot=strtoul(request+1,&eon,10);
		char recvbuffer[togot+1];

		if(eon && *eon!='\n') { 
			sx_report(SX_ERROR,"A-code finised with wrong char '%c' (%s)\n",
				*eon,request);
			exit(1);
		};

		if(fgets(recvbuffer,togot,f)==NULL) { 
			if(feof(f)) { 
				sx_report(SX_FATAL,"EOF from radb\n");
			} else { 
				sx_report(SX_FATAL,"Error reading radb: %s\n", strerror(errno));
			};
			exit(1);
		};
		SX_DEBUG(debug_expander>2,"expander: final reply of %i bytes, '%s'\n",
			strlen(recvbuffer),recvbuffer);
			
		for(c=recvbuffer; c<recvbuffer+togot;) { 
			size_t spn=strcspn(c," \n");
			if(spn) c[spn]=0;
			if(c[0]==0) break;
			if(callback) callback(c,udata);
			c+=spn+1;
		};

		if(fgets(recvbuffer,togot,f)==NULL) { 
			if(feof(f)) { 
				sx_report(SX_FATAL,"EOF from radb\n");
			} else { 
				sx_report(SX_FATAL,"ERROR from radb: %s\n", strerror(errno));
			};
			exit(1);
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
	int fd=-1, err, ret;
	struct sx_slentry* mc;
	struct addrinfo hints, *res=NULL, *rp;
	FILE* f=NULL;
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
		f=fdopen(fd,"a+");
		if(!f) { 
			shutdown(fd,SHUT_RDWR);
			close(fd);
			fd=-1;
			f=NULL;
			continue;
		};
		break;
	};
	freeaddrinfo(res);

	if(!f) { 
		/* all our attempts to connect failed */
		sx_report(SX_ERROR,"All attempts to connect failed\n");
		exit(1);
	};
	
	fseek(f,0,SEEK_END);
	if((ret=fwrite("!!\n",1,3,f))!=3) { 
		sx_report(SX_ERROR,"Partial fwrite to radb: %i bytes, %s\n", 
			ret, strerror(errno));
		exit(1);
	};

	if(b->sources && b->sources[0]!=0) { 
		char sources[128];
		snprintf(sources,sizeof(sources),"!s%s\n", b->sources);
		fseek(f,0,SEEK_END);
		fwrite(sources,strlen(sources),1,f);
		fgets(sources,sizeof(sources),f);
	};

	if(b->identify) { 
		char ident[128];
		snprintf(ident,sizeof(ident),"!n" PACKAGE_STRING "\n");
		fseek(f,0,SEEK_END);
		fwrite(ident,strlen(ident),1,f);
		fgets(ident,sizeof(ident),f);
	};

	for(mc=b->macroses;mc;mc=mc->next) { 
		bgpq_expand_radb(f,bgpq_expanded_macro,b,"!i%s,1\n",mc->text);
	};
	if(b->generation>=T_PREFIXLIST) { 
		unsigned i, j, k;
		for(k=0;k<sizeof(b->asn32s)/sizeof(unsigned char*);k++) { 
			if(!b->asn32s[k]) continue;
			for(i=0;i<8192;i++) { 
				for(j=0;j<8;j++) { 
					if(b->asn32s[k][i]&(0x80>>j)) { 
						if(b->family==AF_INET6) { 
							if(k>0) 
								bgpq_expand_ripe(f,bgpq_expanded_v6prefix,b,
									"-T route6 -i origin as%u.%u\r\n", k,i*8+j);
							else 
								bgpq_expand_ripe(f,bgpq_expanded_v6prefix,b,
									"-T route6 -i origin as%u\r\n", i*8+j);

						} else { 
							if(!pipelining) { 
								if(k>0) 
									bgpq_expand_radb(f,bgpq_expanded_prefix,b,
										"!gas%u.%u\n", k, i*8+j);
								else 
									bgpq_expand_radb(f,bgpq_expanded_prefix,b,
										"!gas%u\n", i*8+j);
							} else { 
								if(k>0) 
									bgpq_pipeline(f,bgpq_expanded_prefix,b,
										"!gas%u.%u\n", k, i*8+j);
								else 
									bgpq_pipeline(f,bgpq_expanded_prefix,b,
										"!gas%u\n", i*8+j);
							};
						};
					};
				};
			};
		};
		if(pipelining) { 
			bgpq_pipeline_dequeue(f,b);
		};
	};
				
	write(fd,"!q\n",3);
	shutdown(fd,SHUT_RDWR);
	close(fd);
	return 1;
};

