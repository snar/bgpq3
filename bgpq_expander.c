#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/socket.h>

#include <assert.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#if __OpenBSD__
#include <sys/select.h>
#endif


#include "bgpq3.h"
#include "sx_report.h"
#include "sx_maxsockbuf.h"

int debug_expander=0;
int pipelining=1;
int expand_as23456=0;
int expand_special_asn=0;

static inline int
tentry_cmp(struct sx_tentry* a, struct sx_tentry* b)
{
	return strcasecmp(a->text, b->text);
};

RB_GENERATE(tentree, sx_tentry, entry, tentry_cmp);

int
bgpq_expander_init(struct bgpq_expander* b, int af)
{
	if(!af) af=AF_INET;
	if(!b) return 0;

	memset(b,0,sizeof(struct bgpq_expander));

	b->tree=sx_radix_tree_new(af);
	if(!b->tree) goto fixups;

	b->family=af;
	b->sources="";
	b->name="NN";
	b->aswidth=8;
	b->asn32s[0]=malloc(8192);
	if(!b->asn32s[0]) {
		sx_report(SX_FATAL,"Unable to allocate 8192 bytes: %s\n",
			strerror(errno));
		exit(1);
	};
	memset(b->asn32s[0],0,8192);
	b->identify=1;
	b->server="whois.radb.net";
	b->port="43";

	STAILQ_INIT(&b->wq);
	STAILQ_INIT(&b->rq);
	STAILQ_INIT(&b->rsets);
	STAILQ_INIT(&b->macroses);

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
	STAILQ_INSERT_TAIL(&b->macroses, le, next);
	return 1;
};

int
bgpq_expander_add_rset(struct bgpq_expander* b, char* rs)
{
	struct sx_slentry* le;
	if(!b || !rs) return 0;
	le=sx_slentry_new(rs);
	if(!le) return 0;
	STAILQ_INSERT_TAIL(&b->rsets, le, next);
	return 1;
};

int
bgpq_expander_add_already(struct bgpq_expander* b, char* rs)
{
	struct sx_tentry* le, lkey;
	lkey.text = rs;
	if (RB_FIND(tentree, &b->already, &lkey))
		return 1;
	le = sx_tentry_new(rs);
	RB_INSERT(tentree, &b->already, le);
	return 1;
};

int
bgpq_expander_add_stop(struct bgpq_expander* b, char* rs)
{
	struct sx_tentry* le, lkey;
	lkey.text = rs;
	if (RB_FIND(tentree, &b->stoplist, &lkey))
		return 1;
	le = sx_tentry_new(rs);
	RB_INSERT(tentree, &b->stoplist, le);
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

	if(*eoa=='.' || asno>65535) {
		if(b->asn32 || b->generation>=T_PREFIXLIST) {
			uint32_t asn1;
			if(asno>65535) {
				asn1=asno%65536;
				asno/=65536;
			} else if(eoa && *(eoa+1)) {
				asn1=strtoul(eoa+1,&eoa,10);
			} else {
				sx_report(SX_ERROR, "Invalid AS number: '%s'\n", as);
				return 0;
			};

			if(eoa && *eoa!=0) {
				sx_report(SX_ERROR,"Invalid symbol in AS number: '%c' in %s\n",
					*eoa, as);
				return 0;
			};
			if(asn1>65535) {
				sx_report(SX_ERROR,"Invalid AS number in %s\n", as);
				return 0;
			};
			if(!expand_special_asn && (((asno*65536+asn1)>=4200000000ul) ||
				((asno*65536+asn1)>=64496 && (asno*65536+asn1) <= 65551))) {
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
		return 1;
	};

	if(asno<1 || asno>65535) {
		sx_report(SX_ERROR,"Invalid AS number in %s\n", as);
		return 0;
	};

	if(asno==23456 && !expand_as23456)
		return 0;

	if(!expand_special_asn && (asno>=64496 && asno <= 65536))
		return 0;

	b->asn32s[0][asno/8]|=(0x80>>(asno%8));

	return 1;
};

int
bgpq_expander_add_prefix(struct bgpq_expander* b, char* prefix)
{
	struct sx_prefix p;
	if(!sx_prefix_parse(&p,0,prefix)) {
		sx_report(SX_ERROR,"Unable to parse prefix %s\n", prefix);
		return 0;
	} else if(p.family!=b->family) {
		SX_DEBUG(debug_expander,"Ignoring prefix %s with wrong address family\n"
			,prefix);
		return 0;
	};
	if(b->maxlen && p.masklen>b->maxlen) {
		SX_DEBUG(debug_expander, "Ignoring prefix %s: masklen %i > max "
			"masklen %u\n", prefix, p.masklen, b->maxlen);
		return 0;
	};
	sx_radix_tree_insert(b->tree,&p);
	return 1;
};

int
bgpq_expander_add_prefix_range(struct bgpq_expander* b, char* prefix)
{
	return sx_prefix_range_parse(b->tree, b->family, b->maxlen, prefix);
};

int
bgpq_expanded_macro(char* as, struct bgpq_expander* ex,
	struct bgpq_request* req)
{
	bgpq_expander_add_as(ex,as);
	return 1;
};

struct bgpq_request* bgpq_pipeline(struct bgpq_expander* b,
	int (*callback)(char*, struct bgpq_expander* b, struct bgpq_request* req),
	void* udata, char* fmt, ...);
int bgpq_expand_irrd(struct bgpq_expander* b,
	int (*callback)(char*, struct bgpq_expander* b, struct bgpq_request* req),
	void* udata, char* fmt, ...);

int
bgpq_expanded_macro_limit(char* as, struct bgpq_expander* b,
	struct bgpq_request* req)
{
	if (!strncasecmp(as, "AS-", 3) || strchr(as, '-') || strchr(as, ':')) {
		struct sx_tentry tkey = { .text = as };
		if (RB_FIND(tentree, &b->already, &tkey)) {
			SX_DEBUG(debug_expander>2,"%s is already expanding, ignore\n", as);
			return 0;
		};
		if (RB_FIND(tentree, &b->stoplist, &tkey)) {
			SX_DEBUG(debug_expander>2,"%s is in the stoplist, ignore\n", as);
			return 0;
		};
		if(!b->maxdepth ||
			(b->cdepth + 1 < b->maxdepth && req->depth + 1 < b->maxdepth)) {
			bgpq_expander_add_already(b,as);
			if (pipelining) {
				struct bgpq_request* req1 = bgpq_pipeline(b,
					bgpq_expanded_macro_limit, NULL, "!i%s\n", as);
				req1->depth = req->depth+1;
			} else {
				b->cdepth++;
				bgpq_expand_irrd(b, bgpq_expanded_macro_limit, NULL, "!i%s\n",
					as);
				b->cdepth--;
			};
		} else {
			SX_DEBUG(debug_expander>2, "ignoring %s at depth %i\n", as,
				b->cdepth?(b->cdepth+1):(req->depth+1));
		};
	} else if(!strncasecmp(as, "AS", 2)) {
		struct sx_tentry tkey = { .text = as };
		if (RB_FIND(tentree, &b->stoplist, &tkey)) {
			SX_DEBUG(debug_expander>2,"%s is in the stoplist, ignore\n", as);
			return 0;
		};
		if(bgpq_expander_add_as(b, as)) {
			SX_DEBUG(debug_expander>2, ".. added asn %s\n", as);
		} else {
			SX_DEBUG(debug_expander, ".. some error adding as %s (in "
				"response to %s)\n", as, req->request);
		};
	} else if (!strcasecmp(as, "ANY")) {
		return 0;
	} else {
		sx_report(SX_ERROR, "unexpected object '%s' in expanded_macro_limit "
			"(in response to %s)\n", as, req->request);
	};
	return 1;
};

int
bgpq_expanded_prefix(char* as, struct bgpq_expander* ex,
	struct bgpq_request* req __attribute__((unused)))
{
	char* d = strchr(as, '^');
	if (!d)
		bgpq_expander_add_prefix(ex,as);
	else
		bgpq_expander_add_prefix_range(ex,as);
	return 1;
};

int
bgpq_expanded_v6prefix(char* prefix, struct bgpq_expander* ex,
	struct bgpq_request* req)
{
	bgpq_expander_add_prefix(ex,prefix);
	return 1;
};

int bgpq_pipeline_dequeue(int fd, struct bgpq_expander* b);

static struct bgpq_request*
bgpq_request_alloc(char* request, int (*callback)(char*, struct bgpq_expander*,
	struct bgpq_request*), void* udata)
{
	struct bgpq_request* bp = malloc(sizeof(struct bgpq_request));
	if (!bp)
		return NULL;
	memset(bp, 0, sizeof(struct bgpq_request));
	bp->request = strdup(request);
	bp->offset = 0;
	bp->size = strlen(bp->request);
	bp->callback = callback;
	bp->udata = udata;
	return bp;
};

static void
bgpq_request_free(struct bgpq_request* req)
{
	if (req->request) free(req->request);
	free(req);
};

struct bgpq_request*
bgpq_pipeline(struct bgpq_expander* b,
	int (*callback)(char*, struct bgpq_expander*, struct bgpq_request*),
	void* udata, char* fmt, ...)
{
	char request[128];
	int ret;
	struct bgpq_request* bp=NULL;
	va_list ap;
	va_start(ap,fmt);
	vsnprintf(request,sizeof(request),fmt,ap);
	va_end(ap);

	SX_DEBUG(debug_expander,"expander: sending %s", request);

	bp = bgpq_request_alloc(request, callback, udata);
	if(!bp) {
		sx_report(SX_FATAL,"Unable to allocate %lu bytes: %s\n",
			(unsigned long)sizeof(struct bgpq_request),strerror(errno));
		exit(1);
	};
	if (STAILQ_EMPTY(&b->wq)) {
		ret=write(b->fd, request, bp->size);
		if (ret < 0) {
			if (errno == EAGAIN) {
				STAILQ_INSERT_TAIL(&b->wq, bp, next);
				return bp;
			};
			sx_report(SX_FATAL, "Error writing request: %s\n", strerror(errno));
		};
		bp->offset=ret;
		if (ret == bp->size) {
			STAILQ_INSERT_TAIL(&b->rq, bp, next);
		} else {
			STAILQ_INSERT_TAIL(&b->wq, bp, next);
		};
	} else
		STAILQ_INSERT_TAIL(&b->wq, bp, next);

	return bp;
};

static void
bgpq_write(struct bgpq_expander* b)
{
	while(!STAILQ_EMPTY(&b->wq)) {
		struct bgpq_request* req = STAILQ_FIRST(&b->wq);
		int ret = write(b->fd, req->request+req->offset, req->size-req->offset);
		if (ret < 0) {
			if (errno == EAGAIN)
				return;
			sx_report(SX_FATAL, "error writing data: %s\n", strerror(errno));
		};

		if (ret == req->size - req->offset) {
			/* this request was dequeued */
			STAILQ_REMOVE_HEAD(&b->wq, next);
			STAILQ_INSERT_TAIL(&b->rq, req, next);
		} else {
			req->offset += ret;
			break;
		};
	};
};

static int
bgpq_selread(struct bgpq_expander* b, char* buffer, int size)
{
	fd_set rfd, wfd;
	int ret;
	struct timeval timeout = {10, 0};

repeat:
	FD_ZERO(&rfd);
	FD_SET(b->fd, &rfd);
	FD_ZERO(&wfd);
	if (!STAILQ_EMPTY(&b->wq))
		FD_SET(b->fd, &wfd);

	ret = select(b->fd+1, &rfd, &wfd, NULL, &timeout);
	if (ret == 0)
		sx_report(SX_FATAL, "select timeout\n");
	else if (ret == -1 && errno == EINTR)
		goto repeat;
	else if (ret == -1)
		sx_report(SX_FATAL, "select error %i: %s\n", errno, strerror(errno));

	if (!STAILQ_EMPTY(&b->wq) && FD_ISSET(b->fd, &wfd))
		bgpq_write(b);

	if (FD_ISSET(b->fd, &rfd))
		return read(b->fd, buffer, size);
	goto repeat;
};

int
bgpq_read(struct bgpq_expander* b)
{
	static char response[256];
	static int off = 0;

	if (!STAILQ_EMPTY(&b->wq))
		bgpq_write(b);

	while(!STAILQ_EMPTY(&b->rq)) {
		struct bgpq_request* req = STAILQ_FIRST(&b->rq);
		SX_DEBUG(debug_expander>2, "waiting for answer to %s, init %i '%.*s'\n",
			req->request, off, off, response);
		int ret = 0;
		char* cres;

		if ((cres=strchr(response, '\n'))!=NULL)
			goto have;
repeat:
		ret = bgpq_selread(b, response+off, sizeof(response)-off);
		if (ret < 0) {
			if (errno == EAGAIN)
				goto repeat;
			sx_report(SX_FATAL,"Error reading data from IRRd: %s (dequeue)\n",
				strerror(errno));
		} else if (ret == 0) {
			sx_report(SX_FATAL,"EOF from IRRd (dequeue)\n");
		};
		off += ret;

		if (!(cres=strchr(response, '\n')))
			goto repeat;
have:
		SX_DEBUG(debug_expander>5, "got response of %.*s\n", off, response);
		if(response[0]=='A') {
			char* eon, *c;
			unsigned long togot=strtoul(response+1,&eon,10);
			char* recvbuffer=malloc(togot+2);
			int offset = 0;
			memset(recvbuffer,0,togot+2);

			if(!eon || *eon!='\n') {
				sx_report(SX_ERROR,"A-code finished with wrong char '%c'(%s)\n",
					eon?*eon:'0',response);
				exit(1);
			};

			if (off - ((eon+1) - response) > togot) {
				/* full response and more data is already in buffer */
				memcpy(recvbuffer, eon+1, togot);
				offset = togot;
				memmove(response, eon+1+togot, off-((eon+1)-response)-togot);
				off -= togot + ((eon+1)-response);
				memset(response+off, 0, sizeof(response)-off);
			} else {
				/* response is not yet fully buffered */
				memcpy(recvbuffer, eon+1, off - ((eon+1)-response));
				offset = off - ((eon+1) - response);
				memset(response, 0, sizeof(response));
				off = 0;
			};

			SX_DEBUG(debug_expander>5,
				"starting read with ready '%.*s', waiting for %lu\n",
				offset, recvbuffer, togot-offset);

			if (off > 0)
				goto have3;
			if (offset == togot)
				goto reread2;
reread:

			ret = bgpq_selread(b, recvbuffer+offset, togot-offset);
			if (ret < 0) {
				if (errno == EAGAIN)
					goto reread;
				sx_report(SX_FATAL,"Error reading IRRd: %s (dequeue, result)\n",
					strerror(errno));
			} else if (ret == 0) {
				sx_report(SX_FATAL,"EOF from IRRd (dequeue, result)\n");
			};
			SX_DEBUG(debug_expander>5,
				"Read1: got '%.*s'\n", ret, recvbuffer+offset);
			offset+=ret;
			if(offset < togot) {
				SX_DEBUG(debug_expander>5, "expected %lu, got %lu expanding %s",
					togot, strlen(recvbuffer), req->request);
				goto reread;
			};
reread2:
			ret = bgpq_selread(b, response+off, sizeof(response) - off);
			if (ret < 0) {
				if (errno == EAGAIN)
					goto reread2;
				sx_report(SX_FATAL,"Error reading IRRd: %s (dequeue,final)\n",
					strerror(errno));
			} else if (ret == 0) {
				sx_report(SX_FATAL,"EOF from IRRd (dequeue,final)\n");
			};
			SX_DEBUG(debug_expander>5,
				"Read2: got '%.*s'\n", ret, response+off);
			off+=ret;

have3:
			if (!(cres = strchr(response, '\n')))
				goto reread2;

			SX_DEBUG(debug_expander>=3,"Got %s (%lu bytes of %lu) in response "
				"to %sfinal code: %.*s",recvbuffer,strlen(recvbuffer),togot,
				req->request,off,response);

			for(c=recvbuffer; c<recvbuffer+togot;) {
				size_t spn=strcspn(c," \n");
				if(spn) c[spn]=0;
				if(c[0]==0) break;
				req->callback(c, b, req);
				c+=spn+1;
			};
			assert(c == recvbuffer+togot);
			memset(recvbuffer,0,togot+2);
			free(recvbuffer);
		} else if(response[0]=='C') {
			/* No data */
			SX_DEBUG(debug_expander,"No data expanding %s\n", req->request);
		} else if(response[0]=='D') {
			/* .... */
			SX_DEBUG(debug_expander,"Key not found expanding %s\n",
				req->request);
		} else if(response[0]=='E') {
			sx_report(SX_ERROR, "Multiple keys expanding %s: %s\n",
				req->request, response);
		} else if(response[0]=='F') {
			sx_report(SX_ERROR, "Error expanding %s: %s\n",
				req->request, response);
		} else {
			sx_report(SX_ERROR,"Wrong reply: %s to %s\n", response,
				req->request);
			exit(1);
		};
		memmove(response, cres+1, off-((cres+1)-response));
		off -= (cres+1)-response;
		memset(response+off, 0, sizeof(response) - off);
		SX_DEBUG(debug_expander>5,
			"fixed response of %i, %.*s\n", off, off, response);

		STAILQ_REMOVE_HEAD(&b->rq, next);
		b->piped--;
		bgpq_request_free(req);
	};
	return 0;
};

int
bgpq_expand_irrd(struct bgpq_expander* b,
	int (*callback)(char*, struct bgpq_expander*, struct bgpq_request* ),
	void* udata, char* fmt, ...)
{
	char request[128], response[128];
	va_list ap;
	int ret, off = 0;
	struct bgpq_request *req;

	va_start(ap,fmt);
	vsnprintf(request,sizeof(request),fmt,ap);
	va_end(ap);

	req = bgpq_request_alloc(request, callback, udata);

	SX_DEBUG(debug_expander,"expander: sending '%s'\n", request);

	ret=write(b->fd, request, strlen(request));
	if(ret!=strlen(request)) {
		sx_report(SX_FATAL,"Partial write to IRRd, only %i bytes written: %s\n",
			ret, strerror(errno));
		exit(1);
	};
	memset(response,0,sizeof(response));

repeat:
	ret = bgpq_selread(b, response+off, sizeof(response)-off);
	if (ret < 0) {
		sx_report(SX_ERROR, "Error reading IRRd: %s\n", strerror(errno));
		exit(1);
	} else if (ret == 0) {
		sx_report(SX_FATAL, "EOF reading IRRd\n");
		exit(1);
	};
	off += ret;

	if (strchr(response, '\n') == NULL)
		goto repeat;

	SX_DEBUG(debug_expander>2,"expander: initially got %lu bytes, '%s'\n",
		(unsigned long)strlen(response),response);
	if(response[0]=='A') {
		char* eon, *c;
		long togot=strtoul(response+1,&eon,10);
		char recvbuffer[togot+2];
		int  offset = 0;

		if(eon && *eon!='\n') {
			sx_report(SX_ERROR,"A-code finised with wrong char '%c' (%s)\n",
				*eon,response);
			exit(1);
		};

		if (off - ((eon+1)-response) > togot) {
			memcpy(recvbuffer, eon+1, togot);
			offset = togot;
			memmove(response, eon+1+togot, off - ((eon+1)-response) - togot);
			off -= togot + ((eon+1)-response);
			memset(response+off, 0, sizeof(response)-off);
		} else {
			memcpy(recvbuffer, eon+1, off - ((eon+1)-response));
			offset = off - ((eon+1) - response);
			memset(response, 0, sizeof(response));
			off = 0;
		};

		if (off > 0)
			goto have3;
		if (offset == togot)
			goto reread2;

reread:
		ret = bgpq_selread(b, recvbuffer+offset, togot-offset);
		if (ret == 0) {
			sx_report(SX_FATAL,"EOF from IRRd (expand,result)\n");
		} else if (ret < 0) {
			sx_report(SX_FATAL,"Error reading IRRd: %s (expand,result)\n",
				strerror(errno));
		};
		offset += ret;
		if (offset < togot)
			goto reread;

reread2:
		ret = bgpq_selread(b, response+off, sizeof(response)-off);
		if (ret < 0) {
			sx_report(SX_FATAL, "error reading IRRd: %s\n", strerror(errno));
			exit(1);
		} else if (ret == 0) {
			sx_report(SX_FATAL, "eof reading IRRd\n");
			exit(1);
		};
		off += ret;
have3:
		if (!strchr(response, '\n'))
			goto reread2;

		SX_DEBUG(debug_expander>2,"expander: final reply of %lu bytes, "
			"%.*sreturn code %.*s",
			(unsigned long)strlen(recvbuffer), offset, recvbuffer, off,
			response);

		for(c=recvbuffer; c<recvbuffer+togot;) {
			size_t spn=strcspn(c," \n");
			if(spn) c[spn]=0;
			if(c[0]==0) break;
			if(callback) callback(c, b, req);
			c+=spn+1;
		};
		memset(recvbuffer, 0, togot+2);
	} else if(response[0]=='C') {
		/* no data */
	} else if(response[0]=='D') {
		/* ... */
	} else if(response[0]=='E') {
		/* XXXXXX */
	} else if(response[0]=='F') {
		/* XXXXXX */
	} else {
		sx_report(SX_ERROR,"Wrong reply: %s\n", response);
		exit(0);
	};
	bgpq_request_free(req);
	return 0;
};

int
bgpq_expand(struct bgpq_expander* b)
{
	int fd=-1, err, ret;
	struct sx_slentry* mc;
	struct addrinfo hints, *res=NULL, *rp;
	memset(&hints,0,sizeof(struct addrinfo));

	hints.ai_socktype=SOCK_STREAM;

	err=getaddrinfo(b->server,b->port,&hints,&res);
	if(err) {
		sx_report(SX_ERROR,"Unable to resolve %s: %s\n",
			b->server, gai_strerror(err));
		exit(1);
	};

	for(rp=res; rp; rp=rp->ai_next) {
		fd=socket(rp->ai_family,rp->ai_socktype,0);
		if(fd==-1) {
			if(errno==EPROTONOSUPPORT || errno==EAFNOSUPPORT) continue;
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
		err=sx_maxsockbuf(fd,SO_SNDBUF);
		if(err>0) {
			SX_DEBUG(debug_expander, "Acquired sendbuf of %i bytes\n", err);
		} else {
			shutdown(fd, SHUT_RDWR);
			close(fd);
			fd=-1;
			continue;
		};
		break;
	};
	freeaddrinfo(res);

	if(fd == -1) {
		/* all our attempts to connect failed */
		sx_report(SX_ERROR,"All attempts to connect %s failed, last"
			" error: %s\n", b->server, strerror(errno));
		exit(1);
	};

	b->fd = fd;

	if((ret=write(fd, "!!\n", 3))!=3) {
		sx_report(SX_ERROR,"Partial write to IRRd: %i bytes, %s\n",
			ret, strerror(errno));
		exit(1);
	};

	if(b->sources && b->sources[0]!=0) {
		char sources[128];
		snprintf(sources,sizeof(sources),"!s%s\n", b->sources);
		SX_DEBUG(debug_expander,"Requesting sources %s", sources);
		write(fd, sources, strlen(sources));
		memset(sources, 0, sizeof(sources));
		read(fd, sources, sizeof(sources));
		SX_DEBUG(debug_expander,"Got answer %s", sources);
		if(sources[0]!='C') {
			sx_report(SX_ERROR, "Invalid source(s) '%s': %s\n", b->sources,
				sources);
			exit(1);
		};
	};

	if(b->identify) {
		char ident[128];
		snprintf(ident,sizeof(ident),"!n" PACKAGE_STRING "\n");
		write(fd, ident, strlen(ident));
		read(fd, ident, sizeof(ident));
	};

	if (pipelining)
		fcntl(fd, F_SETFL, O_NONBLOCK|(fcntl(fd, F_GETFL)));

	STAILQ_FOREACH(mc, &b->macroses, next) {
		if (!b->maxdepth && RB_EMPTY(&b->stoplist)) {
			bgpq_expand_irrd(b, bgpq_expanded_macro, b, "!i%s,1\n", mc->text);
		} else {
			bgpq_expander_add_already(b,mc->text);
			if (pipelining) {
				bgpq_pipeline(b, bgpq_expanded_macro_limit, NULL, "!i%s\n",
					mc->text);
			} else {
				bgpq_expand_irrd(b, bgpq_expanded_macro_limit, NULL, "!i%s\n",
					mc->text);
			};
		};
	};

	if(pipelining) {
		if(!STAILQ_EMPTY(&b->wq))
			bgpq_write(b);
		if (!STAILQ_EMPTY(&b->rq))
			bgpq_read(b);
	};

	if(b->generation>=T_PREFIXLIST) {
		unsigned i, j, k;
		STAILQ_FOREACH(mc, &b->rsets, next) {
			if(b->family==AF_INET) {
				bgpq_expand_irrd(b, bgpq_expanded_prefix, NULL, "!i%s,1\n",
					mc->text);
			} else {
				bgpq_expand_irrd(b, bgpq_expanded_v6prefix, NULL, "!i%s,1\n",
					mc->text);
			};
		};
		for(k=0;k<sizeof(b->asn32s)/sizeof(unsigned char*);k++) {
			if(!b->asn32s[k]) continue;
			for(i=0;i<8192;i++) {
				for(j=0;j<8;j++) {
					if(b->asn32s[k][i]&(0x80>>j)) {
						if(b->family==AF_INET6) {
							if(!pipelining) {
								if(k>0)
									bgpq_expand_irrd(b, bgpq_expanded_v6prefix,
										NULL, "!6as%u.%u\r\n", k, i*8+j);
								else
									bgpq_expand_irrd(b, bgpq_expanded_v6prefix,
										NULL,"!6as%u\r\n", i*8+j);
							} else {
								if(k>0)
									bgpq_pipeline(b, bgpq_expanded_v6prefix,
										NULL, "!6as%u.%u\r\n", k, i*8+j);
								else
									bgpq_pipeline(b,bgpq_expanded_v6prefix,
										NULL, "!6as%u\r\n", i*8+j);
							};
						} else {
							if(!pipelining) {
								if(k>0)
									bgpq_expand_irrd(b, bgpq_expanded_prefix,
										NULL,"!gas%u.%u\n", k, i*8+j);
								else
									bgpq_expand_irrd(b, bgpq_expanded_prefix,
										NULL,"!gas%u\n", i*8+j);
							} else {
								if(k>0)
									bgpq_pipeline(b, bgpq_expanded_prefix,
										NULL, "!gas%u.%u\n", k, i*8+j);
								else
									bgpq_pipeline(b, bgpq_expanded_prefix,
										NULL, "!gas%u\n", i*8+j);
							};
						};
					};
				};
			};
		};
		if(pipelining) {
			if(!STAILQ_EMPTY(&b->wq))
				bgpq_write(b);
			if (!STAILQ_EMPTY(&b->rq))
				bgpq_read(b);
		};
	};

	write(fd, "!q\n",3);
	shutdown(fd, SHUT_RDWR);
	close(fd);
	return 1;
};

