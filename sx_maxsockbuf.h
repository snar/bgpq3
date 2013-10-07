#ifndef SX_MAXSOCKBUF_H_
#define SX_MAXSOCKBUF_H_

/* s - number of opened socket, dir is either SO_SNDBUF or SO_RCVBUF */
int sx_maxsockbuf(int s, int dir);

#endif

