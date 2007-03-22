#ifndef SX_SLENTRY_H_
#define SX_SLENTRY_H_

struct sx_slentry { 
	struct sx_slentry* next;
	char*  text;
};

struct sx_slentry* sx_slentry_new(char* text);

#endif
