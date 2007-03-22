#ifndef SX_REPORT_H_
#define SX_REPORT_H_

typedef enum { 
	SX_DEBUG = 0,
	SX_NOTICE,
	SX_ERROR,
	SX_MISFEATURE,
	SX_FATAL
} sx_report_t;

/* opens syslog and disables logging to stderr */
void sx_openlog(char* progname);

int  sx_report(sx_report_t, char* fmt, ...) 
	__attribute__ ((format (printf, 2, 3)));

int sx_debug(char const* const, char const* const, int const, char* fmt, ...)
	__attribute__ ((format (printf, 4, 5)));

#define SX_DEBUG(a,b,c...) if(a) sx_debug(__FILE__,__FUNCTION__,__LINE__,\
	b, ## c);

#endif
