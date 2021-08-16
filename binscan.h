#ifndef BINSCAN_H
#define BINSCAN_H
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#define BINSCAN_SET(v, f) v |= (f)
#define BINSCAN_UNSET(v, f) v &= ~(f)
#define BINSCAN_ISSET(v, f) (((v) & (f)) == (f))

typedef struct _binscan binscan_t;
typedef struct _binscan_match binscan_match_t;
struct _binscan_match {
	const char* signature;
	int uid;
	size_t addr;
};

// new binscan state
binscan_t*			binscan_new(void);
void 				binscan_delete(binscan_t*);
size_t				binscan_getchunksize(binscan_t*);
void				binscan_setchunksize(binscan_t*, size_t);

// content operations
int					binscan_usefile(binscan_t*, FILE*); // use file stream (you must close it yourself after binscan_exec)
int					binscan_openfile(binscan_t*, const char* filename); // open a file for use
int					binscan_usebuf(binscan_t*, const char* buf, size_t length); // use a predefined buffer, length is optional but recommended.

// signatures
void				binscan_suggest(binscan_t*, size_t); // suggest a predefined size of signatures to optimise proceeding calls to binscan_register
int					binscan_register(binscan_t*, int uid, const char* pattern); // register a signature

// scan
int					binscan_exec(binscan_t*); // returns total detected signatures
binscan_match_t*	binscan_next(binscan_t*);

#ifdef __cplusplus
}
#endif
#endif
