#include "binscan.h"
#include <string.h>

void* mallocz(size_t size)
{
	void* p = malloc(size);
	if (!p) return NULL;
	memset(p, 0, size);
	return p;
}

typedef struct _binscan_vec binscan_vec_t;
struct _binscan_vec {
	void* buf;
	size_t length;
	size_t capacity;
	size_t elem_size;	
};

binscan_vec_t* binscan_vec_grow(binscan_vec_t* v, size_t new_cap)
{
	void* tmp = NULL;
	if (!v->buf) {
		tmp = mallocz(new_cap * v->elem_size);
	}
	else {
		tmp = realloc(v->buf, new_cap * v->elem_size);
	}

	if (!tmp) {
		fprintf(stderr, "allocation failed in binscan_vec_grow");
		free(v->buf);
		exit(EXIT_FAILURE);
	}
	
	v->buf = tmp;
	v->capacity = new_cap;
}

binscan_vec_t* binscan_vec_new(size_t elem_size)
{
	binscan_vec_t* v = mallocz(sizeof(binscan_vec_t));
	if (!v) return NULL;
	v->elem_size = elem_size;
	return v;
}

void binscan_vec_delete(binscan_vec_t* v)
{
	if (!v) return;
	if (v->buf) free(v->buf);
	free(v);
}

void* binscan_vec_push(binscan_vec_t* v)
{
	if (v->length + 1 > v->capacity) {
		binscan_vec_grow(v, (v->capacity * 2) + 1);
	}

	void* e = v->buf + (v->length++ * v->elem_size);
	memset(e, 0, v->elem_size);
	return e;
}

void binscan_vec_pop(binscan_vec_t* v)
{
	if (v->length == 0) return;

	void* e = v->buf + (--v->length * v->elem_size);
	memset(e, 0, v->elem_size); // memset
}

void* binscan_vec_at(binscan_vec_t* v, size_t i)
{
	if (i > v->length) return NULL;

	return v->buf + (i * v->elem_size);
}

typedef struct _binscan_sig binscan_sig_t;
struct _binscan_sig {
	const char* pattern;
	int uid;
	char first_byte; // first "matchable" byte
	int offset; // offset (usually negative) for how many characters to go back in stream. i.e. if pattern starts with ?? ?? EE then offset=-2
	char* bytes; // parsed byte stream from "pattern".
	//uint32_t* mask; // bitmask for which bytes are wildcards in "bytes". One uint32_t per 32 characters. 
	char* mask; // 0=byte, 1=wildcard
	size_t bytes_len; // length of "bytes", required because bytes can contain NULL characters.
};


#define BINSCAN_FLAG_ZERO			1 << 0
#define BINSCAN_FLAG_USEFILE		1 << 1
#define BINSCAN_FLAG_OWNFILE		1 << 2
#define BINSCAN_FLAG_USEBUF			1 << 3

// Can be predefined with compiler flag
#ifndef BINSCAN_CHUNKSIZE
#define BINSCAN_CHUNKSIZE			1024 * 8
#endif

struct _binscan {
	int flags;
	union {
		struct {
			const char* filename;
			FILE* stream;
			
			size_t addr_ac; // address accumulator
			size_t index;
			char* prevchunk;
			size_t prevchunk_size;
			char* curchunk;
			size_t curchunk_size;
			char* preloadchunk;
			size_t preloadchunk_size;
		};
		struct {
			const char* buf;
			size_t buf_size;
		};
	} content;

	binscan_vec_t* signatures; 
	binscan_vec_t* matches;
	int match_index;
	size_t chunksize;
};


binscan_t* binscan_new()
{
	binscan_t* b = mallocz(sizeof(binscan_t));
	if (!b) return NULL;

	BINSCAN_SET(b->flags, BINSCAN_FLAG_ZERO);
	b->signatures = binscan_vec_new(sizeof(binscan_sig_t));
	b->matches = binscan_vec_new(sizeof(binscan_match_t));
	b->chunksize = BINSCAN_CHUNKSIZE;
	return b;
}

void binscan_delete(binscan_t* b)
{
	if (!b) return;

	if (BINSCAN_ISSET(b->flags, BINSCAN_FLAG_OWNFILE)) {
		fclose(b->content.stream);
	}

	// Delete contents in vectors
	for (size_t i = 0; i < b->signatures->length; ++i) {
		binscan_sig_t* sig = (binscan_sig_t*)binscan_vec_at(b->signatures, i);

		if (sig->bytes) free(sig->bytes);
		if (sig->mask) free(sig->mask);
	}
	
	// Delete vecs
	binscan_vec_delete(b->signatures);
	binscan_vec_delete(b->matches);
	free(b);
}

size_t binscan_getchunksize(binscan_t* b) { return b->chunksize; }

void binscan_setchunksize(binscan_t* b, size_t s)
{
	b->chunksize = s;
}

int binscan_usefile(binscan_t* b, FILE* f)
{
	if (!f) return 0;

	BINSCAN_SET(b->flags, BINSCAN_FLAG_USEFILE);
	b->content.stream = f;
	return 1;
}

int binscan_openfile(binscan_t* b, const char* filename)
{
	FILE* f = fopen(filename, "rb");
	if (!f) return 0;

	BINSCAN_SET(b->flags, BINSCAN_FLAG_USEFILE|BINSCAN_FLAG_OWNFILE);
	b->content.stream = f;
	return 1;
}

int binscan_usebuf(binscan_t* b, const char* buf, size_t length)
{
	BINSCAN_SET(b->flags, BINSCAN_FLAG_USEBUF);
	b->content.buf = buf;
	b->content.buf_size = length;
	if (length == 0) {
		b->content.buf_size = strlen(buf);
	}

	return 1;
}	

void binscan_suggest(binscan_t* b, size_t suggested_size)
{
	binscan_vec_grow(b->signatures, suggested_size + 1);
}

size_t strcnt(const char* haystack, char needle)
{
	size_t matches = 0;
	while (*haystack) {
		if (*haystack++ == needle) {
			++matches;
		}
	}

	return matches;
}

int binscan_parse(binscan_sig_t* sig)
{
	// ascii		H  e  l  ?  o
	// pattern		48 65 6C ?? 6F	(5 bytes + 0-term)
	// bytes		48 65 6C 00 6f	(5 bytes)
	// mask			0  0  0  1  0 	(one int)
	
	// copy the string temporarily (cause strtok)
	const char* delim = " ";
	const char* wildcard = "??";

	char* pattern = strdup(sig->pattern);
	sig->bytes_len = strcnt(pattern, ' ') + 1;
	sig->mask = mallocz(sig->bytes_len + 1);
	sig->bytes = mallocz(sig->bytes_len + 1);

	char* mask = sig->mask;
	char* bytes = sig->bytes;
	int found_first_byte = 0;

	// tokenize the stream
	char* token = strtok(pattern, delim);
	while (token != NULL) {
		if (strcmp(token, wildcard) == 0) {
			*mask = 1;			
			*bytes = 0;
		}
		else {
			*mask = 0;
			*bytes = strtol(token, NULL, 16);

			// Prevent needless looking if starts with N amount of wildcards.
			if (!found_first_byte) {
				sig->first_byte = *bytes;
				sig->offset = sig->bytes - bytes;
				found_first_byte = 1;
			}
		}

		token = strtok(NULL, delim);
		++mask;
		++bytes;
	}

	free(pattern);
	return 1;
}

int binscan_register(binscan_t* b, int uid, const char* pattern)
{
	binscan_sig_t* sig = binscan_vec_push(b->signatures);
	if (!sig) return 0;
	sig->pattern = pattern;
	sig->uid = uid;
	
	if (!binscan_parse(sig)) {
		binscan_vec_pop(b->signatures);
		return 0;
	}

	return 1;
}

int binscan_read_chunk(binscan_t* b, char* buf)
{
	return fread(buf, sizeof(char), b->chunksize, b->content.stream);
}

int binscan_sig_match(const char* bytes, const char* sig, const char* mask, size_t siglen)
{
	const char* sigend = sig + siglen;
	while (sig != sigend) {
		if (*mask == 1) {} // wildcard
		else if (*bytes != *sig) {
			return 0;
		}
		
		++bytes;
		++sig;
		++mask;
	}

	return 1;
}	

int binscan_sig_chunked_match(
	const char* chunk1_begin,
	const char* chunk1_end,
	const char* chunk2_begin,
	const char* chunk2_end,
	const char* sig,
	const char* mask,
	size_t bytes_len)
{
	if (!binscan_sig_match(chunk1_begin, sig, mask, chunk1_end - chunk1_begin)) {
		return 0;
	}

	size_t ofs = chunk1_end - chunk1_begin;
	bytes_len -= ofs;
	sig += ofs;
	mask += ofs;

	if (!binscan_sig_match(chunk2_begin, sig, mask, bytes_len)) {
		return 0;
	}

	return 1; // It matched.
}

int binscan_exec_fileptr(binscan_t* b)
{
	if (!b->signatures->length) return 0;


	// Allocate chunk data
	b->content.prevchunk = mallocz(b->chunksize + 1);
	b->content.curchunk = mallocz(b->chunksize + 1);
	b->content.preloadchunk = mallocz(b->chunksize + 1);
	b->content.curchunk_size = binscan_read_chunk(b, b->content.curchunk);	

	if (b->signatures->length > 100) {
		binscan_vec_grow(b->matches, 100);
	}
	else {
		binscan_vec_grow(b->matches, b->signatures->length);
	}

	int matches = 0;
	while (1) {
		char *byte = &b->content.curchunk[b->content.index];		
	
		for (size_t i = 0; i < b->signatures->length; ++i) {
			binscan_sig_t* sig = (binscan_sig_t*)binscan_vec_at(b->signatures, i);

			if (sig->first_byte == *byte) {
				// Perform matching algorithm
				if (sig->bytes_len > (b->content.curchunk_size - b->content.index)) {
					// complex matching, we'll need to preload the next chunk (but only if previous sig hasn't already preloaded it).
					if (b->content.preloadchunk_size == 0) {
						b->content.preloadchunk_size = binscan_read_chunk(b, b->content.preloadchunk);
						if (b->content.preloadchunk_size == 0) {
							continue; // continue to next signature, this one can't be matched because it is too long for the rest of the content.
						}
					}

					if (binscan_sig_chunked_match(
							byte + sig->offset,
							b->content.curchunk + b->content.curchunk_size,
							b->content.preloadchunk,
							b->content.preloadchunk + b->content.preloadchunk_size,
							sig->bytes,
							sig->mask,
							sig->bytes_len
						)) {
						++matches;
						binscan_match_t* match = binscan_vec_push(b->matches);
						match->signature = sig->pattern;
						match->uid = sig->uid;
						match->addr = b->content.addr_ac + sig->offset;
					}
				}
				else if (b->content.index < abs(sig->offset)) {
					// need to start matching from prevchunk into curchunk.
					if (b->content.prevchunk_size == 0) {
						break; // we are still on the first chunk, a match is impossible.
					}

					if (binscan_sig_chunked_match(
							b->content.prevchunk + b->content.prevchunk_size + sig->offset,
							b->content.prevchunk + b->content.prevchunk_size,
							byte,
							b->content.curchunk + b->content.curchunk_size,
							sig->bytes,
							sig->mask,
							sig->bytes_len
						)) {
						++matches;

						binscan_match_t* match = binscan_vec_push(b->matches);
						match->signature = sig->pattern;
						match->uid = sig->uid;
						match->addr = b->content.addr_ac + sig->offset;
					}
				}
				else {
					if (binscan_sig_match(byte + sig->offset, sig->bytes, sig->mask, sig->bytes_len)) {
						++matches;

						binscan_match_t* match = binscan_vec_push(b->matches);
						match->signature = sig->pattern;
						match->uid = sig->uid;
						match->addr = b->content.addr_ac + sig->offset;
					}
				}
			}

					// no match
		}	
		
		++b->content.addr_ac;
		++b->content.index;

		if (b->content.index >= b->content.curchunk_size) {
			if (b->content.preloadchunk_size == 0) {
				b->content.preloadchunk_size = binscan_read_chunk(b, b->content.preloadchunk);

				if (b->content.preloadchunk_size == 0) break; // end of file.
			}	
			// swap curchunk to prevchunk, and then preloadchunk to curchunk making prevchunk=preloadchunk
			char* tmpchunk = b->content.prevchunk;
			b->content.prevchunk = b->content.curchunk;
			b->content.prevchunk_size = b->content.curchunk_size;
			b->content.curchunk = b->content.preloadchunk;
			b->content.curchunk_size = b->content.preloadchunk_size;

			// but set the size to 0 so the next time we need to preload a chunk we know it's not been "preloaded" already.
			b->content.preloadchunk = tmpchunk;
			b->content.preloadchunk_size = 0;
				
			b->content.index = 0; // Reset the index back to 0.
		}
	}

	free(b->content.prevchunk);
	free(b->content.curchunk);
	free(b->content.preloadchunk);
	return matches;
}

int binscan_exec_bufptr(binscan_t* b)
{
	// This should be fairly simple.
	
	int matches = 0;
	const char* byte = b->content.buf;
	while (byte != (b->content.buf + b->content.buf_size)) {
		for (size_t i = 0; i < b->signatures->length; ++i) {
			binscan_sig_t* sig = (binscan_sig_t*)binscan_vec_at(b->signatures, i);

			if (sig->first_byte == *byte) {
				if (binscan_sig_match(byte + sig->offset, sig->bytes, sig->mask, sig->bytes_len)) {
					++matches;
					binscan_match_t* match = binscan_vec_push(b->matches);
					match->signature = sig->pattern;
					match->uid = sig->uid;
					match->addr = b->content.addr_ac + sig->offset;
				}
			}
		}

		++byte;
	}
	
	return matches;
}

int binscan_exec(binscan_t* b)
{
	if (BINSCAN_ISSET(b->flags, BINSCAN_FLAG_USEFILE)) {
		return binscan_exec_fileptr(b);
	}
	else if (BINSCAN_ISSET(b->flags, BINSCAN_FLAG_USEBUF)) {
		return binscan_exec_bufptr(b);
	}

	return 0;
}

binscan_match_t* binscan_next(binscan_t* b)
{
	if (b->match_index >= b->matches->length) return NULL;
	return (binscan_match_t*)binscan_vec_at(b->matches, b->match_index++);
}
