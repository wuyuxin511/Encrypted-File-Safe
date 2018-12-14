#ifndef _UTILS_H
#define _UTILS_H

#include "safebox.h"
#include <inttypes.h>
#include <stdio.h>

int get_raw_key(tgtdefn_t *tgt, uint8_t **key, int *keylen);
                
void *sec_realloc(void *ptr, size_t size);
void mem_cleanse(uint8_t *addr, size_t sz);
void sec_free(void *ptr);

int64_t getblk512count(const char *device, int *blklen);

size_t mk_key_string(const uint8_t *key, const size_t keylen,
                     char *buff);

#endif /* _UTILS_H */
