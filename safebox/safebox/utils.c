#include "utils.h"
#include "safebox.h"

int get_raw_key(tgtdefn_t *tgt, uint8_t **key, int *keylen)
/** Extract key from unencrypted (plain) file */
{
    const keyinfo_t *keyinfo = &tgt->key;
    FILE *fp_key = NULL;
    enum
    {
        BUFFSZ = 512
    };
    char buff[BUFFSZ];
    size_t len, lmt;
    int eflag = ERR_NOERROR;

    if (keyinfo->filename != NULL)
    {
        fp_key = fopen(keyinfo->filename, "rb");
        if (fp_key == NULL)
        {
            fprintf(stderr,
                    _("Failed to open keyfile \"%s\" for target \"%s\"\n"),
                    keyinfo->filename, tgt->ident);
            eflag = ERR_BADFILE;
            goto bail_out;
        }
    }
    else
    {
        fprintf(stderr, _("Missing keyfile for target \"%s\"\n"), tgt->ident);
        eflag = ERR_BADFILE;
        goto bail_out;
    }

    *key = NULL;
    *keylen = 0;

    if (fp_key == NULL)
    {
        eflag = ERR_BADFILE;
        goto bail_out;
    }

    /* Read data directly from keyfile: */
    for (;;)
    {
        lmt = (keyinfo->maxlen > 0 && (*keylen + BUFFSZ) > keyinfo->maxlen
                   ? (size_t)(keyinfo->maxlen - *keylen)
                   : (size_t)BUFFSZ);
        len = fread((void *)buff, (size_t)1, (size_t)lmt, fp_key);
        if (len == 0)
            break;

        /* Copy new block of data onto end of current key: */
        *key = (uint8_t *)sec_realloc((void *)*key, (size_t)(*keylen + len));
        memcpy((void *)(*key + *keylen), (const void *)buff, len);
        *keylen += len;
    }

    if (ferror(fp_key) != 0)
    {
        fprintf(stderr, _("Key-extraction failed for \"%s\"\n"),
                keyinfo->filename);
        /* This is a trivial case of decryption failure: */
        eflag = ERR_BADDECRYPT;
    }

bail_out:

    return eflag;
}

int64_t getblk512count(const char *device, int *blklen)
/** Find size of raw device in blocks of size 512-bytes */
{
    int64_t count = -1;
    int fd;
#ifndef BLKGETSIZE64
    long len;
#endif

    *blklen = 512;
    fd = open(device, O_RDONLY);
    if (fd < 0)
        return (int64_t)-1;

#ifdef BLKGETSIZE64
    if (ioctl(fd, BLKGETSIZE64, &count) == 0 && ioctl(fd, BLKSSZGET, blklen) == 0)
    {
        count /= (int64_t)512;
    }
    else
    {
        count = -1;
    }
#else
    if (ioctl(fd, BLKGETSIZE, &len) == 0)
    {
        /*  This directly gives the number of 512-byte blocks */
        count = (int64_t)len;
    }
#endif

    (void)close(fd);
    return count;
}

size_t mk_key_string(const uint8_t *key, const size_t keylen, char *buff)
/** Create text version of crypto key */
{
    size_t i;

    for (i = 0; i < keylen; ++i)
    {
        sprintf(buff + 2 * i, "%02x", (unsigned)(key[i]));
    }

    return (2 * keylen);
}

void *sec_realloc(void *ptr, size_t size)
/** Slightly more secure version of realloc() */
{
    size_t cnt, *memarr;

    cnt = (size + 2 * sizeof(size_t) - 1) / sizeof(size_t);
    memarr = (size_t *)calloc(cnt, sizeof(size_t));

    if (memarr == NULL)
    {
        fprintf(stderr, _("Unable to allocate memory\n"));
        abort();
        return NULL;
    }

    /* Prepend usable memory chunk with record of size of chunk: */
    memarr[0] = (cnt - 1) * sizeof(size_t);

    if (ptr != NULL)
    {
        size_t oldsz;

        /* Copy (usable) part of old memory block into new: */
        oldsz = *(((size_t *)ptr) - 1);
        if (oldsz > size)
            oldsz = size;
        memcpy((void *)(memarr + 1), (const void *)ptr, oldsz);

        /* Dispose of old memory block: */
        sec_free(ptr);
    }

    return (void *)(memarr + 1);
}

void mem_cleanse(uint8_t *addr, size_t sz)
/** Overwrite memory with (weak) pseudo-random numbers */
{
    size_t i;
    static unsigned long salt = 0x917c;

    salt ^= (unsigned long)addr;

    for (i = 0; i < sz; ++i)
    {
        addr[i] = (i % 21) ^ (salt % 221);
        salt += 4;
    }
}

void sec_free(void *ptr)
/** Slightly more secure version of free() */
{
    size_t *memarr, sz;

    if (ptr == NULL)
        return;

    memarr = ((size_t *)ptr) - 1;
    sz = memarr[0];

    mem_cleanse((uint8_t *)(memarr + 1), sz);

    free((void *)memarr);
}
