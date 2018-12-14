#include <sys/mman.h>
#include "safebox.h"
#include "utils.h"
#include "looputils.h"
#include "dmutils.h"
#include "fsutils.h"

// Overall target definition
static tgtdefn_t *tgt_g = NULL;

// Prepare target object
void prepare_tgt(const char *name, char* dev, char *dir, char *fstype,
                char *cipher, char *key, int keylen)
{
    tgt_g = (tgtdefn_t *)malloc(sizeof(tgtdefn_t));
    strcpy(tgt_g->ident = (char *)malloc(strlen(name) + 1), name);
    strcpy(tgt_g->dev = (char *)malloc(strlen(dev) + 1), dev);
    tgt_g->start = 0;
    tgt_g->length = -1;
    strcpy(tgt_g->dir = (char *)malloc(strlen(dir) + 1), dir);
    strcpy(tgt_g->fstype = (char *)malloc(strlen(fstype) + 1), fstype);
    tgt_g->mountoptions = NULL;
    tgt_g->fsckoptions = NULL;
    tgt_g->loopdev = NULL;
    tgt_g->supath = NULL;
    strcpy(tgt_g->cipher = (char *)malloc(strlen(cipher) + 1), cipher);
    tgt_g->key.format = NULL;
    tgt_g->key.filename = NULL;
    tgt_g->key.key = (char *)sec_realloc(NULL, keylen);
    memcpy((void *)(tgt_g->key.key), (const void *)key, (size_t)keylen);
    tgt_g->key.keylen = keylen;
    tgt_g->key.digestalg = NULL;
    tgt_g->key.cipheralg = NULL;
    tgt_g->key.maxlen = 0;
    tgt_g->key.retries = 3;
}

void free_tgt()
{
    free((void*)tgt_g->ident);
    free((void*)tgt_g->dev);
    free((void*)tgt_g->dir);
    free((void*)tgt_g->fstype);
    free((void*)tgt_g->cipher);
    sec_free((void *)tgt_g->key.key);
    free((void *)tgt_g);
}

void free_mem()
{
    free_tgt();
}

// Entry of setup/release/mount/unmount
int do_work(const char *mode) {
    int eflag = ERR_NOERROR;
    if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0)
    {
        fprintf(stderr, _("Memory-locking failed...\n"));
    }

    if (tgt_g == NULL)
    {
        eflag = ERR_NOTINITIALIZED;
        goto bail_out;
    }

    if (strcmp(mode, "setup") == 0) do_devsetup(tgt_g, NULL);
    else if (strcmp(mode, "release") == 0) do_devshutdown(tgt_g);
    else if (strcmp(mode, "mount") == 0) do_mount(tgt_g);
    else if (strcmp(mode, "unmount") == 0) do_unmount(tgt_g);
    else eflag = ERR_NOTSUPPORTED;

bail_out:

    munlockall();
    free_mem();
    
    return eflag;
}

static int do_devsetup(tgtdefn_t *tgt, char **mntdev)
{
    enum
    {
        BUFFMIN = 1024
    };
    uint8_t *key = (uint8_t *)tgt->key.key;
    int buffpos, blklen, readonly, isloop = 0, killloop = 0,
        keylen = tgt->key.keylen, eflag = ERR_NOERROR;
    int64_t devlen = 0, fslen = 0;
    size_t dpsize;
    char *dmparams = NULL;
    const char *tgtdev = NULL;

    readonly = is_readonlyfs(tgt->dev);
    eflag = blockify_file(tgt->dev, (readonly ? O_RDONLY : O_RDWR),
                          tgt->loopdev, &tgtdev, &isloop);
    if (eflag != ERR_NOERROR)
    {
        fprintf(stderr, _("Cannot open device \"%s\" for target \"%s\"\n"),
                (tgt->dev != NULL ? tgt->dev : "(NULL)"), tgt->ident);
        goto bail_out;
    }

    /* Get size in blocks of target device: */
    devlen = getblk512count(tgtdev, &blklen);
    if (devlen < 0)
    {
        fprintf(stderr, _("Failed to get size of \"%s\"\n"), tgtdev);
        eflag = ERR_BADIOCTL;
        goto bail_out;
    }
    if (tgt->length < 0 || (tgt->start + tgt->length) > devlen)
    {
        fslen = devlen - tgt->start;
    }
    else
    {
        fslen = tgt->length;
    }
    if (tgt->start < 0 || fslen <= 0)
    {
        fprintf(stderr, _("Bad device-mapper start/length"));
        fprintf(stderr, " (%" PRId64 ",%" PRId64 ")\n",
                tgt->start, tgt->length);
        eflag = ERR_BADDEVICE;
        goto bail_out;
    }

    /* Setup device-mapper crypt table (CIPHER KEY IV_OFFSET DEV START): */
    dpsize = 2 * keylen + BUFFMIN;
    dmparams = (char *)sec_realloc(dmparams, dpsize);
    buffpos = snprintf(dmparams, dpsize, "%s ", tgt->cipher);
    buffpos += mk_key_string(key, (size_t)keylen, dmparams + buffpos);
    buffpos += snprintf(dmparams + buffpos, (dpsize - buffpos),
                        " %" PRId64 " %s %" PRId64,
                        tgt->ivoffset, tgtdev, tgt->start);

    /* Setup device-mapper target: */
    eflag = devmap_create(tgt->ident,
                          (uint64_t)0, (uint64_t)fslen, "crypt", dmparams);
    if (eflag != ERR_NOERROR)
    {
        fprintf(stderr,
                _("Device-mapper target-creation failed for \"%s\"\n"),
                tgt->ident);
        killloop = 1;
        goto bail_out;
    }
    if (mntdev != NULL)
    {
        devmap_path(mntdev, tgt->ident);
    }

bail_out:

    if (killloop)
        unblockify_file(&tgtdev, isloop); /* mounting failed? */
    sec_free(dmparams);

    return eflag;
} /* do_devsetup() */

static int do_devshutdown(tgtdefn_t *tgt)
{
    struct stat sbuff;
    unsigned devcnt = 0;
    dev_t *devids = NULL;
    int eflag = ERR_NOERROR;

    /* Find any underlying (e.g. loopback) devices for device-mapper target: */
    udev_settle();
    (void)devmap_dependencies(tgt->ident, &devcnt, &devids);

    if (stat(tgt->dev, &sbuff) != 0)
    {
        fprintf(stderr, _("Cannot stat \"%s\"\n"), tgt->dev);
        eflag = ERR_BADDEVICE;
        goto bail_out;
    }

    /* Remove demice-mapper target: */
    eflag = devmap_remove(tgt->ident);
    if (eflag != ERR_NOERROR)
    {
        fprintf(stderr, _("Failed to remove device-mapper target \"%s\"\n"),
                tgt->ident);
        goto bail_out;
    }
    udev_settle();

    /* Tidy-up any associated loopback devices: */
    if (S_ISREG(sbuff.st_mode) && devids != NULL)
    {
        (void)loop_dellist(devcnt, devids);
    }

bail_out:

    if (devids != NULL)
        free((void *)devids);

    return eflag;
}

static int do_mount(tgtdefn_t *tgt)
{
    int freedev = 0, eflag = ERR_NOERROR;
    char *mntdev = NULL;

    if (is_mounted(tgt))
    {
        fprintf(stderr, _("Target \"%s\" is already mounted\n"),
                tgt->ident);
        eflag = WRN_MOUNTED;
        goto bail_out;
    }

    eflag = do_devsetup(tgt, &mntdev);
    if (eflag != ERR_NOERROR)
        goto bail_out;

    if (fs_mount(mntdev, tgt) != ERR_NOERROR)
    {
        freedev = 1;
        eflag = ERR_BADMOUNT;
        goto bail_out;
    }

bail_out:

    if (freedev)
    {
        /* Tidy-up debris if mount failed */
        udev_settle();
        do_devshutdown(tgt);
    }
    if (mntdev != NULL)
        free((void *)mntdev);

    return eflag;
}

static int do_unmount(tgtdefn_t *tgt)
{
    int eflag = ERR_NOERROR;
    struct passwd *pwent;
    char *mntdev = NULL;

    /* Check if filing system has been configured at all: */
    if (!is_mounted(tgt))
    {
        fprintf(stderr, _("Target \"%s\" does not appear to be mounted\n"),
                tgt->ident);
        eflag = WRN_UNCONFIG;
        goto bail_out;
    }

    /* Unmount filing system: */
    if (fs_unmount(tgt) != ERR_NOERROR)
    {
        eflag = ERR_BADMOUNT;
        goto bail_out;
    }

    /* Remove supporting device-mapper target etc */
    if (do_devshutdown(tgt) != ERR_NOERROR)
    {
        eflag = ERR_BADDEVICE;
    }

bail_out:

    if (mntdev != NULL)
        free((void *)mntdev);

    return eflag;
}
