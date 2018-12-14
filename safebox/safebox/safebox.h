#ifndef _SAFEBOX_H
#define _SAFEBOX_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <ctype.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <pwd.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#ifdef HAVE_SYSLOG
#include <syslog.h>
#endif
#include <linux/fs.h> /* Beware ordering conflict with sys/mount.h */

#ifdef HAVE_GETTEXT
#include <libintl.h>
#include <locale.h>
#define _(String) gettext(String)
#define gettext_noop(String) String
#define N_(String) gettext_noop(String)
#else
#define _(String) (String)
#define N_(String) String
#define textdomain(Domain)                 /* empty */
#define bindtextdomain(Package, Directory) /* empty */
#endif

enum /*! Exit-codes */
{
    EXIT_OK = 0,
    EXIT_BADOPT = 1,
    EXIT_BADTGT = 2,
    EXIT_BADEXEC = 3,
    EXIT_PRIV = 100,
    EXIT_INSECURE = 101
};

enum /*! Error flags */
{
    ERR_NOERROR = 0,

    WRN_UNCONFIG, /*!< Filesystem is already unmounted */
    WRN_NOPASSWD,
    WRN_LOWENTROPY,
    WRN_MOUNTED, /*!< Filesystem is already mounted */

    ERR_threshold = 0x10, /*!< Dividing-line between warnings & errors */

    ERR_NOTSUPPORTED,
    ERR_BADKEYFORMAT,
    ERR_BADALGORITHM,
    ERR_BADFILE,    /*!< Serious problem with accessing file */
    ERR_BADDECRYPT, /*!< Failure to extract cipher key from file */
    ERR_BADENCRYPT,
    ERR_MEMSPACE,
    ERR_DMSETUP,
    ERR_BADDEVICE,
    ERR_BADIOCTL,
    ERR_BADSUID,
    ERR_BADPRIV,
    ERR_BADMOUNT,
    ERR_BADFSCK,
    ERR_BADSWAP,
    ERR_INSECURE,
    ERR_BADPASSWD,
    ERR_BADPARAM,
    ERR_BADMUTEX,
    ERR_NOTINITIALIZED,
    ERR_ABORT
};

typedef struct keyinfo
{
    const char *format; /*!< Type of key file, e.g. 'raw', 'libgcrypt' */
    char *filename;
    char *key;
    int keylen;
    char *digestalg;
    char *cipheralg;
    long maxlen;      /*!< Maximum number of bytes to read from keyfile */
    unsigned retries; /*!< Limit on password-entry attempts */
} keyinfo_t;

typedef struct tgtdefn
{
    const char *ident; /*!< Unique identifying name */
    unsigned flags;    /*!< Configuration switches */

    char *dev;             /*!< Device node or raw file */
    int64_t start, length; /*!< Starting sector + num of sectors (or 0, -1) */
    char *dir;             /*!< Mount-point */
    char *fstype;          /*!< Filesystem type */
    char *mountoptions;    /*!< Options passed to 'mount' command */
    char *fsckoptions;     /*!< Options passed to 'fsck' command */
    char *loopdev;         /*!< Loopback device to wrap around raw file */
    char *supath;          /*!< PATH to setup for commands run as root */

    char *cipher;     /*!< Cipher used on filesystem */
    int64_t ivoffset; /*!< Cipher initialization-vector offset */

    keyinfo_t key; /*!< Location/format of key */

    struct tgtdefn *nx; /*!< Form into linked list */
} tgtdefn_t;

void prepare_tgt(const char *name, char *dev, char *dir, char *fstype,
                 char *cipher, char *key, int keylen);

void free_tgt();

void free_mem();

int do_work(const char *mode);

static int do_devsetup(tgtdefn_t *tgt, char **mntdev);
static int do_devshutdown(tgtdefn_t *tgt);
static int do_mount(tgtdefn_t *tgt);
static int do_unmount(tgtdefn_t *tgt);

#endif /* _SAFEBOX_H */
