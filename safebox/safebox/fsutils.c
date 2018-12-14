/*
 *  Filesystem-related utilities for cryptmount
 *  (C)Copyright 2005-2018, RW Penney
 */

/*
    This file is part of cryptmount

    cryptmount is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    cryptmount is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <ctype.h>
#include <fcntl.h>
#include <math.h>
#include <mntent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "utils.h"
#include "delegates.h"
#include "dmutils.h"
#include "fsutils.h"

static const char *ETCMTAB = "/etc/mtab",
                  *ETCMTABTMP = "/etc/mtab.cm",
                  *STDPATH = CM_DEFAULT_SUPATH;

enum
{
    F_MATCHUID = 0x01, /*!< Set real UID to match effective UID */
    F_CLOSE1 = 0x02,   /*!< Close stdout on child process */
    F_SETPATH = 0x04   /*!< Set standard PATH for child process */
};
static int run_sucommand(const char *path, const char *argv[],
                         const char *supath, unsigned switches);
int do_addmntent(const tgtdefn_t *tgt);
int do_rmvmntent(const tgtdefn_t *tgt);

static char **split_fsckopts(const char *fsckoptions, unsigned *argc)
/*! Split options separated by ';' into vector of strings */
{
    const char SEP = ';';
    const char *pos, *posnext;
    size_t optlen;
    char **opttable = NULL;
    size_t tablesize = 0;

    *argc = 0;
    if (fsckoptions == NULL || *fsckoptions == '\0')
        return opttable;

    pos = fsckoptions;
    do
    {
        if (*argc >= tablesize)
        {
            tablesize = (tablesize + 8) * 2;
            opttable = (char **)realloc((void *)opttable,
                                        (size_t)(tablesize * sizeof(char *)));
        }

        posnext = pos;
        optlen = 0;
        while (*posnext != SEP && *posnext != '\0')
        {
            ++posnext;
            ++optlen;
        }

        opttable[*argc] = (char *)malloc(optlen + 1);
        strncpy(opttable[*argc], pos, optlen);
        opttable[*argc][optlen] = '\0';

        ++*argc;
        pos = posnext + 1;
    } while (*posnext != '\0');

    return opttable;
}

#if ERSATZ_MOUNT

static int parse_mountoptions(const char *buff, unsigned long *mflags)
/*! Convert string of mount-options into binary flags */
{
    struct fsopt_t
    {
        const char *str;
        unsigned long mask;
    };
    struct fsopt_t fsopts[] = {
        {"defaults", 0},
        {"noatime", MS_NOATIME},
        {"nodev", MS_NODEV},
        {"noexec", MS_NOEXEC},
        {"nosuid", MS_NOSUID},
        {"ro", MS_RDONLY},
        {"sync", MS_SYNCHRONOUS},
        {NULL, 0}};
    unsigned idx, len;

    *mflags = 0;
    if (buff == NULL)
        return 0;

    for (;;)
    {
        for (len = 0; buff[len] != '\0' && buff[len] != ','; ++len)
            ;
        for (idx = 0; fsopts[idx].str != NULL; ++idx)
        {
            if (strncmp(buff, fsopts[idx].str, (size_t)len) == 0)
            {
                *mflags |= fsopts[idx].mask;
                break;
            }
        }
        if (fsopts[idx].str == NULL)
        {
            fprintf(stderr, "bad option \"%s\"\n", buff);
            return 1;
        }

        if (buff[len] == '\0')
            break;
        buff += len + 1;
    }

    return 0;
}

int fs_mount(const char *mntdev, const tgtdefn_t *tgt)
/*! Fallback version of mount(8) using mount(2) */
{
    unsigned long mflags;
    int eflag = ERR_NOERROR;
    char *errstr = NULL;

    if (parse_mountoptions(tgt->mountoptions, &mflags) != 0)
    {
        return ERR_BADMOUNT;
    }

    errstr = (char *)malloc((size_t)(strlen(mntdev) + strlen(tgt->dir) + 64));
    sprintf(errstr, "mounting \"%s\" on \"%s\" failed", mntdev, tgt->dir);

    if (mount(mntdev, tgt->dir, tgt->fstype, mflags, NULL) == 0)
    {
        (void)do_addmntent(tgt);
    }
    else
    {
        perror(errstr);
        eflag = ERR_BADMOUNT;
    }

    free((void *)errstr);

    return eflag;
}

#else /* !ERSATZ_MOUNT */

int fs_mount(const char *dev, const tgtdefn_t *tgt)
/*! Delegate filesystem mounting to mount(8) */
{
    int idx, stat, eflag = ERR_NOERROR;
    const char *argv[16];

    /* Construct argument list for mount -t ... -o ... <dev> <dir> */
    idx = 0;
    argv[idx++] = "[cryptmount-mount]";
    if (tgt->fstype != NULL)
    {
        argv[idx++] = "-t";
        argv[idx++] = tgt->fstype;
    }
    if (tgt->mountoptions != NULL)
    {
        argv[idx++] = "-o";
        argv[idx++] = tgt->mountoptions;
    }
    argv[idx++] = dev;
    argv[idx++] = tgt->dir;
    argv[idx++] = NULL;

    stat = run_sucommand(DLGT_MOUNT, argv, tgt->supath, F_MATCHUID);
    eflag = (stat != 0 ? ERR_BADMOUNT : ERR_NOERROR);

    return eflag;
}

#endif /* ERSATZ_MOUNT */

#if ERSATZ_UMOUNT

int fs_unmount(const tgtdefn_t *tgt)
/*! Fallback version of umount(8) using umount(2) */
{
    int eflag = ERR_NOERROR;
    char *errstr = NULL;

    errstr = (char *)malloc((size_t)(strlen(tgt->dir) + 64));
    sprintf(errstr, "unmounting \"%s\" failed", tgt->dir);

    if (umount(tgt->dir) == 0)
    {
        (void)do_rmvmntent(tgt);
    }
    else
    {
        perror(errstr);
        eflag = ERR_BADMOUNT;
    }

    free((void *)errstr);

    return eflag;
}

#else /* !ERSATZ_UMOUNT */

int fs_unmount(const tgtdefn_t *tgt)
/*! Delegate filesystem mounting to umount(8) */
{
    int idx, stat, eflag = ERR_NOERROR;
    const char *argv[16];

    /* Construct argument list for umount -t ... <dir> */
    idx = 0;
    argv[idx++] = "[cryptmount-umount]";
#ifdef PARANOID
    if (tgt->fstype != NULL)
    {
        argv[idx++] = "-t";
        argv[idx++] = tgt->fstype;
    }
    if (tgt->mountoptions != NULL)
    {
        argv[idx++] = "-O";
        argv[idx++] = tgt->mountoptions;
    }
#endif
    argv[idx++] = tgt->dir;
    argv[idx++] = NULL;

    stat = run_sucommand(DLGT_UMOUNT, argv, tgt->supath, F_MATCHUID);
    eflag = (stat != 0 ? ERR_BADMOUNT : ERR_NOERROR);

    return eflag;
}

#endif /* ERSATZ_UMOUNT */

int do_addmntent(const tgtdefn_t *tgt)
/*! Add entry into /etc/mtab for newly-mounted filing system */
{
    char *mntdev = NULL;
    struct mntent mntinfo;
    FILE *fp;
    int eflag = ERR_NOERROR;

    devmap_path(&mntdev, tgt->ident);

    mntinfo.mnt_fsname = mntdev;
    mntinfo.mnt_dir = tgt->dir;
    mntinfo.mnt_type = tgt->fstype;
    mntinfo.mnt_opts = "none";
    mntinfo.mnt_freq = 0;
    mntinfo.mnt_passno = 0;

    fp = setmntent(ETCMTAB, "a");
    if (fp == NULL)
    {
        eflag = ERR_BADFILE;
        goto bail_out;
    }
    (void)addmntent(fp, &mntinfo);
    endmntent(fp);

bail_out:

    if (mntdev != NULL)
        free((void *)mntdev);

    return eflag;
}

int do_rmvmntent(const tgtdefn_t *tgt)
/*! Remove entry from /etc/mtab after unmounting filing system */
{
    char *mntdev = NULL;
    struct mntent *mntinfo;
    FILE *fp_in = NULL, *fp_out = NULL;
    struct stat sbuff;
    int i, eflag = ERR_NOERROR, found = 0;

    /* FIXME - add lots more checks on integrity: */

    devmap_path(&mntdev, tgt->ident);

    /* Open old /etc/mtab & create temporary replacement: */
    fp_in = setmntent(ETCMTAB, "r");
    fp_out = setmntent(ETCMTABTMP, "w");
    if (fp_in == NULL || fp_out == NULL)
    {
        eflag = ERR_BADFILE;
        goto bail_out;
    }

    i = stat(ETCMTAB, &sbuff);
    if (i != 0 || !S_ISREG(sbuff.st_mode))
    {
        fprintf(stderr, "%s is not a valid file\n", ETCMTAB);
        eflag = ERR_BADFILE;
        goto bail_out;
    }

    /* Transfer entries from old /etc/mtab to prototype replacement file: */
    while ((mntinfo = getmntent(fp_in)) != NULL)
    {
        if (strcmp(mntinfo->mnt_fsname, mntdev) == 0 && strcmp(mntinfo->mnt_dir, tgt->dir) == 0)
        {
            ++found;
        }
        else
        {
            addmntent(fp_out, mntinfo);
        }
    }

    /* Transfer ownership & permissions from old /etc/mtab to new: */
    if (chown(ETCMTABTMP, sbuff.st_uid, sbuff.st_gid) != 0 || chmod(ETCMTABTMP, sbuff.st_mode) != 0)
    {
        fprintf(stderr, "cannot transfer ownership/modes to \"%s\"\n",
                ETCMTABTMP);
        eflag = ERR_BADFILE;
        goto bail_out;
    }

    endmntent(fp_in);
    fp_in = NULL;

    if (rename(ETCMTABTMP, ETCMTAB))
    {
        fprintf(stderr, "Failed to recreate %s\n", ETCMTAB);
    }

bail_out:

    if (fp_in != NULL)
        endmntent(fp_in);
    if (fp_out != NULL)
        endmntent(fp_out);
    if (mntdev != NULL)
        free((void *)mntdev);

    return eflag;
}

/*!
 *  Check whether a filesystem target is mounted.
 *
 *  This will examine entries in /etc/mtab via getmntent(),
 *  looking for a filesystem whose major and minor device numbers
 *  match those of the block device associated with the supplied target.
 *
 *  Note that this will return false for targets that refer
 *  to swap partitions, even if they are active.
 */
int is_mounted(const tgtdefn_t *tgt)
{
    int mounted = 0;
    char *mntdev = NULL;
    struct mntent *mntinfo;
    struct stat st_mtb, st_tgt;
    FILE *fp;

    /* check if underlying device has been configured at all: */
    if (!is_configured(tgt->ident, NULL))
        return 0;

    /* find path to device that would have been mounted & device info: */
    devmap_path(&mntdev, tgt->ident);
    if (stat(mntdev, &st_tgt) != 0)
        return 0;

    /* check entries in /etc/mtab: */
    fp = setmntent(ETCMTAB, "r");
    if (fp == NULL)
    {
        return 0; /* indeterminate case - assume not mounted */
    }
    while ((mntinfo = getmntent(fp)) != NULL && !mounted)
    {
        if (stat(mntinfo->mnt_fsname, &st_mtb) != 0)
            continue;

        /* compare to mounted device on basis of kernel device maj/min: */
        if (major(st_mtb.st_rdev) == major(st_tgt.st_rdev) && minor(st_mtb.st_rdev) == minor(st_tgt.st_rdev))
        {
            mounted = 1;
        }
    }
    endmntent(fp);

    return mounted;
}

int is_readonlyfs(const char *path)
/*! Check if filesystem containing *path is read-only */
{
    struct statvfs sbuff;

    return (path == NULL || (statvfs(path, &sbuff) != 0 || (sbuff.f_flag & ST_RDONLY) != 0));
}

#if !ERSATZ_MOUNT || !ERSATZ_UMOUNT || WITH_FSCK || WITH_CSWAP

static int run_sucommand(const char *path, const char **argv,
                         const char *supath, unsigned switches)
/*! Fork (& wait for) system-command as root */
{
    pid_t child;
    int stat = -1, fd;

    switch ((child = fork()))
    {
    case -1: /* fork failed */
        fprintf(stderr, "failed to fork (%s)\n", path);
        break;
    case 0: /* child fork */
        if ((switches & F_MATCHUID) != 0)
        {
            /* change real UID to match effective UID
                   (probably only useful if euid==root): */
            if (setuid(geteuid()) != 0)
                exit(EXIT_BADEXEC);
        }
        if ((switches & F_CLOSE1) != 0)
        {
            /* redirect standard output to /dev/null */
            fd = open("/dev/null", O_WRONLY);
            if (fd >= 0)
                (void)dup2(fd, STDOUT_FILENO);
            else
                (void)close(STDOUT_FILENO);
        }
        if ((switches & F_SETPATH) != 0)
        {
            if (supath == NULL)
                supath = STDPATH;
            if (setenv("PATH", supath, 1) != 0)
            {
                exit(EXIT_BADEXEC);
            }
        }

        execv(path, (char *const *)argv);
        fprintf(stderr, "failed to invoke \"%s\"\n", path);
        exit(EXIT_BADEXEC);
        break;
    default: /* parent fork */
        if (waitpid(child, &fd, 0) == child)
        {
            stat = fd;
        }
        break;
    }

    return stat;
}

#endif /* !ERSATZ_MOUNT ... */


/*
 *  (C)Copyright 2005-2018, RW Penney
 */
