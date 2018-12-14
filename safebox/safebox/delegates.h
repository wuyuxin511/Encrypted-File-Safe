/*
 *  Delegation-related declations for cryptmount
 *  (C)Copyright 2006-2018, RW Penney
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

#ifndef _DELEGATES_H
#define _DELEGATES_H

/*! Default PATH to use when running subprocesses as root */
#define CM_DEFAULT_SUPATH ""

/* Whether to use internal substitutes for mount(8) or umount(8): */
#ifndef ERSATZ_MOUNT
#define ERSATZ_MOUNT 1
#endif
#ifndef ERSATZ_UMOUNT
#define ERSATZ_UMOUNT 1
#endif

/* whether to enable crypto-swap support: */
#ifndef WITH_CSWAP
#define WITH_CSWAP 0
#endif

/* whether to automatically check filesystem before mounting: */
#ifndef WITH_FSCK
#define WITH_FSCK 0
#endif

#if !ERSATZ_MOUNT
/* path of mount(8), e.g. from util-linux package: */
#define DLGT_MOUNT ""
#endif

#if !ERSATZ_UMOUNT
/* path of umount(8), e.g. from util-linux package: */
#define DLGT_UMOUNT ""
#endif

#if WITH_CSWAP
/* path of mkswap(8), e.g. from util-linux package: */
#define DLGT_MKSWAP ""
#endif

#if WITH_FSCK
/* path of fsck(8), e.g. from e2fsprogs package: */
#define DLGT_FSCK ""
#endif

#endif /* _DELEGATES_H */

/*
 *  (C)Copyright 2006-2017, RW Penney
 */
