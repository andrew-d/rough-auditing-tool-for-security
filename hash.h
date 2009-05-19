/* 
 * Copyright (c) 2001-2002 Secure Software, Inc
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 */

#ifndef _HHASH_H
#define _HHASH_H

#include "kazhash.h"

typedef hash_t * Hash;

hash_val_t HashMangle(const void *);
int HashCompare(const void *, const void *);

Hash HashInit();
int HashInsert(Hash, void *, char *name);
void *HashGet(Hash,char *);
int HashDelete(Hash,char *);
long HashCount(Hash);
char **HashKeys(Hash);
void HashFreeKeys(Hash, char **);

#endif
