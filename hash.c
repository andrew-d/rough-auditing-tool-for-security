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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "hash.h"

Hash HashInit()
{
    return (Hash)hash_create(515, HashCompare, NULL);
}

int HashCompare(const void *firstitem, const void *seconditem)
{
    return strcmp((char *)firstitem, (char *)seconditem);
}

int HashInsert(Hash myhash, void *item, char *name)
{
    hnode_t *   mynode = (hnode_t *)NULL;
    hnode_t *   hisnode = (hnode_t *)NULL;

    if (myhash == NULL)
    {
        fprintf(stderr, "NULL Hash object passed to HashInsert\n");
        return 0;
    }
 
    mynode = hnode_create(item);
    if (mynode == NULL)
    {
        fprintf(stderr, "Node creation failed in HashInsert\n");
        return 0;
    }

    if ((hisnode = hash_lookup(myhash, name)) != NULL)
    {
        fprintf(stderr, "Function %s has multiple entries in database.  New entry will be used\n", name);
	hash_delete(myhash, hisnode);
    }
    hash_insert(myhash, mynode, name);
    return 1;
}

void *HashGet(Hash myhash, char *name)
{
    hnode_t *   mynode = (hnode_t *)NULL;
    void *      mydata = (void *)NULL;

    mynode = hash_lookup(myhash, name);
    if (mynode != (hnode_t *)NULL)
        mydata = hnode_get(mynode);
    return mydata;
}


long
HashCount(Hash myhash)
{

  return (long)hash_count(myhash);
}


char **
HashKeys(Hash myhash)
{
    hscan_t hs;
    hnode_t *hn;
    long nents = 0;
    char **ret = NULL; 
    int i = 0;
    
    nents = HashCount(myhash);
    ret = malloc((nents+1)*(sizeof(char *)));
    hash_scan_begin(&hs, myhash);
    while ((hn = hash_scan_next(&hs)))
    { 
        char *tmp = hnode_getkey(hn);
        ret[i++] = tmp;
    }
    ret[i] = NULL;
    return ret;
}

void
HashFreeKeys(Hash myhash , char **keys)
{
    if (keys)
        free(keys);
}
