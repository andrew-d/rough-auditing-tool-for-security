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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifdef HAVE_EXPAT_H
#  include "expat.h"
#  else /* HAVE_XMLPARSE_H */
#    ifdef HAVE_XMLPARSE_H
#      include "xmlparse.h"
#    else
#      ifdef _MSC_VER
#        include "expat.h"
#      endif
#    endif
#endif
#include "hash.h"
#include "vuln_db.h"

/* Modified by Mike Ellison February 17th, 2002 - win32 port
 *
 * Just #define to using native win32 functions, since VC++ at least doesn't
 * seem to have the strncasecmp() function.
 */
#ifdef _MSC_VER
#define strcasecmp _strcmpi
#endif

typedef struct udata_t
{
    char *      fname[10];      /* Arbitrary max depth of XML doc */
    int         depth;
    char        databuf[2048];
    char *      bufptr;
    Vuln_t *    vuln;
    int         failed;
    int         failedat;
    XML_Parser  parser;
    Hash        myhash;
    Hash        parenthash;
} udata_t;

void InitUdata(udata_t *udata, XML_Parser parser)
{
    udata->failed   = 0;
    udata->failedat = 0;
    udata->parser   = parser;
    udata->depth    = -1;
    udata->bufptr   = (char *)NULL;
    udata->vuln     = (Vuln_t *)NULL;
    udata->myhash   = (Hash)NULL;
}

void FreeVuln(Vuln_t *vuln)
{
    if (vuln == (Vuln_t *)NULL)
        return;
    if (vuln->Name != (char *)NULL)
        free(vuln->Name);
    if (vuln->FSProblem != (FSProblem_t *)NULL) 
        free(vuln->FSProblem);
    if (vuln->BOProblem != (BOProblem_t *)NULL)
        free(vuln->BOProblem);
    if (vuln->InputProblem != (InputProblem_t *)NULL)
        free(vuln->InputProblem);
    if (vuln->Info != (Info_t *)NULL)
    {
        FreeInfo(vuln->Info);
        free(vuln->Info);
    }
}

void InitVuln(Vuln_t *vuln)
{
    vuln->Name         = (char *)NULL;
    vuln->FSProblem    = (FSProblem_t *)NULL;
    vuln->BOProblem    = (BOProblem_t *)NULL;
    vuln->RaceCheck    = 0;
    vuln->RaceUse      = 0;
    vuln->Input        = 0;
    vuln->Info         = (Info_t *)NULL;
    vuln->InputProblem = (InputProblem_t *)NULL;
}

void InitFSProblem(FSProblem_t *prob)
{
    prob->Arg      = 0;
    prob->Severity = Default;
}

void InitBOProblem(BOProblem_t *prob)
{
    prob->FormatArg = 0;
    prob->SrcBufArg = 0;
    prob->Severity  = Default;
}

void InitInputProblem(InputProblem_t *prob)
{
    prob->Arg      = 0;
    prob->Severity = Default;
}

void FreeInfo(Info_t *info)
{
    if (info == (Info_t *)NULL)
        return; 
    if (info->Description != (char *)NULL)
        free(info->Description);
    if (info->URL != (char *)NULL)
        free(info->URL);
}

void InitInfo(Info_t *info)
{
    info->Description = (char *)NULL;
    info->URL         = (char *)NULL;
    info->Severity    = Default;
}

static int SetFailed(udata_t *mydata)
{
    mydata->failed   = 1;
    mydata->failedat = XML_GetCurrentLineNumber(mydata->parser);
    return mydata->failedat;
}

void StartElement(void *udata, const char *name, const char **atts)
{
    udata_t *       mydata = (udata_t *)udata;
    char *          langname = (char *)NULL;
    char **         tmp;
    char *          curname = (char *)NULL;
    char *          curval;
    int             count = 0;
    unsigned int    i;

    if (mydata->failed)  
        return;

    mydata->fname[mydata->depth + 1] = (char *)malloc(strlen(name) + 1);
    strncpy(mydata->fname[mydata->depth + 1], name, strlen(name));
    mydata->fname[mydata->depth + 1][strlen(name)] = '\0';  
    mydata->depth++;
    mydata->bufptr = mydata->databuf;

    if (!strcmp(name, "VulnDB"))
    {
        if (!atts || !atts[0])
            langname = "default"; 
        else
        {
            tmp = (char **)atts;
            while (*tmp != NULL)
            {
                if (!(count % 2))
                    curname = *tmp;
                else if (count % 2 == 1)
                {
                    curval = *tmp;
                    if (!strcasecmp(curname, "lang"))
                    {
                        langname = (char *)malloc(strlen(curval) + 1);
                        for (i = 0;  i < strlen(curval);  i++)
                            langname[i] = tolower(curval[i]);
                        langname[strlen(curval)] = 0;
                    }
                }
                
                tmp++;
                count++;
            }
        }
	/* This prevented loading multiple xml files for the same language */
/*  	if (!HashGet(mydata->parenthash, langname)) */
	if(!(mydata->myhash=HashGet(mydata->parenthash,langname)))
        {
            mydata->myhash = HashInit();
            if (mydata->myhash != (Hash)NULL)
                HashInsert(mydata->parenthash, mydata->myhash, langname);
        }
    }
    else if (!strcmp(name, "Vulnerability"))
    {
        if (mydata->vuln != (Vuln_t *)NULL)
        {
            fprintf(stderr, "Vulnerability open tag found, but already in one at line %d\n", SetFailed(mydata));
            return;
        }
        mydata->vuln = (Vuln_t *)malloc(sizeof(Vuln_t));
        InitVuln(mydata->vuln);
    }
    else if (!strcmp(name, "FSProblem"))
    {
        if (mydata->vuln == (Vuln_t *)NULL)
        {
            fprintf(stderr,"In FSProblem, but no Vuln struct at line %d\n", SetFailed(mydata)); 
            return;
        } 
        if (mydata->vuln->FSProblem != (FSProblem_t *)NULL)
        {
            fprintf(stderr, "FSProblem open tag found but already in one at line %d\n", SetFailed(mydata));
            return;
        }              
        mydata->vuln->FSProblem = (FSProblem_t *)malloc(sizeof(FSProblem_t));
        InitFSProblem(mydata->vuln->FSProblem);
    }
    else if (!strcmp(name, "BOProblem"))
    {
        if (mydata->vuln == (Vuln_t *)NULL)
        {
            fprintf(stderr, "In BOProblem, but no Vuln struct at line %d\n", SetFailed(mydata));
            return;
        }
        if (mydata->vuln->BOProblem != (BOProblem_t *)NULL)
        {
            fprintf(stderr,"BOProblem open tag found, but already in one at line %d\n", SetFailed(mydata));
            return;
        }
        mydata->vuln->BOProblem = (BOProblem_t *)malloc(sizeof(BOProblem_t));
        InitBOProblem(mydata->vuln->BOProblem);
    }
    else if (!strcmp(name, "InputProblem"))
    {
        if (mydata->vuln == (Vuln_t *)NULL)
        {
            fprintf(stderr, "In InputProblem, but no Vuln struct at line %d\n", SetFailed(mydata));
            return;
        }
        if (mydata->vuln->InputProblem != (InputProblem_t *)NULL)
        {
            fprintf(stderr,"InputProblem open tag found, but already in one at %d\n", SetFailed(mydata));
            return;
        }
        mydata->vuln->InputProblem = (InputProblem_t *)malloc(sizeof(InputProblem_t));
        InitInputProblem(mydata->vuln->InputProblem);
    }
    else if (!strcmp(name, "Info"))
    {
        if (mydata->vuln == (Vuln_t *)NULL)
        {
            fprintf(stderr,"In Info, but no Vuln struct at line %d\n", SetFailed(mydata));
            return;
        }
        if (mydata->vuln->Info != (Info_t *)NULL)
        {
            fprintf(stderr, "Found Info open tag, but already in one at line %d\n", SetFailed(mydata));
            return;
        }
        mydata->vuln->Info = (Info_t *)malloc(sizeof(Info_t));
        InitInfo(mydata->vuln->Info);
    }
    else if (!strcmp(name, "Description"))
    {
        if (mydata->vuln == (Vuln_t *)NULL || mydata->vuln->Info == (Info_t *)NULL)
            fprintf(stderr, "Found Description tag, in wrong place, must be inside <Info>\n");
    }
}

int FrameIsName(udata_t *udata, const char *name)
{
    return strcmp(udata->fname[udata->depth], name);
}

Severity_t ConvertSeverity(const char *buf)
{
    if (!strcasecmp(buf, "high"))
        return High;
    if (!strcasecmp(buf, "medium"))
        return Medium;
    if (!strcasecmp(buf, "low"))
        return Low;
    return Default;
}

void EndElement(void *udata, const char *name)
{
    udata_t *   mydata = (udata_t *)udata;
    
    if (mydata->failed)
        return;
    free(mydata->fname[mydata->depth]);
    mydata->depth--;
    if (!strcmp(name, "Vulnerability"))
    {
        if (mydata->vuln == (Vuln_t *)NULL)
        {
            fprintf(stderr, "At end of Vulnerability section, but no vuln data?!\n");
            return;
        }
        else
        {
            if (!HashInsert(mydata->myhash, (void *)mydata->vuln, mydata->vuln->Name))
            {
                FreeVuln(mydata->vuln);
                free(mydata->vuln);
            }
                
            mydata->vuln = (Vuln_t *)NULL;
        }
    }
    else if (!strcmp(name, "Name"))
    {
        mydata->vuln->Name = (char *)malloc(strlen(mydata->databuf) + 1);
        strncpy(mydata->vuln->Name, mydata->databuf, strlen(mydata->databuf));
        mydata->vuln->Name[strlen(mydata->databuf)] = '\0';
    }
    else if (!strcmp(name, "FormatArg"))
        mydata->vuln->BOProblem->FormatArg = atoi(mydata->databuf);
    else if (!strcmp(name, "SrcBufArg"))
        mydata->vuln->BOProblem->SrcBufArg = atoi(mydata->databuf);
    else if (!strcmp(name, "Scan"))
        mydata->vuln->BOProblem->Scan = 1;
    else if (!strcmp(name, "Description"))
    {
        mydata->vuln->Info->Description = (char *)malloc(strlen(mydata->databuf) + 1);
        strncpy(mydata->vuln->Info->Description, mydata->databuf, strlen(mydata->databuf));
        mydata->vuln->Info->Description[strlen(mydata->databuf)] = '\0';
    }
    else if (!strcmp(name, "URL"))
    {
        mydata->vuln->Info->URL = (char *)malloc(strlen(mydata->databuf) + 1);
        strncpy(mydata->vuln->Info->URL, mydata->databuf, strlen(mydata->databuf));
        mydata->vuln->Info->URL[strlen(mydata->databuf)] = '\0';
    }
    else if (!strcmp(name, "RaceCheck"))
        mydata->vuln->RaceCheck = atoi(mydata->databuf);
    else if (!strcmp(name, "RaceUse"))
        mydata->vuln->RaceUse = atoi(mydata->databuf);
    else if (!strcmp(name, "Input"))
        mydata->vuln->Input = 1;
    else if (!strcmp(name, "Arg"))
    {
        if (!FrameIsName(mydata, "FSProblem"))
            mydata->vuln->FSProblem->Arg = atoi(mydata->databuf);
        else if (!FrameIsName(mydata, "InputProblem"))
            mydata->vuln->InputProblem->Arg = atoi(mydata->databuf);
    }
    else if (!strcmp(name, "Severity"))
    {
        if (!FrameIsName(mydata, "FSProblem"))
            mydata->vuln->FSProblem->Severity = ConvertSeverity(mydata->databuf);
        else if(!FrameIsName(mydata, "BOProblem"))
            mydata->vuln->BOProblem->Severity = ConvertSeverity(mydata->databuf);
        else if(!FrameIsName(mydata, "InputProblem"))
            mydata->vuln->InputProblem->Severity = ConvertSeverity(mydata->databuf);
        else if(!FrameIsName(mydata, "Info"))
            mydata->vuln->Info->Severity = ConvertSeverity(mydata->databuf);
    } 
    mydata->bufptr = mydata->databuf;
}

void CharData(void *udata, const XML_Char *str, int len)
{
    udata_t *   mydata = (udata_t *)udata;

    if (mydata->failed)
        return;
    if (mydata->bufptr + len > mydata->databuf + sizeof(mydata->databuf))
    {
        fprintf(stderr, "Possible data overflow, ignoring it.\n");
        return;
    }

    strncpy(mydata->bufptr, str, len);
    mydata->bufptr += len;
    *mydata->bufptr = '\0';
}
  
Hash ParseVulnDb(char *buf, Hash *usehash)
{
    XML_Parser  parser;
    udata_t     mydata;

    parser = XML_ParserCreate(NULL);
    if (parser == (XML_Parser)NULL)
    {
        fprintf(stderr, "Failed to create XML Parser\n");
        return (Hash)NULL;
    }
    InitUdata(&mydata, parser);
    XML_SetUserData(parser, &mydata);
    XML_SetElementHandler(parser, StartElement, EndElement);
    XML_SetCharacterDataHandler(parser, CharData);

    if (*usehash == (Hash)NULL)
        *usehash = HashInit();
    mydata.parenthash = *usehash;
    if (*usehash == NULL)
    {
        fprintf(stderr, "Failed to create Hash table\n");
        return (Hash)NULL;
    }
    if (!XML_Parse(parser, buf, strlen(buf), 1))
    {
        fprintf(stderr, "%s at line %d\n",
                XML_ErrorString(XML_GetErrorCode(parser)),
                XML_GetCurrentLineNumber(parser));
        return (Hash)NULL;
    }
    if (mydata.failed)
        return (Hash)NULL;
    return *usehash;
}
