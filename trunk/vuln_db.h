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

#ifndef _VULN_DB_H
#define _VULN_DB_H
#include "hash.h"

typedef enum Severity_t  {

    Default,
    Low,
    Medium,
    High
} Severity_t;


typedef struct FSProblem_t  {

    int Arg;
    Severity_t Severity; 
} FSProblem_t;

    
typedef struct BOProblem_t  {
    int FormatArg; 
    int SrcBufArg;
    Severity_t Severity; 
    int Scan;
} BOProblem_t;

typedef struct InputProblem_t  {
    int Arg;
    Severity_t Severity;
} InputProblem_t;

typedef struct Info_t  {
    char *Description;
    char *URL;
    Severity_t Severity;
} Info_t;

typedef struct Vuln_t  {

    char *Name;
    FSProblem_t *FSProblem;
    BOProblem_t *BOProblem;
    int RaceCheck;
    int RaceUse;
    int Input;
    InputProblem_t *InputProblem;
    Info_t *Info;
} Vuln_t;




Hash ParseVulnDb(char *, Hash *);
void FreeInfo(Info_t *);
void InitVuln(Vuln_t *);
void InitInfo(Info_t *);


#endif
