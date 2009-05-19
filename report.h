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

#ifndef REPORT_H
#define REPORT_H

#include "vuln_db.h"
#include "engine.h"
#ifndef _MSC_VER
#include <sys/time.h>
#endif


extern int total_lines;
#ifdef _MSC_VER
extern DWORD time_started;
extern DWORD time_finished;
#else
extern struct timeval time_started;
extern struct timeval time_finished; 
#endif

typedef enum _type_t type_t;
enum _type_t
{
    BOProblem,
    FSProblem,
    InputProblem,
    Info,
    RaceConditionCheck,
    RaceConditionUse,
    StaticLocalBuffer,
    StaticGlobalBuffer,
    Reference,
    PythonBacktick,
    PhpBacktick,
    PerlBacktick,
    None
};

typedef struct _toctou_use_t toctou_use_t;
struct _toctou_use_t
{
    char *  name;
    int     lineno;
    int	    column;
};

typedef struct _vulnerability_t vulnerability_t;
struct _vulnerability_t
{
    char *              filename;
    int                 lineno;
    int			column;
    Vuln_t *            data;
    type_t              type;
    Severity_t          severity;
    toctou_use_t *      uses;
    vulnerability_t *   next;
    vulnerability_t *   prev;
};

typedef struct _input_t input_t;
struct _input_t
{
    char *      filename;
    int         lineno;
    int		column;
    Vuln_t *    data;
    input_t *   next;
};

typedef struct _ignore_t ignore_t;
struct _ignore_t
{
    char *      filename;
    int         lineno;
    char *      token;  /* can be NULL */
    ignore_t *  next;
};

extern int warning_level;

extern void         log_staticbuffer(type_t type, int, int, Severity_t);
extern void         log_toctou(toctou_t **, int, int, int);
extern void	    log_pythonbacktick(int, int,Severity_t);
extern void         log_perlbacktick(int, int,Severity_t);
extern void         log_phpbacktick(int, int,Severity_t);
extern void         log_vulnerability(type_t, Severity_t);
extern void         record_input(void);
extern void         generate_report(void);
extern void         generate_xml(void);
extern void         generate_html(void);
extern ignore_t *   new_ignore(int lineno, char *token);

#endif
