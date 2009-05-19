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

#ifndef ENGINE_H
#define ENGINE_H

#include "vuln_db.h"

#define DEPTH_PARENTHESIS       0
#define DEPTH_BRACKET           1
#define DEPTH_BRACE             2
#define DEPTH_COUNT             3

#define INCLUDE_ALL_REFERENCES  0x1
#define INPUT_MODE              0x2
#define RECURSIVE_FILE_SCAN     0x4
#define XML_OUTPUT		0x8
#define HTML_OUTPUT		0x10
#define FOLLOW_SYMLINK		0x20
#define NO_HEADER		0x40
#define NO_STATUS		0x80
#define NO_FOOTER		0x100
#define SHOW_COLUMNS	        0x200
#define SHOW_CONTEXT		0x400
#define ALL_STATIC		0x800



#define LANG_PYTHON		1	
#define LANG_C		 	2	
#define LANG_PERL		3
#define LANG_PHP		4

typedef struct _lexer_t lexer_t;

struct _lexer_t
{
    char **	    yytext;
    FILE *	    yyin;
    int 	    (*yylex)();
    char **	    yycomment;
    int *	    lex_lineno;
    Hash	    langhash;
    int		    lang;
    int *	    lex_column;
};

    
typedef struct _argument_t argument_t;
struct _argument_t
{
    int             is_constant;    /* is the argument a constant string?    */
    int             contains_ps;    /* does the string contain dangerous %s? */
    char *          yytext;         /* token text making up the argument     */
    argument_t *    next;
};

typedef struct _rats_stack_t rats_stack_t;
struct _rats_stack_t
{
    char *          identifier;
    Vuln_t *        data;
    int		    column;
    int             lineno;
    int             argc;
    argument_t *    argv;
    rats_stack_t *  next;
};

typedef struct _argscan_t argscan_t;
struct _argscan_t
{
    argument_t *    tail;
    argument_t *    current;
    int             depths[DEPTH_COUNT];
};

typedef struct _charscan_t charscan_t;
struct _charscan_t
{
    int lineno;
    int last_token;
    int column;
    int initial_type;
    int depth;
    int skip;
};

typedef struct _accumulator_t accumulator_t;
struct _accumulator_t
{
    char **         text;
    int             length;
    accumulator_t * next;
};

typedef struct _toctou_t toctou_t;
struct _toctou_t
{
    int		column;
    int         lineno;
    Vuln_t *    data;
    char *      key;
    int         use;
    toctou_t *  next;
};

typedef int (* processorfn_t)(int, void *);

extern int              flags;
extern Hash             database;
extern Hash	        defaultdb;
extern char *           current_file;
extern rats_stack_t *   current_frame;

extern void process_file(char *, int);

#endif  /* ENGINE_H */
