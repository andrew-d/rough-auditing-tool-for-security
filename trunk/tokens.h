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

#ifndef TOKENS_H
#define TOKENS_H

 
#define TOKEN_START 256 /* start of common tokens */
#define TOKEN_END   (TOKEN_START + 127)

#define CONST_START     (TOKEN_END + 1)
#define CONST_END       (CONST_START + 127)
 
#define TOKEN_C_START   (CONST_END + 1) /* start of C tokens */
#define TOKEN_C_END     (TOKEN_C_START + 127)

#define TOKEN_PY_START  (TOKEN_C_END + 1)   /* start of Python tokens */
#define TOKEN_PY_END    (TOKEN_PY_START + 127)

#define TOKEN_PERL_START  (TOKEN_PY_END + 1)   /* start of Python tokens */
#define TOKEN_PERL_END    (TOKEN_PERL_START + 127)

#define TOKEN_PHP_START   (TOKEN_PERL_END + 1)
#define TOKEN_PHP_END     (TOKEN_PHP_START + 127)

/* Tokens that are common to multiple languages */

#define TOKEN_HEX_CONST 	(CONST_START +  0)
#define TOKEN_OCT_CONST	(CONST_START +  1)
#define TOKEN_DEC_CONST	(CONST_START +  2)
#define TOKEN_FLOAT_CONST	(CONST_START +  3)
#define TOKEN_IMAG_CONST	(CONST_START +  4)
#define TOKEN_STRING_CONST    (CONST_START +  5)
#define TOKEN_CHAR_CONST	(CONST_START +  6)

#define TOKEN_BREAK           (TOKEN_START +  0)
#define TOKEN_CONTINUE        (TOKEN_START +  1)
#define TOKEN_ELSE            (TOKEN_START +  2)
#define TOKEN_FOR             (TOKEN_START +  3)
#define TOKEN_IF              (TOKEN_START +  4)
#define TOKEN_RETURN          (TOKEN_START +  5)
#define TOKEN_WHILE           (TOKEN_START +  6)
#define TOKEN_IDENTIFIER      (TOKEN_START + 11)
#define TOKEN_COMMENT         (TOKEN_START + 13)
#define TOKEN_JUNK            (TOKEN_START + 14)

#define TOKEN_RIGHT_ASSIGN    (TOKEN_START + 15)
#define TOKEN_LEFT_ASSIGN     (TOKEN_START + 16)
#define TOKEN_ADD_ASSIGN      (TOKEN_START + 17)
#define TOKEN_SUB_ASSIGN      (TOKEN_START + 18)
#define TOKEN_MUL_ASSIGN      (TOKEN_START + 19)
#define TOKEN_DIV_ASSIGN      (TOKEN_START + 20)
#define TOKEN_MOD_ASSIGN      (TOKEN_START + 21)
#define TOKEN_AND_ASSIGN      (TOKEN_START + 22)
#define TOKEN_XOR_ASSIGN      (TOKEN_START + 23)
#define TOKEN_OR_ASSIGN       (TOKEN_START + 24)

#define TOKEN_RIGHT_OP        (TOKEN_START + 25)
#define TOKEN_LEFT_OP         (TOKEN_START + 26)
#define TOKEN_LE_OP           (TOKEN_START + 27)
#define TOKEN_GE_OP           (TOKEN_START + 28)
#define TOKEN_EQ_OP           (TOKEN_START + 29)
#define TOKEN_NE_OP           (TOKEN_START + 30)

/* Language specific tokens */
#include "c-tokens.h"
#include "python-tokens.h"
#include "perl-tokens.h"
#include "php-tokens.h"

/* Common externs */
/*C language */
extern int	clex_column;
extern int      clex_lineno;
extern FILE *   yycin;
extern char *   yyctext;
extern int      yycleng;
extern int      yyclength, yycsize;
extern char *   yyccomment;

extern int yyclex(void);

/*python language */
extern int 	plex_column;
extern int      plex_lineno;
extern FILE *   yypin;
extern char *   yyptext;
extern int      yypleng;
extern char *   yypcomment;

extern int yyplex(void);

/* perl language */
extern int 	perllex_column;
extern int 	perllex_lineno;
extern FILE *	yyperlin;
extern char *	yyperltext;
extern int	yyperlleng;
extern char *	yyperlcomment;
extern int yyperllex(void);

/* php language */
extern int 	phplex_column;
extern int      phplex_lineno;
extern FILE *   yyphpin;
extern char *   yyphptext;
extern int      yyphpleng;
extern char *   yyphpcomment;
extern int yyphplex(void);



#endif
