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

%{
#include <string.h>
#include "tokens.h"
#include "engine.h"

int clexreal_column = 0;
int clex_column = 0;
int clex_lineno = 1;
int yyclength = 0;
int yycsize = 0;
char *yyccomment = NULL;

static int  identifier(void);
static int  string_const(void);
static int  preprocessor(void);
static void reset_comment(void);
static int  cstyle_comment(void);
static void no_match(void);
static void accumulate_comment(char *data, int length);
static void count(void);

#define YY_INPUT(buf, result, max_size)                                     \
    if (((result = fread(buf, 1, max_size, yycin)) == 0) && ferror(yycin)) {    \
        YY_FATAL_ERROR("input in flex scanner failed");                     \
    } else {                                                                  \
        char *c, *end = (buf) + result - 1;                                 \
        for (c = (buf);  c < end;  c++) {                                   \
            if (*c == '\r') *c = ' ';                                       \
            if (*c == '\\' && *(c + 1) == '\n') {                           \
                memmove(c + 1, c + 2, end - c);                             \
                result--;                                                   \
                end--;                                                      \
                *c = '\r';                                                  \
            }                                                               \
        }                                                                   \
        if (*end == '\r') *end = ' ';                                       \
        if (*end == '\\') {                                                 \
            result--;                                                       \
            fseek(yycin, -1, SEEK_CUR);                                      \
        }                                                                   \
    }

%}

%%

"#"                     { count(); return preprocessor(); }
"/*"                    { count(); return cstyle_comment(); }
"//".*                  { count(); reset_comment();  
                          accumulate_comment(yytext+2,strlen(yytext+2)); 
			  return TOKEN_COMMENT; }

"auto"                  { count(); return TOKEN_AUTO; }
"break"                 { count(); return TOKEN_BREAK; }
"case"                  { count(); return TOKEN_CASE; }
"char"                  { count(); return TOKEN_CHAR; }
"const"                 { count(); return TOKEN_CONST; }
"continue"              { count(); return TOKEN_CONTINUE; }
"default"               { count();return TOKEN_DEFAULT; }
"do"                    { count();return TOKEN_DO; }
"double"                { count();return TOKEN_DOUBLE; }
"else"                  { count();return TOKEN_ELSE; }
"enum"                  { count();return TOKEN_ENUM; }
"extern"                { count();return TOKEN_EXTERN; }
"float"                 { count();return TOKEN_FLOAT; }
"for"                   { count();return TOKEN_FOR; }
"goto"                  { count();return TOKEN_GOTO; }
"if"                    { count();return TOKEN_IF; }
"int"                   { count();return TOKEN_INT; }
"long"                  { count();return TOKEN_LONG; }
"register"              { count();return TOKEN_REGISTER; }
"return"                { count();return TOKEN_RETURN; }
"short"                 { count();return TOKEN_SHORT; }
"signed"                { count();return TOKEN_SIGNED; }
"sizeof"                { count();return TOKEN_SIZEOF; }
"static"                { count();return TOKEN_STATIC; }
"struct"                { count();return TOKEN_STRUCT; }
"switch"                { count();return TOKEN_SWITCH; }
"typedef"               { count();return TOKEN_TYPEDEF; }
"union"                 { count();return TOKEN_UNION; }
"unsigned"              { count();return TOKEN_UNSIGNED; }
"void"                  { count();return TOKEN_VOID; }
"volatile"              { count();return TOKEN_VOLATILE; }
"while"                 { count();return TOKEN_WHILE; }

[a-zA-Z_]([a-zA-Z_]|[0-9]|\$|[\r])* { count();return identifier(); }

0[xX][a-fA-F0-9]+(u|U|l|L)*     { count();return TOKEN_HEX_CONST; }
0[0-9]+(u|U|l|L)*               { count();return TOKEN_OCT_CONST; }
[0-9]+(u|U|l|L)*                { count();return TOKEN_DEC_CONST; }
'(\\.|[^\\'])+'                 { count();return TOKEN_CHAR_CONST; }

[0-9]+[Ee][+-]?[0-9]+(f|F|l|L)*              { count();return TOKEN_FLOAT_CONST; }
[0-9]*"."[0-9]+([Ee][+-]?[0-9]+)?(f|F|l|L)*  { count();return TOKEN_FLOAT_CONST; }
[0-9]+"."[0-9]*([Ee][+-]?[0-9]+)?(f|F|l|L)*  { count();return TOKEN_FLOAT_CONST; }

\"(\\.|[^\\"])*\"       { count();return string_const(); }

">>="                   { count();return TOKEN_RIGHT_ASSIGN; }
"<<="                   { count();return TOKEN_LEFT_ASSIGN; }
"+="                    { count();return TOKEN_ADD_ASSIGN; }
"-="                    { count();return TOKEN_SUB_ASSIGN; }
"*="                    { count();return TOKEN_MUL_ASSIGN; }
"/="                    { count();return TOKEN_DIV_ASSIGN; }
"%="                    { count();return TOKEN_MOD_ASSIGN; }
"&="                    { count();return TOKEN_AND_ASSIGN; }
"^="                    { count();return TOKEN_XOR_ASSIGN; }
"|="                    { count();return TOKEN_OR_ASSIGN; }
">>"                    { count();return TOKEN_RIGHT_OP; }
"<<"                    { count();return TOKEN_LEFT_OP; }
"++"                    { count();return TOKEN_INC_OP; }
"--"                    { count();return TOKEN_DEC_OP; }
"->"                    { count();return TOKEN_PTR_OP; }
"&&"                    { count();return TOKEN_AND_OP; }
"||"                    { count();return TOKEN_OR_OP; }
"<="                    { count();return TOKEN_LE_OP; }
">="                    { count();return TOKEN_GE_OP; }
"=="                    { count();return TOKEN_EQ_OP; }
"!="                    { count();return TOKEN_NE_OP; }
";"                     { count();return ';'; }
"{"                     { count();return '{'; }
"}"                     { count();return '}'; }
","                     { count();return ','; }
":"                     { count();return ':'; }
"="                     { count();return '='; }
"("                     { count();return '('; }
")"                     { count();return ')'; }
"["                     { count();return '['; }
"]"                     { count();return ']'; }
"."                     { count();return '.'; }
"&"                     { count();return '&'; }
"!"                     { count();return '!'; }
"~"                     { count();return '~'; }
"-"                     { count();return '-'; }
"+"                     { count();return '+'; }
"*"                     { count();return '*'; }
"/"                     { count();return '/'; }
"%"                     { count();return '%'; }
"<"                     { count();return '<'; }
">"                     { count();return '>'; }
"^"                     { count();return '^'; }
"|"                     { count();return '|'; }
"?"                     { count();return '?'; }
 
[ \t\v\f]               { count();/* eat white space */ }
[\n\r]                  { count();clex_lineno++; }
.                       { count();no_match(); }

%%

int yywrap(void)
{
    return 1;
}

static
int identifier(void)
{
    char *  c;

    while ((c = strchr(yytext, '\r')) != (char *)NULL)
    {
        memmove(c, c + 1, strlen(c));
        clexreal_column = 0;
        clex_column = 0;
        clex_lineno++;
    }
    return TOKEN_IDENTIFIER;
}

static
int string_const(void)
{
    char *  c;

    while ((c = strchr(yytext, '\r')) != (char *)NULL)
    {
        memmove(c, c + 1, strlen(c));
        clexreal_column = 0;
        clex_column = 0;
        clex_lineno++;
    }
    return TOKEN_STRING_CONST;
}

static
void accumulate_comment(char *data, int length)
{
    int     need;
    char *  text = yyccomment;

    need = yyclength + length + 1;
    need = (need + 127) / 128 * 128;
    if (need > yycsize)
    {
        text = (char *)(yycsize ? realloc(yyccomment, need) : malloc(need));
        if (text == (char *)NULL)
            return;
        yycsize = need;
        yyccomment = text;
    }
    memcpy(yyccomment + yyclength, data, length);
    yyclength += length;
    *(yyccomment + yyclength) = '\0';
}

static void 
count()
{
	int i;

        if (clexreal_column != 0)
        {
          clex_column = clexreal_column+1;
        }
	for (i = 0; yytext[i] != '\0'; i++)
        {
		if (yytext[i] == '\n')
                {
                        clexreal_column = 0;
			clex_column = 0;
		} else if (yytext[i] == '\t') {
			clexreal_column += 8 - (clexreal_column % 8);
		}else {
			clexreal_column++;
                }
        }
}



static
void reset_comment(void)
{
    if (yyccomment != (char *)NULL)
        *yyccomment = '\0';
    yyclength = 0;
}

static
int cstyle_comment(void)
{
    char    c;

    reset_comment();
    while ((c = input()) && c != -1)
    {
        clexreal_column++;
        accumulate_comment(&c, 1);
        if (c == '\n' || c == '\r')
        {
            clexreal_column = 0;
            clex_column = 0;
            clex_lineno++;
        }
        while (c == '*')
        {
            if (!(c = input()) || c == -1)
                return TOKEN_COMMENT;
            clexreal_column++;
            if (c == '\n' || c == '\r')
            {
                clexreal_column = 0;
                clex_column = 0;
                clex_lineno++;
            }
            if (c == '/')
                return TOKEN_COMMENT;
            else
            {
                char tmp[2] = { '*', c };
                accumulate_comment(tmp, sizeof(tmp));
            }
        }
    }

    return TOKEN_COMMENT;
}

static
int preprocessor(void)
{
    char    c;

    while ((c = input()) && c != -1)
    {
        clexreal_column++;
        if (c == '\n')
        {
            clex_lineno++;
            clexreal_column = 0;
            clex_column = 0;
            break;
        }
        if (c == '\r')
        {
            clex_lineno++;
            clexreal_column = 0;
            clex_column = 0;
        }

        /* handle multi-line comments beginning on a preprocessor line */
        if (c == '/')
        {
            if (!(c = input()) || c == -1)
                break;
            clexreal_column++;
            if (c == '*')
            {
                int save_lineno = clex_lineno;

                cstyle_comment();
                if (clex_lineno != save_lineno)
                    return TOKEN_COMMENT;
                continue;
            }
            clexreal_column--;
            unput(c);
        }
    }

    return TOKEN_JUNK;
}

static
void no_match(void)
{
    fprintf(stderr, "%s:%d: warning: bad token `%s'\n", current_file, clex_lineno, yytext);
}
