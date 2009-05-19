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

int plexreal_column = 0;
int plex_column = 0;
int plex_lineno = 1;
int pyyclength = 0;
int pyycsize = 0;
char *yypcomment = NULL;
static void gobble_string(char c);

static int  identifier(void);
static void no_match(void);
static int longstring(int);
static void count(void);



#define YY_INPUT(buf, result, max_size)                                     \
    if (((result = fread(buf, 1, max_size, yyin)) == 0) && ferror(yyin))    \
        YY_FATAL_ERROR("input in flex scanner failed");                     \
    else {                                                                  \
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
            fseek(yyin, -1, SEEK_CUR);                                      \
        }                                                                   \
    }

%}

%%

[\n\r]			{ count();plex_lineno++; return TOKEN_NEWLINE; }
[ \t\v\f]		{ count(); }
^[ \r\t]*"#".*\n	{ count();plex_lineno++; }
"#".*			{ count(); }

and			{count(); return TOKEN_AND; }
assert			{count(); return TOKEN_ASSERT; }
break			{count(); return TOKEN_BREAK; }
class			{count(); return TOKEN_CLASS; }
continue		{count(); return TOKEN_CONTINUE; }
def			{count(); return TOKEN_DEF; }
del			{count(); return TOKEN_DEL; }
elif			{count(); return TOKEN_ELIF; }
else			{count(); return TOKEN_ELSE; }
except			{count(); return TOKEN_EXCEPT; }
exec			{count(); return TOKEN_EXEC; }
finally			{count(); return TOKEN_FINALLY; }
for			{count(); return TOKEN_FOR; }
from			{count(); return TOKEN_FROM; }
global			{count(); return TOKEN_GLOBAL; }
if			{count(); return TOKEN_IF; }
import			{count(); return TOKEN_IMPORT; }
in			{count(); return TOKEN_IN; }
is			{count(); return TOKEN_IS; }
lambda			{count(); return TOKEN_LAMBDA; }
not			{count(); return TOKEN_NOT; }
or			{count(); return TOKEN_OR; }
pass			{count(); return TOKEN_PASS; }
print			{count(); return TOKEN_PRINT; }
raise			{count(); return TOKEN_RAISE; }
return			{count(); return TOKEN_RETURN; }
try			{count(); return TOKEN_TRY; }
while			{count(); return TOKEN_WHILE; }

("\'") { count();gobble_string('\''); return TOKEN_SSTRING_LITERAL; }
("\"")  { count();gobble_string('"'); return TOKEN_SSTRING_LITERAL; }

\"\"\"  {count();return longstring('\"');}
\'\'\'  {count();return longstring('\'');}

0[xX][a-fA-F0-9]+(l|L)*     {count(); return TOKEN_HEX_CONST; }
0[0-9]+(l|L)*               {count(); return TOKEN_OCT_CONST; }
[0-9]+(l|L)*                {count(); return TOKEN_DEC_CONST; }
[0-9]+[Ee][+-]?[0-9]+              {count(); return TOKEN_FLOAT_CONST; }
[0-9]*"."[0-9]+([Ee][+-]?[0-9]+)?  {count(); return TOKEN_FLOAT_CONST; }
[0-9]+"."[0-9]*([Ee][+-]?[0-9]+)?  {count(); return TOKEN_FLOAT_CONST; }
[1-9][0-9]*(j|J)			{count(); return TOKEN_IMAG_CONST; }
[0-9]+[Ee][+-]?[0-9]+(j|J)              {count(); return TOKEN_IMAG_CONST; }
[0-9]*"."[0-9]+([Ee][+-]?[0-9]+)?(j|J)  {count(); return TOKEN_IMAG_CONST; }
[0-9]+"."[0-9]*([Ee][+-]?[0-9]+)?(j|J)  {count(); return TOKEN_IMAG_CONST; }

[a-zA-Z_]([a-zA-Z_]|[0-9]|\$|[\r])* {count(); return identifier(); }

">>="			{count(); return TOKEN_RIGHT_ASSIGN; }
"<<="			{count(); return TOKEN_LEFT_ASSIGN; }
"**="			{count(); return TOKEN_EXP_ASSIGN; }
"+="			{count(); return TOKEN_ADD_ASSIGN; }
"-="			{count(); return TOKEN_SUB_ASSIGN; }
"*="			{count(); return TOKEN_MUL_ASSIGN; }
"/="			{count(); return TOKEN_DIV_ASSIGN; }
"%="			{count(); return TOKEN_MOD_ASSIGN; }
"&="			{count(); return TOKEN_AND_ASSIGN; }
"|="			{count(); return TOKEN_OR_ASSIGN; }
"^="			{count(); return TOKEN_XOR_ASSIGN; }
">>"                    {count(); return TOKEN_RIGHT_OP; }
"<<"                    {count(); return TOKEN_LEFT_OP; }
"**"                    {count(); return TOKEN_EXP_OP; }
"<="                    {count(); return TOKEN_LE_OP; }
">="                    {count(); return TOKEN_GE_OP; }
"=="                    {count(); return TOKEN_EQ_OP; }
"!="                    {count(); return TOKEN_NE_OP; }
"<>"                    {count(); return TOKEN_NE_OP; }
"&"                     {count(); return '&'; }
"~"                     {count(); return '~'; }
"-"                     {count(); return '-'; }
"+"                     {count(); return '+'; }
"*"                     {count(); return '*'; }
"/"                     {count(); return '/'; }
"%"                     {count(); return '%'; }
"<"                     {count(); return '<'; }
">"                     {count(); return '>'; }
"^"                     {count(); return '^'; }
"|"                     {count(); return '|'; }
 
"("			{count(); return '('; }
")"			{count(); return ')'; }
"["			{count(); return '['; }
"]"			{count(); return ']'; }
"{"			{count(); return '{'; }
"}"			{count(); return '}'; }
","			{count(); return ','; }
":"			{count(); return ':'; }
"."			{count(); return '.'; }
"`"			{count(); return '`'; }
"="			{count(); return '='; }
";"			{count(); return ';'; }

.                       { count();no_match(); }

%%

int yywrap(void)
{
    return 1;
}


static void
count()
{
        int i;

        if (plexreal_column != 0)
        {
          plex_column = plexreal_column+1;
        }
        for (i = 0; yytext[i] != '\0'; i++)
        {
                if (yytext[i] == '\n')
                {
                        plexreal_column = 0;
                        plex_column = 0;
                } else if (yytext[i] == '\t') {
                        plexreal_column += 8 - (plexreal_column % 8);
                }else {
                        plexreal_column++;
                }
        }
}

static
void gobble_string(char which)
{

  int bslash = 0;
  char c;
  while ((c = input()) && c != -1)
  {

    plexreal_column++;
    switch(c)  {

      case '\\':
                 if (!bslash)
                   bslash = 1;
                 else
                   bslash = 0;
                 break;
      case '\n':
                 plexreal_column = 0;
                 plex_column = 0;
                 plex_lineno++;
                 bslash = 0;
                 break;
      default:
                 if (c == which && !bslash)  {
                   return;
                 }
                 bslash = 0;
                 break;
    }
  }
}

static
void no_match(void)
{
    fprintf(stderr, "%s:%d: warning: bad token `%s'\n", current_file, plex_lineno, yytext);
}

static
int identifier(void)
{   
    char *  c;

    while ((c = strchr(yytext, '\r')) != (char *)NULL)
    {   
        memmove(c, c + 1, strlen(c));
        plex_column = 0;
        plexreal_column = 0;
        plex_lineno++;
    }
    return TOKEN_IDENTIFIER;
}



static
int longstring(int q)
{
    char    c;

    int quotes =  0;
    int backtick = 0;
    while ((c = input()) && c != -1)
    {
        plexreal_column++ ;
        if (c != q) 
          quotes = 0;
        if (c == '\\')  {
          backtick = 1;
          continue;
        }
         
        
        if (c == q)
        {
          if (backtick)
          {
            quotes = 0;
            backtick = 0;
          } else {
            quotes++;
          }
        }   
        backtick = 0;

       if (quotes == 3)  
       {
         return TOKEN_LSTRING_LITERAL;
       }
       if (c == '\n' || c == '\r')
       {
         plexreal_column = 0;
         plex_column = 0;
         plex_lineno++;
       }
  
    }

    return TOKEN_LSTRING_LITERAL;
}










