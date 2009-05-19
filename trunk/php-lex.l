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

%x IN_PHP_SCRIPT
%x IN_PHP_OCOMMENT
%option stack

%{
#include <string.h>
#include "tokens.h"
#include "engine.h"

int phplexreal_column = 0;
int phplex_column = 0;
int phplex_lineno = 1;
int yyphplength = 0;
int yyphpsize = 0;
char *yyphpcomment = NULL;

static void count(void);
static int  identifier(void);
static void reset_comment(void);
static int  cstyle_comment(void);
static void no_match(void);
static void gobble_string(char c);
static void scan_yytext(void);

#define YY_INPUT(buf, result, max_size)                                     \
    if (((result = fread(buf, 1, max_size, yyin)) == 0) && ferror(yyin)) { \
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
            fseek(yyin, -1, SEEK_CUR);                                      \
        }                                                                   \
    }

%}



LNUM    [0-9]+
DNUM    ([0-9]*[\.][0-9]+)|([0-9]+[\.][0-9]*)
EXPONENT_DNUM   (({LNUM}|{DNUM})[eE][+-]?{LNUM})
HNUM    "0x"[0-9a-fA-F]+
LABEL   [a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*
WHITESPACE [ \n\r\t]+
TABS_AND_SPACES [ \t]*
TOKENS [;:,.\[\]()|^&+-/*=%!~$<>?@]
NEWLINE ("\r"|"\n"|"\r\n")


%%

<INITIAL>"<?"|"<script"{WHITESPACE}+"language"{WHITESPACE}*"="{WHITESPACE}*("php"|"\"php\""|"\'php\'"){WHITESPACE}*">"  {
    BEGIN(IN_PHP_SCRIPT);
    scan_yytext();
    count();
    return TOKEN_PHP_IN_SCRIPT;
}
   

<INITIAL>"<%="|"<?="  {
    BEGIN(IN_PHP_SCRIPT);
    count();
    return TOKEN_PHP_IN_SCRIPT;
}

<INITIAL>"<%"  {

    BEGIN(IN_PHP_SCRIPT);
    count();
    return TOKEN_PHP_IN_SCRIPT;
}


<INITIAL>"<?php"([ \t]|{NEWLINE})  {
    
    BEGIN(IN_PHP_SCRIPT);
    scan_yytext();
    count();
    return TOKEN_PHP_IN_SCRIPT;
}



<IN_PHP_SCRIPT,IN_PHP_OCOMMENT>("?>"|"</script"{WHITESPACE}*">"){NEWLINE}?  {
    BEGIN(INITIAL);
    scan_yytext();
    count();
    return TOKEN_PHP_IN_SCRIPT;

}

<IN_PHP_SCRIPT,IN_PHP_OCOMMENT>"%>"{NEWLINE}?  {
    BEGIN(INITIAL);
    scan_yytext();
    count();
    return TOKEN_PHP_IN_SCRIPT;
}




<IN_PHP_SCRIPT>"#"|"//"		{
                                  BEGIN(IN_PHP_OCOMMENT);
                                  count();
                                  return TOKEN_COMMENT;
                                }
 

<IN_PHP_SCRIPT>"/*"		{count();return cstyle_comment();}
<IN_PHP_SCRIPT>"$"	       {count();return '$';}
<IN_PHP_SCRIPT>"old_function"  {count();return TOKEN_FUNCTION;}
<IN_PHP_SCRIPT>"function"|"cfunction" {count();return TOKEN_FUNCTION;}
<IN_PHP_SCRIPT>"const"		{count();return TOKEN_CONST;}
<IN_PHP_SCRIPT>"return"		{count();return TOKEN_RETURN;}
<IN_PHP_SCRIPT>"if"		{count();return TOKEN_IF;}
<IN_PHP_SCRIPT>"elseif"		{count();return TOKEN_ELSEIF;}
<IN_PHP_SCRIPT>"else"		{count();return TOKEN_ELSE;}
<IN_PHP_SCRIPT>"while"		{count();return TOKEN_WHILE;}
<IN_PHP_SCRIPT>"endwhile"	{count();return TOKEN_ENDWHILE;}
<IN_PHP_SCRIPT>"do"		{count();return TOKEN_DO;}
<IN_PHP_SCRIPT>"for"		{count();return TOKEN_FOR;}
<IN_PHP_SCRIPT>"endfor"		{count();return TOKEN_ENDFOR;}
<IN_PHP_SCRIPT>"foreach"	{count();return TOKEN_FOREACH;}
<IN_PHP_SCRIPT>"endforeach"	{count();return TOKEN_ENDFOREACH;}
<IN_PHP_SCRIPT>"declare"	{count();return TOKEN_DECLARE;}
<IN_PHP_SCRIPT>"enddeclare"	{count();return TOKEN_ENDDECLARE;}
<IN_PHP_SCRIPT>"as"		{count();return TOKEN_AS;}
<IN_PHP_SCRIPT>"switch"		{count();return TOKEN_SWITCH;}
<IN_PHP_SCRIPT>"endswitch"	{count();return TOKEN_ENDSWITCH;}
<IN_PHP_SCRIPT>"case"		{count();return TOKEN_CASE;}
<IN_PHP_SCRIPT>"default"	{count();return TOKEN_DEFAULT;}
<IN_PHP_SCRIPT>"break"		{count();return TOKEN_BREAK;}
<IN_PHP_SCRIPT>"continue"	{count();return TOKEN_CONTINUE;}
<IN_PHP_SCRIPT>"print"		{count();return TOKEN_PRINT;}
<IN_PHP_SCRIPT>"class"		{count();return TOKEN_CLASS;}
<IN_PHP_SCRIPT>"extends"	{count();return TOKEN_EXTENDS;}
<IN_PHP_SCRIPT>"var"		{count();return TOKEN_VAR;}
<IN_PHP_SCRIPT>"=>"		{count();return TOKEN_DOUBLE_ARROW;}
<IN_PHP_SCRIPT>"++"		{count();return TOKEN_INC_OP;}
<IN_PHP_SCRIPT>"--"		{count();return TOKEN_DEC_OP;}
<IN_PHP_SCRIPT>"==="           {count();return TOKEN_T_EQUAL;}
<IN_PHP_SCRIPT>"!=="	        {count();return TOKEN_T_NOTEQUAL;}	
<IN_PHP_SCRIPT>"=="		{count();return TOKEN_EQ_OP;}
<IN_PHP_SCRIPT>"!="|"<>"	{count();return TOKEN_NE_OP;}
<IN_PHP_SCRIPT>"<="		{count();return TOKEN_LE_OP;}
<IN_PHP_SCRIPT>">="		{count();return TOKEN_GE_OP;}
<IN_PHP_SCRIPT>"+="		{count();return TOKEN_ADD_ASSIGN;}
<IN_PHP_SCRIPT>"-="		{count();return TOKEN_SUB_ASSIGN;}
<IN_PHP_SCRIPT>"*="		{count();return TOKEN_MUL_ASSIGN;}
<IN_PHP_SCRIPT>"/="		{count();return TOKEN_DIV_ASSIGN;}
<IN_PHP_SCRIPT>".="		{count();return TOKEN_CONCAT_ASSIGN;}
<IN_PHP_SCRIPT>"%="		{count();return TOKEN_MOD_ASSIGN;}
<IN_PHP_SCRIPT>"<<="		{count();return TOKEN_LEFT_ASSIGN;}
<IN_PHP_SCRIPT>">>="		{count();return TOKEN_RIGHT_ASSIGN;}
<IN_PHP_SCRIPT>"&="		{count();return TOKEN_AND_ASSIGN;}
<IN_PHP_SCRIPT>"|="		{count();return TOKEN_OR_ASSIGN;}
<IN_PHP_SCRIPT>"^="		{count();return TOKEN_XOR_ASSIGN;}
<IN_PHP_SCRIPT>"||"		{count();return TOKEN_OR_OP;}
<IN_PHP_SCRIPT>"&&"		{count();return TOKEN_AND_OP;}
<IN_PHP_SCRIPT>"OR"		{count();return TOKEN_OR_OP;}
<IN_PHP_SCRIPT>"AND"		{count();return TOKEN_AND_OP;}
<IN_PHP_SCRIPT>"XOR"		{count();return TOKEN_XOR_OP;}
<IN_PHP_SCRIPT>"<<"		{count();return TOKEN_LEFT_OP;}
<IN_PHP_SCRIPT>">>"		{count();return TOKEN_RIGHT_OP;}
<IN_PHP_SCRIPT>{HNUM}		{count();return TOKEN_HEX_CONST;}
<IN_PHP_SCRIPT>{DNUM}		{count();return TOKEN_DEC_CONST;}
<IN_PHP_SCRIPT>{LNUM}		{count();return TOKEN_DEC_CONST;}
<IN_PHP_SCRIPT>{EXPONENT_DNUM}	{count();return TOKEN_DEC_CONST;}
<IN_PHP_SCRIPT>{LABEL}		{count();return identifier();}

<IN_PHP_SCRIPT>";"                     { count();return ';'; }
<IN_PHP_SCRIPT>"{"                     { count();return '{'; }
<IN_PHP_SCRIPT>"}"                     { count();return '}'; }
<IN_PHP_SCRIPT>","                     { count();return ','; }
<IN_PHP_SCRIPT>":"                     { count();return ':'; }
<IN_PHP_SCRIPT>"="                     { count();return '='; }
<IN_PHP_SCRIPT>"("                     { count();return '('; }
<IN_PHP_SCRIPT>")"                     { count();return ')'; }
<IN_PHP_SCRIPT>"["                     { count();return '['; }
<IN_PHP_SCRIPT>"]"                     { count();return ']'; }
<IN_PHP_SCRIPT>"."                     { count();return '.'; }
<IN_PHP_SCRIPT>"&"                     { count();return '&'; }
<IN_PHP_SCRIPT>"!"                     { count();return '!'; }
<IN_PHP_SCRIPT>"~"                     { count();return '~'; }
<IN_PHP_SCRIPT>"-"                     { count();return '-'; }
<IN_PHP_SCRIPT>"+"                     { count();return '+'; }
<IN_PHP_SCRIPT>"*"                     { count();return '*'; }
<IN_PHP_SCRIPT>"/"                     { count();return '/'; }
<IN_PHP_SCRIPT>"%"                     { count();return '%'; }
<IN_PHP_SCRIPT>"<"                     { count();return '<'; }
<IN_PHP_SCRIPT>"`"                     { count();return '`'; }

<IN_PHP_SCRIPT>">"                     { count();return '>'; }
<IN_PHP_SCRIPT>"^"                     { count();return '^'; }
<IN_PHP_SCRIPT>"@"		       {count();return '@'; }
<IN_PHP_SCRIPT>"|"                     { count();return '|'; }
<IN_PHP_SCRIPT>"?"                     { count();return '?'; }
<IN_PHP_SCRIPT>("\"")                  { count();gobble_string('"'); return TOKEN_STRING_CONST; }
<IN_PHP_SCRIPT>("'")                  { count();gobble_string('\''); return TOKEN_STRING_CONST; }


<*>[ \t\v\f]               { /* eat white space */ }
<IN_PHP_OCOMMENT>[\n\r]   { BEGIN(IN_PHP_SCRIPT); count();phplex_lineno++; } 
<INITIAL,IN_PHP_SCRIPT>[\n\r]                  { count();phplex_lineno++; }
<IN_PHP_OCOMMENT>.		       { count();/* eat it! */}
<IN_PHP_SCRIPT>.                       { count();no_match(); }
<INITIAL>.			       { count();/* it's just HTML, we don't care */}

%%


int yywrap(void)
{
    return 1;
}


static void
count()
{
        int i;

        if (phplexreal_column != 0)
        {
          phplex_column = phplexreal_column+1;
        }
        for (i = 0; yytext[i] != '\0'; i++)
        {
                if (yytext[i] == '\n')
                {
                        phplexreal_column = 0;
                        phplex_column = 0;
                } else if (yytext[i] == '\t') {
                        phplexreal_column += 8 - (phplexreal_column % 8);
                }else {
                        phplexreal_column++;
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

    phplexreal_column++;
    switch(c)  {

      case '\\':
                 if (!bslash)
                   bslash = 1;
                 else
                   bslash = 0;
                 break;
      case '\n':
                 phplexreal_column = 0;
                 phplex_column = 0;
                 phplex_lineno++;
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
void scan_yytext(void)
{

    char *tmp;
    tmp = yytext;
    while(*tmp)  {
      if(*tmp == '\n' || *tmp == '\r')
      {
       
        phplexreal_column = 0;
        phplex_column = 0;
        phplex_lineno++;
      }
      tmp++;
    }
}

         
static
int identifier(void)
{
    char *  c;

    while ((c = strchr(yytext, '\r')) != (char *)NULL)
    {
        memmove(c, c + 1, strlen(c));
        phplexreal_column = 0;
        phplex_column = 0;
        phplex_lineno++;
    }
    return TOKEN_IDENTIFIER;
}

static
void no_match(void)
{
    fprintf(stderr, "%s:%d: warning: bad token `%s'\n", current_file, phplex_lineno, yytext);
}

static
void accumulate_comment(char *data, int length)
{
    int     need;
    char *  text = yyphpcomment;

    need = yyphplength + length + 1;
    need = (need + 127) / 128 * 128;
    if (need > yyphpsize)
    {
        text = (char *)(yyphpsize ? realloc(yyphpcomment, need) : malloc(need));
        if (text == (char *)NULL)
            return;
        yyphpsize = need;
        yyphpcomment = text;
    }
    memcpy(yyphpcomment + yyphplength, data, length);
    yyphplength += length;
    *(yyphpcomment + yyphplength) = '\0';
}

static
void reset_comment(void)
{
    if (yyphpcomment != (char *)NULL)
        *yyphpcomment = '\0';
    yyphplength = 0;
}

static
int cstyle_comment(void)
{
    char    c;

    reset_comment();
    while ((c = input()) && c != -1)
    {
        phplexreal_column++;
        accumulate_comment(&c, 1);
        if (c == '\n' || c == '\r')
        {
            phplexreal_column = 0;
            phplex_column = 0;

            phplex_lineno++;
        }
        while (c == '*')
        {
            phplexreal_column++;
            if (!(c = input()) || c == -1) {
                return TOKEN_COMMENT;
            }
            if (c == '\n' || c == '\r')
            {
                phplexreal_column = 0;
                phplex_column = 0;
                phplex_lineno++;
            }
            if (c == '/')  {
                return TOKEN_COMMENT;
            } else
            {
                char tmp[2] = { '*', c };
                accumulate_comment(tmp, sizeof(tmp));
            }
        }
    }
    return TOKEN_COMMENT;
}

