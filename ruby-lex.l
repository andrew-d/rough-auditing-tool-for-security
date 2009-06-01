/* 
 *
 */



%{
#include <string.h>
#include "tokens.h"
#include "engine.h"

int rubylexreal_column = 0;
int rubylex_column = 0;
int rubylex_lineno = 1;
//int yyclength = 0;
int yyrubysize = 0;
char *yyrubycomment = NULL;

// Forward declaration
static void count(void);
static int  identifier(void);
static void reset_comment(void);
static int  rubystyle_comment(void);
static void ruby_accumulate_comment(char *data, int length);
static void no_match(void);
static void gobble_string(char c);
static void scan_yytext(void);

#define YY_INPUT(buf, result, max_size)                                     \
    if (((result = fread(buf, 1, max_size, yyin)) == 0) && ferror(yyin)) { \
        YY_FATAL_ERROR("input in flex scanner failed");                     \
    } else {                                                                  \
        if (result) {                                                           \ 
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
        }                                                                       \
    }
%}

%%

"#".*					{ count();	reset_comment();  
								ruby_accumulate_comment(yytext+1,strlen(yytext+1)); 
								return TOKEN_COMMENT; }
								
[\n\r]				{ count();	rubylex_lineno++; return TOKEN_NEWLINE; }
[ \t\v\f]			{ count(); }
^[ \r\t]*"#".*\n	{ count();	rubylex_lineno++; }


=begin		{count();return rubystyle_comment();}

alias 	 	{count(); return TOKEN_ALIAS 	;}
and 	 	{count(); return TOKEN_AND 		;}
BEGIN 	 	{count(); return TOKEN_BEGIN 	;}
begin 	 	{count(); return TOKEN_BEGIN 	;}
break 	 	{count(); return TOKEN_BREAK 	;}
case 	 	{count(); return TOKEN_CASE 	;}
class 	 	{count(); return TOKEN_CLASS 	;}
def 	 	{count(); return TOKEN_DEF 		;}
defined 	{count(); return TOKEN_DEFINED 	;}
do 	 		{count(); return TOKEN_DO 		;}
else 	 	{count(); return TOKEN_ELSE 	;}
elsif 	 	{count(); return TOKEN_ELSIF 	;}
END 	 	{count(); return TOKEN_END 		;}
end 	 	{count(); return TOKEN_END 		;}
ensure 	 	{count(); return TOKEN_ENSURE 	;}
false 	 	{count(); return TOKEN_FALSE 	;}
for 	 	{count(); return TOKEN_FOR 		;}
if 	 		{count(); return TOKEN_IF 		;}
in 	 		{count(); return TOKEN_IN 		;}
module 	 	{count(); return TOKEN_MODULE 	;}
next 	 	{count(); return TOKEN_NEXT 	;}
nil 	 	{count(); return TOKEN_NIL 		;}
not 	 	{count(); return TOKEN_NOT 		;}
or 	 		{count(); return TOKEN_OR 		;}
redo 	 	{count(); return TOKEN_REDO 	;}
rescue 	 	{count(); return TOKEN_RESCUE 	;}
retry 	 	{count(); return TOKEN_RETRY 	;}
return 	 	{count(); return TOKEN_RETURN 	;}
self 	 	{count(); return TOKEN_SELF 	;}
super 	 	{count(); return TOKEN_SUPER 	;}
then 	 	{count(); return TOKEN_THEN 	;}
true 	 	{count(); return TOKEN_TRUE 	;}
undef 	 	{count(); return TOKEN_UNDEF 	;}
unless 	 	{count(); return TOKEN_UNLESS 	;}
until 	 	{count(); return TOKEN_UNTIL 	;}
when 	 	{count(); return TOKEN_WHEN 	;}
while 	 	{count(); return TOKEN_WHILE 	;}
yield 	 	{count(); return TOKEN_YIELD 	;}

("\'")	{ count();gobble_string('\''); return TOKEN_SSTRING_LITERAL; }
("\"")  { count();gobble_string('"'); return TOKEN_SSTRING_LITERAL; }

0[xX][a-fA-F0-9]+(l|L)*					{count(); return TOKEN_HEX_CONST; }
0[0-9]+(l|L)*							{count(); return TOKEN_OCT_CONST; }
[0-9]+(l|L)*							{count(); return TOKEN_DEC_CONST; }
[0-9]+[Ee][+-]?[0-9]+					{count(); return TOKEN_FLOAT_CONST; }
[0-9]*"."[0-9]+([Ee][+-]?[0-9]+)?		{count(); return TOKEN_FLOAT_CONST; }
[0-9]+"."[0-9]*([Ee][+-]?[0-9]+)?		{count(); return TOKEN_FLOAT_CONST; }
[1-9][0-9]*(j|J)						{count(); return TOKEN_IMAG_CONST; }
[0-9]+[Ee][+-]?[0-9]+(j|J)              {count(); return TOKEN_IMAG_CONST; }
[0-9]*"."[0-9]+([Ee][+-]?[0-9]+)?(j|J)  {count(); return TOKEN_IMAG_CONST; }
[0-9]+"."[0-9]*([Ee][+-]?[0-9]+)?(j|J)  {count(); return TOKEN_IMAG_CONST; }
"/".*"/"								{count(); return TOKEN_REGEXP; }

@[a-zA-Z_0-9\r]*					{count(); return TOKEN_INSTANCE_VARIABLE; }
@@[a-zA-Z_0-9\r]*				{count(); return TOKEN_CLASS_VARIABLE; }
$[a-zA-Z_0-9\r]*					{count(); return TOKEN_GLOBAL_VARIABLE; }
[a-zA-Z_][a-zA-Z_0-9\?\!\r]*		{count(); return identifier(); }


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
">>"            {count(); return TOKEN_RIGHT_OP; }
"<<"            {count(); return TOKEN_LEFT_OP; }
"**"            {count(); return TOKEN_EXP_OP; }
"<="            {count(); return TOKEN_LE_OP; }
">="            {count(); return TOKEN_GE_OP; }
"=="            {count(); return TOKEN_EQ_OP; }
"!="            {count(); return TOKEN_NE_OP; }
"<>"            {count(); return TOKEN_NE_OP; }
"&"             {count(); return '&'; }
"~"             {count(); return '~'; }
"-"             {count(); return '-'; }
"+"             {count(); return '+'; }
"*"             {count(); return '*'; }
"/"             {count(); return '/'; }
"\\"             {count(); return '\\'; }
"%"             {count(); return '%'; }
"<"             {count(); return '<'; }
">"             {count(); return '>'; }
"^"             {count(); return '^'; }
"|"             {count(); return '|'; }
"`"			{count(); return '`'; } 
"("			{count(); return '('; }
")"			{count(); return ')'; }
"["			{count(); return '['; }
"]"			{count(); return ']'; }
"{"			{count(); return '{'; }
"}"			{count(); return '}'; }
","			{count(); return ','; }
":"			{count(); return ':'; }
"."			{count(); return '.'; }
"="			{count(); return '='; }
";"			{count(); return ';'; }
"!"			{count(); return '!'; }
"?"			{count(); return '?'; }

.           { count();no_match(); }

%%

int yywrap(void)
{
    return 1;
}


static void
count()
{
        int i;

        if (rubylexreal_column != 0)
        {
          rubylex_column = rubylexreal_column+1;
        }
        for (i = 0; yytext[i] != '\0'; i++)
        {
                if (yytext[i] == '\n')
                {
                        rubylexreal_column = 0;
                        rubylex_column = 0;
                } else if (yytext[i] == '\t') {
                        rubylexreal_column += 8 - (rubylexreal_column % 8);
                }else {
                        rubylexreal_column++;
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

    rubylexreal_column++;
    switch(c)  {

      case '\\':
                 if (!bslash)
                   bslash = 1;
                 else
                   bslash = 0;
                 break;
      case '\n':
                 rubylexreal_column = 0;
                 rubylex_column = 0;
                 rubylex_lineno++;
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
       
        rubylexreal_column = 0;
        rubylex_column = 0;
        rubylex_lineno++;
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
        rubylexreal_column = 0;
        rubylex_column = 0;
        rubylex_lineno++;
    }
    return TOKEN_IDENTIFIER;
}

static
void no_match(void)
{
    fprintf(stderr, "%s:%d: warning: bad token `%s'\n", current_file, rubylex_lineno, yytext);
}

static
void ruby_accumulate_comment(char *data, int length)
{
    int need = 0;
    char *  text = yyrubycomment;

    need = yyclength + length + 1;
    need = (need + 127) / 128 * 128;
    if (need > yyrubysize)
    {
        text = (char *)(yyrubysize ? realloc(yyrubycomment, need) : malloc(need));
        if (text == (char *)NULL)
            return;
        yyrubysize = need;
        yyrubycomment = text;
    }
    memcpy(yyrubycomment + yyclength, data, length);
    yyclength += length;
    *(yyrubycomment + yyclength) = '\0';
}

static
void reset_comment(void)
{
    if (yyrubycomment != (char *)NULL)
        *yyrubycomment = '\0';
    yyclength = 0;
}

static
int rubystyle_comment(void)
{
    char    c;
    int i;
    int flag = 0;

    reset_comment();
    while ((c = input()) && c != -1)
    {
        rubylexreal_column++;
        ruby_accumulate_comment(&c, 1);
        if (c == '\n' || c == '\r')
        {
            rubylexreal_column = 0;
            rubylex_column = 0;

            rubylex_lineno++;
        }
        while (c == '=')
        {
			char tmp[4] = {0};
			tmp[0] = '=';
			
            rubylexreal_column++;
            
            for (i = 1; i < 4; i++)
            {
				if (!(c = input()) || c == -1) {
					return TOKEN_COMMENT;
				}
	            
				if (c == '\n' || c == '\r')
				{
					rubylexreal_column = 0;
					rubylex_column = 0;
					rubylex_lineno++;
				}
				
				if (c == '=')
				{
				    ruby_accumulate_comment(tmp, i);
				    flag = 1;
				    break;
				}
	            
				tmp[i] = c;
            }
            
            if (flag == 1)
            {
				flag = 0;
				continue;
            }
            
            if (!memcmp(tmp,"=end",sizeof(tmp)))  {
                return TOKEN_COMMENT;
            } else
            {
                ruby_accumulate_comment(tmp, sizeof(tmp));
            }
        }
    }
    return TOKEN_COMMENT;
}
