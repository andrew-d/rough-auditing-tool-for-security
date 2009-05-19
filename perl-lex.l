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

int perllexreal_column = 0;
int perllex_column = 0;
int perllex_lineno = 1;

char *yyperlcomment = NULL; /* for consistency, not used */

static void no_match(void);
static void gobble_pod(void);
static void count(void);
static void gobble_string(char c);


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

[\n\r]			{ count();perllex_lineno++; return TOKEN_NEWLINE; }
[ \t\v\f]		{ count(); }
^[ \r\t]*"#".*\n	{ count();perllex_lineno++; }
"#".*			{ count(); }



%{


/*
xor			{count(); return XOR; }
write			{count(); return WRITE; }
while			{count(); return WHILE; }
warn			{count(); return WARN; }
wantarray		{count(); return WANTARRAY; }
waitpid			{count(); return WAITPID; }
wait			{count(); return WAIT; }
vec			{count(); return VEC; }
values			{count(); return VALUES; }
utime			{count(); return UTIME; }
use			{count(); return USE; }
until			{count(); return UNTIL; }
untie			{count(); return UNTIE; }
unshift			{count(); return UNSHIFT; }
unpack			{count(); return UNPACK; }
unlink			{count(); return UNLINK; }
unless			{count(); return UNLESS; }
undef			{count(); return UNDEF; }
umask			{count(); return UMASK; }
ucfirst			{count(); return UCFIRST; }
uc			{count(); return UC; }
truncate		{count(); return TRUNCATE; }
tr			{count(); return TR; }
times			{count(); return TIMES; }
time			{count(); return TIME; }
tied			{count(); return TIED; }
tie			{count(); return TIE; }
telldir			{count(); return TELLDIR; }
tell			{count(); return TELL; }
syswrite		{count(); return SYSWRITE; }
system			{count(); return SYSTEM; }
sysseek			{count(); return SYSSEEK; }
sysread			{count(); return SYSREAD; }
sysopen			{count(); return SYSOPEN; }
syscall			{count(); return SYSCALL; }
symlink			{count(); return SYMLINK; }
substr			{count(); return SUBSTR; }
sub			{count(); return SUB; }
study			{count(); return STUDY; }
stat			{count(); return STAT; }
srand			{count(); return SRAND; }
sqrt			{count(); return SQRT; }
sprintf			{count(); return SPRINTF; }
split			{count(); return SPLIT; }
splice			{count(); return SPLICE; }
sort			{count(); return SORT; }
socketpair		{count(); return SOCKETPAIR; }
socket			{count(); return SOCKET; }
sleep			{count(); return SLEEP; }
sin			{count(); return SIN; }
shutdown		{count(); return SHUTDOWN; }
shmwrite		{count(); return SHMWRITE; }
shmread			{count(); return SHMREAD; }
shmget			{count(); return SHMGET; }
shmctl			{count(); return SHMCTL; }
shift			{count(); return SHIFT; }
setsockopt		{count(); return SETSOCKOPT; }
setservent		{count(); return SETSERVENT; }
setpwent		{count(); return SETPWENT; }
setprotoent		{count(); return SETPROTOENT; }
setpriority		{count(); return SETPRIORITY; }
setpgrp			{count(); return SETPGRP; }
setnetent		{count(); return SETNETENT; }
sethostent		{count(); return SETHOSTENT; }
setgrent		{count(); return SETGRENT; }
send			{count(); return SEND; }
semop			{count(); return SEMOP; }
semget			{count(); return SEMGET; }
semctl			{count(); return SEMCTL; }
select			{count(); return SELECT; }
seekdir			{count(); return SEEKDIR; }
seek			{count(); return SEEK; }
scalar			{count(); return SCALAR; }
rmdir			{count(); return RMDIR; }
rindex			{count(); return RINDEX; }
rewinddir		{count(); return REWINDDIR; }
reverse			{count(); return REVERSE; }
return			{count(); return RETURN; }
reset			{count(); return RESET; }
require			{count(); return REQUIRE; }
rename			{count(); return RENAME; }
ref			{count(); return REF; }
redo			{count(); return REDO; }
recv			{count(); return RECV; }
readpipe		{count(); return READPIPE; }
readlink		{count(); return READLINK; }
readline		{count(); return READLINE; }
readdir			{count(); return READDIR; }
read			{count(); return READ; }
rand			{count(); return RAND; }
qx			{count(); return QX; }
qw			{count(); return QW; }
quotemeta		{count(); return QUOTEMETA; }
qr			{count(); return QR; }
qq			{count(); return QQ; }
push			{count(); return PUSH; }
prototype		{count(); return PROTOTYPE; }
printf			{count(); return PRINTF; }
print			{count(); return PRINT; }
pos			{count(); return POS; }
pop			{count(); return POP; }
pipe			{count(); return PIPE; }
package			{count(); return PACKAGE; }
pack			{count(); return PACK; }
our			{count(); return OUR; }
ord			{count(); return ORD; }
or			{count(); return OR; }
opendir			{count(); return OPENDIR; }
open			{count(); return OPEN; }
oct			{count(); return OCT; }
not			{count(); return NOT; }
no			{count(); return NO; }
next			{count(); return NEXT; }
ne			{count(); return NE; }
my			{count(); return MY; }
msgsnd			{count(); return MSGSND; }
msgrcv			{count(); return MSGRCV; }
msgget			{count(); return MSGGET; }
msgctl			{count(); return MSGCTL; }
mkdir			{count(); return MKDIR; }
map			{count(); return MAP; }
lt			{count(); return LT; }
lstat			{count(); return LSTAT; }
log			{count(); return LOG; }
lock			{count(); return LOCK; }
localtime		{count(); return LOCALTIME; }
local			{count(); return LOCAL; }
listen			{count(); return LISTEN; }
link			{count(); return LINK; }
length			{count(); return LENGTH; }
le			{count(); return LE; }
lcfirst			{count(); return LCFIRST; }
lc			{count(); return LC; }
last			{count(); return LAST; }
kill			{count(); return KILL; }
keys			{count(); return KEYS; }
join			{count(); return JOIN; }
ioctl			{count(); return IOCTL; }
int			{count(); return INT; }
index			{count(); return INDEX; }
if			{count(); return IF; }
hex			{count(); return HEX; }
gt			{count(); return GT; }
grep			{count(); return GREP; }
goto			{count(); return GOTO; }
gmtime			{count(); return GMTIME; }
glob			{count(); return GLOB; }
getsockopt		{count(); return GETSOCKOPT; }
getsockname		{count(); return GETSOCKNAME; }
getservent		{count(); return GETSERVENT; }
getservbyport		{count(); return GETSERVBYPORT; }
getservbyname		{count(); return GETSERVBYNAME; }
getpwuid		{count(); return GETPWUID; }
getpwnam		{count(); return GETPWNAM; }
getpwent		{count(); return GETPWENT; }
getprotoent		{count(); return GETPROTOENT; }
getprotobynumber	{count(); return GETPROTOBYNUMBER; }
getprotobyname		{count(); return GETPROTOBYNAME; }
getpriority		{count(); return GETPRIORITY; }
getppid			{count(); return GETPPID; }
getpgrp			{count(); return GETPGRP; }
getpeername		{count(); return GETPEERNAME; }
getnetent		{count(); return GETNETENT; }
getnetbyname		{count(); return GETNETBYNAME; }
getnetbyaddr		{count(); return GETNETBYADDR; }
getlogin		{count(); return GETLOGIN; }
gethostent		{count(); return GETHOSTENT; }
gethostbyname		{count(); return GETHOSTBYNAME; }
gethostbyaddr		{count(); return GETHOSTBYADDR; }
getgrnam		{count(); return GETGRNAM; }
getgrgid		{count(); return GETGRGID; }
getgrent		{count(); return GETGRENT; }
getc			{count(); return GETC; }
ge			{count(); return GE; }
formline		{count(); return FORMLINE; }
format			{count(); return FORMAT; }
fork			{count(); return FORK; }
foreach			{count(); return FOREACH; }
for			{count(); return FOR; }
flock			{count(); return FLOCK; }
fileno			{count(); return FILENO; }
fcntl			{count(); return FCNTL; }
exp			{count(); return EXP; }
exit			{count(); return EXIT; }
exists			{count(); return EXISTS; }
exec			{count(); return EXEC; }
eval			{count(); return EVAL; }
eq			{count(); return EQ; }
eof			{count(); return EOF; }
endservent		{count(); return ENDSERVENT; }
endpwent		{count(); return ENDPWENT; }
endprotoent		{count(); return ENDPROTOENT; }
endnetent		{count(); return ENDNETENT; }
endhostent		{count(); return ENDHOSTENT; }
endgrent		{count(); return ENDGRENT; }
elsif			{count(); return ELSIF; }
else			{count(); return ELSE; }
each			{count(); return EACH; }
dump			{count(); return DUMP; }
do			{count(); return DO; }
die			{count(); return DIE; }
delete			{count(); return DELETE; }
defined			{count(); return DEFINED; }
dbmopen			{count(); return DBMOPEN; }
dbmclose		{count(); return DBMCLOSE; }
crypt			{count(); return CRYPT; }
cos			{count(); return COS; }
continue		{count(); return CONTINUE; }
connect			{count(); return CONNECT; }
cmp			{count(); return CMP; }
closedir		{count(); return CLOSEDIR; }
close			{count(); return CLOSE; }
chroot			{count(); return CHROOT; }
chr			{count(); return CHR; }
chown			{count(); return CHOWN; }
chop			{count(); return CHOP; }
chomp			{count(); return CHOMP; }
chmod			{count(); return CHMOD; }
chdir			{count(); return CHDIR; }
caller			{count(); return CALLER; }
bless			{count(); return BLESS; }
binmode			{count(); return BINMODE; }
bind			{count(); return BIND; }
atan2			{count(); return ATAN2; }
and			{count(); return AND; }
alarm			{count(); return ALARM; }
accept			{count(); return ACCEPT; }
abs			{count(); return ABS; }
*/
%}

__PACKAGE__ 		{count(); return TOKEN_PACKAGE; }
__LINE__                {count(); return TOKEN_LINE; }
__FILE__                {count(); return TOKEN_FILE; }
__END__                 {count(); return TOKEN_END; }
__DATA__                {count(); return TOKEN_DATA; }
NULL                    {count(); return TOKEN_NULL; }


"=head1"		{ count();gobble_pod(); return TOKEN_PERLPOD; }
"=head2"		 { count();gobble_pod(); return TOKEN_PERLPOD; }
"=back"			 { count();gobble_pod(); return TOKEN_PERLPOD; }
"=pod"			{ count();gobble_pod(); return TOKEN_PERLPOD; }
"=item"			{ count();gobble_pod();  return TOKEN_PERLPOD; }
("'") 			{ count();gobble_string('\''); return TOKEN_QSTRING_LITERAL; }
("\"")                  { count();gobble_string('"'); return TOKEN_QQSTRING_LITERAL; }
("`")                  { count();gobble_string('`'); return TOKEN_BACKTICK_LITERAL; }


"/".*"/"		{count(); return TOKEN_REGEXP; }
0[xX][a-fA-F0-9]+     {count(); return TOKEN_HEX_CONST; }
0[0-9]+               {count(); return TOKEN_OCT_CONST; }
[0-9]+                {count(); return TOKEN_DEC_CONST; }
[0-9]+[Ee][+-]?[0-9]+              {count(); return TOKEN_FLOAT_CONST; }
[0-9]*"."[0-9]+([Ee][+-]?[0-9]+)?  {count(); return TOKEN_FLOAT_CONST; }
[0-9]+"."[0-9]*([Ee][+-]?[0-9]+)?  {count(); return TOKEN_FLOAT_CONST; }


">>="			{count(); return TOKEN_RIGHT_ASSIGN; }
"<<="		        {count(); return TOKEN_LEFT_ASSIGN; }

"**="			{count(); return TOKEN_EXP_ASSIGN; }
"+="			{count(); return TOKEN_ADD_ASSIGN; }
"-="			{count(); return TOKEN_SUB_ASSIGN; }
"*="			{count(); return TOKEN_MUL_ASSIGN; }
"/="			{count(); return TOKEN_DIV_ASSIGN; }
"%="			{count(); return TOKEN_MOD_ASSIGN; }
".="                    {count(); return TOKEN_CONCAT_ASSIGN; }
"x="                    {count(); return TOKEN_REPEAT_ASSIGN; }

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
"!"			{count(); return '!'; }
"?"			{count(); return '?'; }
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
"="			{count(); return '='; }
";"			{count(); return ';'; }
"x"                     {count(); return 'x'; }
"y"                     {count(); return 'y'; }
"s"                     {count(); return 's'; }
"q"                     {count(); return 'q'; }
"m"                     {count(); return 'm'; }
"\\"			{count(); return '\\';}


"$"[_&'`+*./|,\;#%=-~^:?!@"$<>)([\]]  {count();return TOKEN_ID_SCALAR;}
"$"[^][a-zA-Z]			{count(); return TOKEN_ID_SCALAR; }
"$"[0-9]*			{count(); return TOKEN_ID_SCALAR; }
"$"[a-zA-Z_$][a-zA-Z0-9_']*	{count(); return TOKEN_ID_SCALAR; }
"\\"*"@"[ \t]*"{"*["$a-zA-Z_]*[a-zA-Z0-9_'$]*"}"*	{count(); return TOKEN_ID_ARRAY; }
"%"[a-zA-Z_$][a-zA-Z0-9_']*	{count(); return TOKEN_ID_HASHT; }
[a-zA-Z_][a-zA-Z0-9_':]*	        {count(); return TOKEN_ID_HANDLE; }


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

        if (perllexreal_column != 0)
        {
          perllex_column = perllexreal_column+1;
        }
        for (i = 0; yytext[i] != '\0'; i++)
        {
                if (yytext[i] == '\n')
                {
                        perllexreal_column = 0;
                        perllex_column = 0;
                } else if (yytext[i] == '\t') {
                        perllexreal_column += 8 - (perllexreal_column % 8);
                }else {
                        perllexreal_column++;
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

    perllexreal_column++;
    switch(c)  {

      case '\\':
                 if (!bslash)
                   bslash = 1;
                 else
                   bslash = 0;
                 break;
      case '\n':
                 perllexreal_column = 0;
                 perllex_column = 0;
                 perllex_lineno++;
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
void gobble_pod(void)
{

  int bline = 0;
  int cstate = 0;
  char c;
  while ((c = input()) && c != -1)
  {
    perllexreal_column++;
    switch(c)  {
    
      case '=':
                if (!bline)
                  cstate = 1;
                break;
      case '\n':
                 perllexreal_column = 0;
                 perllex_column = 0;
                 perllex_lineno++;
                 
                 bline = 0;
                 if (cstate == 4)
                   return;
                 break;
      case 'c': 
                 if (cstate == 1)
                   cstate = 2;
                 break;
      case 'u':  if (cstate == 2)
                   cstate = 3;
                 break;
      case 't':  if (cstate == 3)
                   cstate = 4;
                 break;
      case ' ':
      case '\t':
                 if (cstate == 4)
                   return;
                 break; 
      default:
                 bline++;
                 cstate = 0;
                 break;
    }
  }
}

    

    
static
void no_match(void)
{
    fprintf(stderr, "%s:%d: warning: bad token `%s'\n", current_file, perllex_lineno, yytext);
}








