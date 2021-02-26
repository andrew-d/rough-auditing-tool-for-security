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
/* Modified by Mike Ellison February 17th, 2002 - win32 port

   Just #define to using native win32 functions, since VC++ at least doesn't
   seem to have the strncasecmp() function.  */

#ifdef _MSC_VER
#define strcasecmp  _stricmp
#define strncasecmp _strnicmp
#define lstat(x,y) _stat(x,y)
#define PATH_MAX _MAX_PATH
#include <windows.h>

/* S_ISDIR does not exist in VC so we have to pull the macros from <sys/stat.h>
 * of a reasonable OS  -- Robert */
#define	_S_ISTYPE(mode, mask)	(((mode) & _S_IFMT) == (mask))
#define	S_ISDIR(mode)	 _S_ISTYPE((mode), _S_IFDIR)
#define _S_ISDIR(mode) S_ISDIR(mode)
#define S_ISREG(m)      _S_ISTYPE((m), _S_IFREG)

#else
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#endif

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include "tokens.h"
#include "report.h"


#include <errno.h>

lexer_t         ratslexer;
Hash            database = (Hash)NULL;
Hash	        defaultdb = (Hash)NULL;
char *          current_file;
rats_stack_t *  current_frame = (rats_stack_t *)NULL;

static int                  depths[DEPTH_COUNT];
static int                  ungotten_token  = -1;
static int                  toctou_count = 0;
static int                  last_text_line = 0;
static ignore_t *           current_ignore = (ignore_t *)NULL;
static toctou_t *           toctous = (toctou_t *)NULL;
static accumulator_t *      accumulators = (accumulator_t *)NULL;

static void analyze_variable(int token);
static void analyze_identifier(void);
static void analyze_comment(void);
static void analyze_backticks(void);
static argument_t *get_argument(int number);

static
int accumulate_text(accumulator_t *acc, char *text)
{
    int     length;
    char *  new_text;

    length = strlen(text);
    if (*(acc->text) == (char *)NULL)
    {
        *(acc->text) = (char *)calloc(length + 1,1);
        acc->length  = 0;
    }
    else
    {
        new_text = (char *)realloc(*(acc->text), acc->length + length + 1);
        if (new_text == (char *)NULL)
            return 0;
        *(acc->text) = new_text;
    }

    memcpy(*acc->text + acc->length, text, length);
    acc->length += length;
    *(*acc->text + acc->length) = '\0';
    return 1;
}

static
void push_accumulator(char **text)
{
    accumulator_t * acc;

    acc = (accumulator_t *)calloc(sizeof(accumulator_t),1);
    acc->text    = text;
    acc->length  = (*text == (char *)NULL ? 0 : strlen(*text));
    acc->next    = accumulators;
    accumulators = acc;

    accumulate_text(acc, *ratslexer.yytext);
}

static
void pop_accumulator(void)
{
    accumulator_t * acc;

    acc = accumulators;
    accumulators = acc->next;
    if (*(acc->text) != (char *)NULL)
    {
        if (accumulators != (accumulator_t *)NULL)
        {
            accumulators->length = 0;
            accumulate_text(accumulators, *(acc->text));
        }
        acc->length -= strlen(*ratslexer.yytext);
        *(*acc->text + acc->length) = '\0';
    }
    free(acc);
}

static
void unget_token(int token)
{
    ungotten_token = token;
    switch (token)
    {
        case '(': depths[DEPTH_PARENTHESIS]--;  break;
        case ')': depths[DEPTH_PARENTHESIS]++;  break;
        case '[': depths[DEPTH_BRACKET]--;  break;
        case ']': depths[DEPTH_BRACKET]++;  break;
        case '{': depths[DEPTH_BRACE]--;  break;
        case '}': depths[DEPTH_BRACE]--;  break;
    }
}

static
int get_token(void)
{
    int token;

    if (ungotten_token != -1)
    {
        token = ungotten_token;
        ungotten_token = -1;
    }
    else
      {
      if (!(token = (ratslexer.yylex)() )) {
            return 0;
      }
      if (accumulators != (accumulator_t *)NULL)
	accumulate_text(accumulators, *ratslexer.yytext);
    }

    switch (token)
    {
        case '(': depths[DEPTH_PARENTHESIS]++;  break;
        case ')': depths[DEPTH_PARENTHESIS]--;  break;
        case '[': depths[DEPTH_BRACKET]++;  break;
        case ']': depths[DEPTH_BRACKET]--;  break;
        case '{': depths[DEPTH_BRACE]++;  break;
        case '}': depths[DEPTH_BRACE]--;  break;
    }

    return token;
}

static
void scan_tokens(processorfn_t fn, void *arg)
{
    int token;

    while ((token = get_token()) != 0)
    {
        if (token != TOKEN_COMMENT)
        {
            last_text_line = *ratslexer.lex_lineno;
            if (current_ignore != (ignore_t *)NULL)
            {
                current_ignore->lineno = *ratslexer.lex_lineno;
                current_ignore = (ignore_t *)NULL;
            }
        }
        if (fn != NULL)
            if (!fn(token, arg))
                break;
        switch (token)
        {
        
            case TOKEN_DOUBLE:
            case TOKEN_FLOAT:
            case TOKEN_INT:
            case TOKEN_LONG:
            case TOKEN_SHORT:
            case TOKEN_STRUCT:
            case TOKEN_VOID:
            case TOKEN_ENUM:
            case TOKEN_UNION:
            case TOKEN_CHAR:
                analyze_variable(token);
                break;

            case TOKEN_IDENTIFIER:
                analyze_identifier();
                break;

            case TOKEN_COMMENT:
                analyze_comment();
                break;

            case '`':
                analyze_backticks();
                break;
 
        }
    }
}

static
 int gobble_backtick(int token, void *arg)
{
    if (token == '`')
        return 0;
    return 1;
}

static void
analyze_backticks(void)
{
    int myline = *ratslexer.lex_lineno;
    int column = *ratslexer.lex_column;

    if (ratslexer.lang == LANG_C)  
        return;
  
    /* we're just gobbling up whatever is in the backticks and
     * ignoring them for now.
     */

    scan_tokens(gobble_backtick, NULL);

    switch (ratslexer.lang)
    {
        case LANG_PYTHON:
            log_pythonbacktick(myline, column, Medium);
            break;
        case LANG_PHP:    
            log_phpbacktick(myline, column,Medium);
            break;
        case LANG_PERL:
            log_perlbacktick(myline, column,Medium);
            break;
	    case LANG_RUBY:
            log_rubybacktick(myline, column,Medium);
            break;
    }
}

static
int check_buffer(int token, void *arg)
{
    charscan_t *    data;

    data = (charscan_t *)arg;
    if (token == ';' || token == '{')
        return 0;
    if (data->skip)
        return 1;

    if (token == '=')
        data->skip = 1;
    else if (token == '[' && data->last_token == TOKEN_IDENTIFIER)
        data->depth = depths[DEPTH_BRACE];
    else if (data->last_token == '[')
    {
        if (token != ']')
        {
            if (data->initial_type == TOKEN_CHAR || (flags & ALL_STATIC))
            {
              if (data->depth)
                  log_staticbuffer(StaticLocalBuffer, data->lineno, data->column,High);
              else
                  log_staticbuffer(StaticGlobalBuffer, data->lineno, data->column,Low);
            }
            data->skip = 1;
        }
    }
    data->last_token = token;
    return 1;
}

/*
 * XXX: This function can be cleaned up to prevent more false positives.
 *      Currently running lex.yy.c through this yields false positives due to
 *      pointer initializers, i.e. char *foo = bar[15]; - MMessier, 09-May-2001
 */
static
void analyze_variable(int token)
{
    charscan_t  data;

    /* If we're processing arguments right now, we don't want to check for
     * stack variables because they're not really stack variables
     */
    if (current_frame != (rats_stack_t *)NULL && current_frame->next != (rats_stack_t *)NULL)
        return;
    if (depths[DEPTH_PARENTHESIS] || depths[DEPTH_BRACKET])
        return;

    data.column = *ratslexer.lex_column;
    data.lineno = *ratslexer.lex_lineno;
    data.initial_type = token;
    data.last_token = token;
    data.depth = depths[DEPTH_BRACE];
    data.skip = 0;
    scan_tokens(check_buffer, (void *)&data);
}

static
int check_format_string(char *fmt, int format_arg)
{
    int     arg = format_arg + 1;
    char *  c;
    
    for (c = strchr(fmt, '%');  c != (char *)NULL;  c = strchr((fmt = c + 1), '%'))
    {
        int done = 0, precision = 0;

        for (fmt = c++;  !done && *c;  c++)
        {
            switch (*c)
            {
                case '#':
                case '-':
                case ' ':
                case '+':
                    break;
                default:
                    done = 1;
                    c--;
                    break;
            }
        }

        if (*c == '*')
        {
            arg++;
            c++;
        }
        else if (isdigit(*c))
            while (isdigit(*++c));

        if (*c == '.')
        {
            precision = 1;
            if (*c == '*')
            {
                arg++;
                c++;
            }
            else
                while (isdigit(*++c));
        }

        switch (*c)
        {
            case 'L':
            case 'j':
            case 't':
            case 'z':
                c++;
                break;

            case 'h':
                if (*++c == 'h')
                    c++;
                break;

            case 'l':
                if (*++c == 'l')
                    c++;
                break;
        }

        if (format_arg == -1)
        {
            if (*c == 's' && !precision)
                return 1;
        }
        else
        {
            switch (*c)
            {
                case 's':
		  if(get_argument(arg)) {
                    if (!get_argument(arg)->is_constant)
                        return 1;
		  }
                    /* FALL THROUGH */

                case 'c':
                case 'd': case 'i':
                case 'o': case 'u':
                case 'x': case 'X':
                case 'e': case 'E':
                case 'f': case 'F':
                case 'g': case 'G':
                case 'a': case 'A':
                case 'p': case 'n':
                    arg++;
                    break;
            }
        }
    }

    return 0;
}

static
int check_scan_format_string(char *fmt, int format_arg)
{
    int     arg = format_arg + 1;
    char *  c;
    
    for (c = strchr(fmt, '%');  c != (char *)NULL;  c = strchr((fmt = c + 1), '%'))
    {
        if (*c == '*')
        {
            arg--;
            c++;
        }

        switch (*c)
        {
            case 'a':
            case 'L':
            case 'q':
                c++;
                break;
            case 'h':
                if (*++c == 'h')
                    c++;
                break;

            case 'l':
                if (*++c == 'l')
                    c++;
                break;
        }

        if (format_arg == -1)
        {
            if (*c == 's')
                return 1;
        }
        else
        {
            switch (*c)
            {
                case 's':
                    if (!get_argument(arg)->is_constant)
                        return 1;
                    /* FALL THROUGH */
                
                case 'c':
                case 'd': case 'D':
                case 'i':
                case 'o': case 'u':
                case 'x': case 'X':
                case 'e': case 'E':
                case 'f': case 'F':
                case 'g': case 'G':
                case 'a': case 'A':
                case 'p': case 'n':
                    arg++;
                    break;
            }
        }
    }
    return 0;
}

static
int check_argument(int token, void *arg)
{
    int         advance = 0;
    argscan_t * data;

    data = (argscan_t *)arg;
    if (token == ',' || token == ')')
    {
        int i;

        advance = 1;
        for (i = 0;  i < DEPTH_COUNT;  i++)
        {
            if (data->depths[i] != depths[i])
            {
                if (i != DEPTH_PARENTHESIS || token != ')' ||
                    data->depths[i] != depths[i] + 1)
                {
                    advance = 0;
                }
            }
        }
    }

    if (advance)
    {
        if (data->current != (argument_t *)NULL)
        {
            pop_accumulator();
            current_frame->argc++;
            if (data->tail != (argument_t *)NULL)
                data->tail->next = data->current;
            else
                current_frame->argv = data->current;
            data->tail = data->current;
            data->current = (argument_t *)NULL;
        }
        if (token == ')' || token == ';')
            return 0;
        return 1;
    }

    if (data->current == (argument_t *)NULL)
    {
        data->current = (argument_t *)calloc(sizeof(argument_t),1);
        data->current->is_constant = 1;
        data->current->contains_ps = 0;
        data->current->yytext      = (char *)NULL;
        data->current->next        = (argument_t *)NULL;

        push_accumulator(&(data->current->yytext));
    }

    if (data->current->is_constant)
    {
        if (token < CONST_START || token > CONST_END)
            data->current->is_constant = 0;
        else if (token == TOKEN_STRING_CONST && !data->current->contains_ps)
            data->current->contains_ps = check_format_string(*ratslexer.yytext, -1);
    }

    return 1;
}

static
void scan_arguments(void)
{
    int         i;
    argscan_t   data;

    data.tail = (argument_t *)NULL;
    data.current = (argument_t *)NULL;
    for (i = 0;  i < DEPTH_COUNT;  i++)
        data.depths[i] = depths[i];

    scan_tokens(check_argument, (void *)&data);
}

static
argument_t *get_argument(int number)
{
    argument_t *    arg;

    if (number < 0 || number > current_frame->argc)
        return (argument_t *)NULL;

    for (arg = current_frame->argv;  --number > 0;  arg = arg->next);
    return arg;
}

static
Vuln_t *locate_identifier(char *identifier)
{
    Vuln_t *    data = NULL;
    
    if (ratslexer.langhash) 
        data = (Vuln_t *)HashGet(ratslexer.langhash, identifier);
    if ((data == NULL) && defaultdb)
        data = (Vuln_t *)HashGet(defaultdb, identifier);
    return data;
}

static
int push_identifier(char *identifier, int lineno, int column)
{
    Vuln_t *        data;
    rats_stack_t *  frame;

    if (database == NULL || (data = locate_identifier(identifier)) == NULL)
        return 0;

    frame = (rats_stack_t *)calloc(sizeof(rats_stack_t),1);
    frame->identifier = identifier;
    frame->data       = data;
    frame->lineno     = lineno;
    frame->column     = column;
    frame->argc       = 0;
    frame->argv       = (argument_t *)NULL;
    frame->next       = current_frame;
    current_frame     = frame;

    return 1;
}

static
void pop_identifier(void)
{
    rats_stack_t *  frame;
    argument_t *    arg;
    argument_t *    next;

    frame = current_frame;
    current_frame = frame->next;

    free(frame->identifier);
    for (arg = frame->argv;  arg != (argument_t *)NULL;  arg = next)
    {
        next = arg->next;
        if (arg->yytext != (char *)NULL)
            free(arg->yytext);
        free(arg);
    }
    free(frame);
}

static
void record_toctou(int argn, int lineno, int use, int column)
{
    toctou_t *      toctou;
    argument_t *    arg;

    if ((arg = get_argument(argn)) == (argument_t *)NULL)
        return;

    toctou = (toctou_t *)calloc(sizeof(toctou_t),1);
    toctou->lineno = lineno;
    toctou->data   = current_frame->data;
    toctou->key    = strdup(arg->yytext);
    toctou->use    = use;
    toctou->column = column;
    toctou->next   = toctous;
    toctous        = toctou;
    toctou_count++;
}

static
void analyze_identifier(void)
{
    int             to_analyze, analyzed, lineno, token, column;
    char *          identifier;
    Vuln_t *        data;
    argument_t *    arg;
	int			process = 0;

    to_analyze=token=0;

    lineno     = *ratslexer.lex_lineno;
    column     = *ratslexer.lex_column;
    identifier = strdup(*ratslexer.yytext);


    if (!push_identifier(identifier, lineno, column))
    {
        free(identifier);
        return;
    }

    /* Special handling for cin in C++.  This is rather hackish -- Robert */
    if(!strcmp(identifier,"cin")) {
      if(token==TOKEN_RIGHT_ASSIGN) {
	to_analyze=1;
      }
    }

    /* looking only for function calls here */
    if (!to_analyze &&
		(token = get_token()) != '(')
    {
		if (ratslexer.lang == LANG_RUBY)
		{
			if (current_frame != NULL)
			{
				process = 1;
				goto go;
			}
		}
cleanup:
		if (flags & INCLUDE_ALL_REFERENCES)
            log_vulnerability(Reference, Medium);
        pop_identifier();
        unget_token(token);

        return;
    }

    scan_arguments();
go:
    data = current_frame->data;
    analyzed = 0;

    /* If there's an info record, it's always a vulnerability.  Log it */
    if (data->Info != (Info_t *)NULL)
    {
        analyzed++;
        log_vulnerability(Info, data->Info->Severity);
    }

    if (data->FSProblem != (FSProblem_t *)NULL)
    {
        analyzed++;
        if ((arg = get_argument(data->FSProblem->Arg)) != (argument_t *)NULL)
        {
            if (!arg->is_constant)
                log_vulnerability(FSProblem, data->FSProblem->Severity);
        }
    }

    if (data->BOProblem != (BOProblem_t *)NULL)
    {
        analyzed++;
        if (data->BOProblem->FormatArg > 0)
        {
            if ((arg = get_argument(data->BOProblem->FormatArg)) != (argument_t *)NULL)
            {
                if (!arg->is_constant)
                    log_vulnerability(BOProblem, data->BOProblem->Severity);
            
                if (arg->is_constant && arg->contains_ps)
                {
                    if(data->BOProblem->Scan)
                    {
                        if (check_scan_format_string(arg->yytext, data->BOProblem->FormatArg))
                            log_vulnerability(BOProblem, data->BOProblem->Severity);
                    }
                    else
                    {
                        if (check_format_string(arg->yytext, data->BOProblem->FormatArg))
                            log_vulnerability(BOProblem, data->BOProblem->Severity);
                    }
                }
            }
        }
        if (data->BOProblem->SrcBufArg > 0)
            if ((arg = get_argument(data->BOProblem->SrcBufArg)) != (argument_t *)NULL)
                if (!arg->is_constant)
                    log_vulnerability(BOProblem, data->BOProblem->Severity);
    }

    if (data->InputProblem != (InputProblem_t *)NULL)
    {
        analyzed++;
        if ((arg = get_argument(data->InputProblem->Arg)) != (argument_t *)NULL)
        {
            if (!arg->is_constant)
                log_vulnerability(InputProblem, data->InputProblem->Severity);
        }
    }

    if (data->RaceCheck > 0)
    {
        analyzed++;
        record_toctou(data->RaceCheck, lineno, 0, column);
    }
    if (data->RaceUse > 0)
    {
        analyzed++;
        record_toctou(data->RaceUse, lineno, 1, column);
    }
    if (data->Input > 0)
    {
        analyzed++;
        if (flags & INPUT_MODE) {
            record_input();
	}
    }

    if (!analyzed)
        log_vulnerability(None, Default);

	if (process)
	{
		pop_identifier();
	}
	else
	{
		goto cleanup;
	}
}

static
int toctou_sort(const void *p1, const void *p2)
{
    toctou_t *  t1 = *(toctou_t **)p1;
    toctou_t *  t2 = *(toctou_t **)p2;

    if (strcmp(t1->key, t2->key) == 0)
        if (t1->use != t2->use)
            return (t1->use ? 1 : -1);

    if (t1->lineno == t2->lineno)
        return 0;
    return (t1->lineno < t2->lineno ? -1 : 1);
}

static
void process_toctou(void)
{
    int         check = -1, i = 0, start;
    char *      name = (char *)NULL;
    toctou_t *  toctou;
    toctou_t ** table;

    if (!toctou_count)
        return;

    /* build a table for sorting and sort it, first by name and then by check
     * vs. use.  sort checks ahead of uses
     */
    table = (toctou_t **)calloc(sizeof(toctou_t *) * toctou_count,1);
    for (toctou = toctous;  toctou != (toctou_t *)NULL;  toctou = toctou->next)
        table[i++] = toctou;
    qsort(table, toctou_count, sizeof(toctou_t *), toctou_sort);

    /* Go over toctou records and match them up */
    start = 0;
    for (i = 0;  i < toctou_count;  i++)
    {
        if (name == (char *)NULL || strcmp(table[i]->key, name) != 0)
        {
            if (name != (char *)NULL)
                log_toctou(table, start, i - 1, check);
            name = table[i]->key;
            check = (table[i]->use ? -1 : i);
            start = i;
        }
    }

    if (name != (char *)NULL)
        log_toctou(table, start, i - 1, check);

    /* cleanup */
    for (i = 0;  i < toctou_count;  i++)
    {
        free(table[i]->key);
        free(table[i]);
    }
    toctous = (toctou_t *)NULL;
    toctou_count = 0;
}

void setup_perl(FILE *fd)
{
    yyperlin = fd;
    ratslexer.lex_column = &perllex_column;
    ratslexer.yytext = &yyperltext;
    ratslexer.yyin =  fd;
    ratslexer.yylex = yyperllex;
    ratslexer.yycomment = &yyperlcomment;
    ratslexer.lex_lineno = &perllex_lineno;
    ratslexer.langhash = (Hash)HashGet(database, "perl");
    ratslexer.lang = LANG_PERL;
}

void setup_python(FILE *fd)
{
    yypin = fd;
    ratslexer.yytext = &yyptext;
    ratslexer.yyin =  fd;
    ratslexer.yylex = yyplex;
    ratslexer.yycomment = &yypcomment;
    ratslexer.lex_lineno = &plex_lineno;
    ratslexer.langhash = (Hash)HashGet(database, "python");
    ratslexer.lex_column = &plex_column;
    ratslexer.lang = LANG_PYTHON;
}

void setup_c(FILE *fd)
{
    yycin = fd;
    ratslexer.yytext = &yyctext;
    ratslexer.yyin = fd;
    ratslexer.yylex = yyclex;
    ratslexer.yycomment = &yyccomment;
    ratslexer.lex_lineno = &clex_lineno;
    ratslexer.langhash = (Hash)HashGet(database, "c");
    ratslexer.lex_column = &clex_column;
    ratslexer.lang = LANG_C;
}

void setup_php(FILE *fd)
{
    yyphpin = fd;
    ratslexer.yytext = &yyphptext;
    ratslexer.yyin = fd;
    ratslexer.yylex = yyphplex;
    ratslexer.yycomment = &yyphpcomment;
    ratslexer.lex_lineno = &phplex_lineno;
    ratslexer.langhash = (Hash)HashGet(database, "php");
    ratslexer.lex_column = &phplex_column;
    ratslexer.lang = LANG_PHP;
}

void setup_ruby(FILE *fd)
{
    yyrubyin = fd;
    ratslexer.yytext = &yyrubytext;
    ratslexer.yyin = fd;
    ratslexer.yylex = yyrubylex;
    ratslexer.yycomment = &yyrubycomment;
    ratslexer.lex_lineno = &rubylex_lineno;
    ratslexer.langhash = (Hash)HashGet(database, "ruby");
    ratslexer.lex_column = &rubylex_column;
    ratslexer.lang = LANG_RUBY;
}

/* Changed to char type to return 1 on successful language detemrination, 0 otherwise 
 * -- Robert */
char determine_language(char *filename, FILE *fd, int forcelang)
{
    char *  dot;

    dot = strrchr(filename, '.');
  
    if (forcelang)
    {
        if (forcelang == LANG_PYTHON)
            setup_python(fd);
        else if (forcelang == LANG_C)
            setup_c(fd);
        else if (forcelang == LANG_PERL)
            setup_perl(fd);
		else if ( forcelang == LANG_PHP)
		  setup_php(fd);
		else if ( forcelang == LANG_RUBY)
		  setup_ruby(fd);
        return 1;
    }
    if (!dot)
    {
      if(flags |= RECURSIVE_FILE_SCAN) {
	/* Skip the file if there's no dot on a recurssive file scan */
	return 0;
      }
      setup_c(fd);
      return 1;
    }
    if (!strcasecmp(dot, ".py"))
        setup_python(fd);
    else if (!strcasecmp(dot, ".pl") || !strcasecmp(dot, ".pm"))
        setup_perl(fd);
    else if (!strcasecmp(dot, ".php"))
        setup_php(fd);
	else if (!strcasecmp(dot, ".rb"))
		setup_ruby(fd);
    else if (!strcasecmp(dot, ".c")||
	     !strcasecmp(dot, ".c++")||
	     !strcasecmp(dot, ".cp")||
	     !strcasecmp(dot, ".cpp")||
	     !strcasecmp(dot, ".cc")||
	     !strcasecmp(dot, ".cxx")||
	     !strcasecmp(dot, ".c++")||
	     !strcasecmp(dot, ".C")||
	     !strcasecmp(dot, ".i")||
	     !strcasecmp(dot, ".ii")) {
        setup_c(fd);
    }
    /* For now, we skip it if it's not a match -- Robert */
    else {
      return 0;
    }
    return 1;
}


void process_directory(char *filename, int forcelang) {
#ifdef _MSC_VER
  HANDLE dir;
  WIN32_FIND_DATA dirdata;
  char *newfname;
  BOOL ok;
  int error;

#else
  DIR *dir;
  struct dirent *dirdata;
#endif

  char *buf;
  
/* Due to the way MSVC handles things, it appears that we need to
 * do the actual processing of the first file before we go into the
 * loop */


#ifdef _MSC_VER
  newfname=calloc(PATH_MAX,1);
  sprintf(newfname,"%s/*",filename);
  for (dir=FindFirstFile(newfname, &dirdata), ok=1;
       dir!=INVALID_HANDLE_VALUE && ok;
       ok=FindNextFile(dir, &dirdata)) {
    newfname=calloc(strlen(dirdata.cFileName)+1,1);
    strcpy(newfname,dirdata.cFileName);
    if(!strcmp(dirdata.cFileName,".") ||
       !strcmp(dirdata.cFileName,"..") ) {
      continue;
    }
    buf=calloc(PATH_MAX,1);
    sprintf(buf,
	    "%s/%s",
	    filename,
	    dirdata.cFileName);
    process_file(buf,forcelang);
  }

  error = GetLastError();
  if (error!=ERROR_NO_MORE_FILES) {
    printf("Find*File: error %d\n", error);
  }
  
  if (dir!=INVALID_HANDLE_VALUE) {
    BOOL ok = FindClose(dir);
    if (!ok) {
      printf("FindClose: error %d", GetLastError());
      return;
    }
  }
#else
  if((dir=opendir(filename))==NULL) {
    fprintf(stderr,"There was a problem opening the directory.\n");
    return;
  }
  while((dirdata=readdir(dir))!=NULL) {
    if(!strcmp(dirdata->d_name,".")||
       !strcmp(dirdata->d_name,"..")) {
      continue;
    }
    buf=calloc(PATH_MAX,1);
    sprintf(buf,
	    "%s/%s",
	    filename,
	    dirdata->d_name);
    process_file(buf,forcelang);
  }
#endif
}

void process_file(char *filename, int forcelang)
{
    FILE *fd = NULL;
    int             i;
    accumulator_t * acc;
#ifdef _MSC_VER
    struct _stat fstat;
#else
	struct stat fstat;
#endif

    /* 
     * We need to determine the filetype first.
     * If it's a real file, process normally.  
     * If it's a directory and the recursion flag is set, iterate through the
     * files in the directory and run process_file on them.
     */

    if (!strcmp(filename, "<stdin>"))
    {
      fd=stdin;
    } else {
    
      if(lstat(filename,&fstat)==-1) 
      {
        fprintf(stderr,"An error occurred. The file '%s' does not appear to exist\n", filename);
      return;
      }
#ifndef _MSC_VER
      /* Symbolic link check */
      if(S_ISLNK(fstat.st_mode)) {
        if(flags & FOLLOW_SYMLINK) {
	  char *symname;
	  symname=calloc(PATH_MAX,1);
	  if(readlink(filename,symname,PATH_MAX)==-1) {
	    return;
	  }
	  process_file(symname,forcelang);
        }
        return;
      }
#endif
      if(S_ISDIR(fstat.st_mode)) {
        /* Need to error catch here.*/
        if( flags & RECURSIVE_FILE_SCAN ) {
	  process_directory(filename,forcelang);
	  return;
        }
     }
    
     if (!S_ISREG(fstat.st_mode))
     {
       printf("NOT REGULAR FILE\n");
       return;
     } 

   }
 

   if(!fd && (fd=fopen(filename,"r")) == (FILE *)NULL) {
      return;
   }

    /* (Re-)Initialize state */
    if(!determine_language(filename, fd, forcelang)) {
      fclose(fd);
      return;
    }

    *ratslexer.lex_lineno = 1;
    last_text_line = 0;
    current_file = strdup(filename);
    for (i = 0;  i < DEPTH_COUNT;  depths[i++] = 0);

    /* Process the file */

   if (!(flags & NO_STATUS))
   {
     if ((flags & HTML_OUTPUT))
     {
       printf("Analyzing <b>%s</b><br>\n", filename);
     } else if (flags & XML_OUTPUT) {
       printf("<analyzed>%s</analyzed>\n", filename);
     } else {
       printf("Analyzing %s\n", filename);
     }
   }

    scan_tokens((processorfn_t)NULL, NULL);
    process_toctou();
    

    total_lines += *ratslexer.lex_lineno;
    /* Cleanup */
    current_ignore = (ignore_t *)NULL;
    while ((acc = accumulators) != (accumulator_t *)NULL)
    {
        if (*(acc->text) != (char *)NULL)
            free(*(acc->text));
        pop_accumulator();
    }
    fclose(fd);
}

static
void analyze_comment(void)
{
    ignore_t *  ign;
    char *      c;

    if (yyclength < 5)
        return;
	if (*ratslexer.yycomment == NULL)
		return;

    for (c = *ratslexer.yycomment;  *c && isspace(*c);  c++);
    if (!*c)
        return;
    if (strncasecmp(c, "its4:", 5) && strncasecmp(c, "rats:", 5))
        return;

    for (c += 5;  *c && isspace(*c);  c++);
    if (!*c)
        return;
    if (strncasecmp(c, "ignore", 6))
        return;

    for (c += 6;  *c && isspace(*c);  c++);
    if (!*c || (*c != '$' && *c != '_' && !isalpha(*c)))
        ign = new_ignore(*ratslexer.lex_lineno, (char *)NULL);
    else
    {
        char *  p;

        for (p = c;  *p && (isalnum(*p) || *p == '$' || *p == '_');  p++);
        *p = '\0';
        ign = new_ignore(*ratslexer.lex_lineno, c);
    }

    /* are we on a line that we've already encountered text on? */
    if (last_text_line != *ratslexer.lex_lineno)
        current_ignore = ign;
}
