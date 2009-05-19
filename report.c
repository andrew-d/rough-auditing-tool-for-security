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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef _MSC_VER
#include <windows.h>
#else
#include <sys/time.h>
#endif

#include <string.h>
#include "report.h"

int warning_level = 2;

static input_t *            input_head  = (input_t *)NULL;
static input_t *            input_tail  = (input_t *)NULL;
static ignore_t *           ignore_list = (ignore_t *)NULL;
static vulnerability_t *    list_head   = (vulnerability_t *)NULL;
static vulnerability_t *    list_tail   = (vulnerability_t *)NULL;

static char *context_filename = NULL;
static FILE *context_fp = NULL;
static int context_line = 0;
static int lookup_ignore(char *filename, int lineno, char *token);
static int determine_ignorance(vulnerability_t *ptr);
static void diff_times(const struct timeval *, const struct timeval *,  struct timeval *);

int total_lines = 0;
#ifdef _MSC_VER
DWORD time_started;
DWORD time_finished;
#else
struct timeval time_started;
struct timeval time_finished;
#endif


/* This function EXPECTS a MALLOCED BUFFER to be passed into it, as it will
 * free it if it needs to be
 */
static char *
xml_escape(char *xstr)
{

  char *result = NULL;
  char *cntptr = NULL;
  char *cpptr = NULL;
  char *dstptr = NULL;
  unsigned int newsz = 0;

  newsz = strlen(xstr)+1; 

  cntptr = xstr;
  while((cntptr = strchr(cntptr, '&')))
  {
    newsz += 4;
    cntptr++;
  }

  cntptr = xstr;

  while((cntptr = strchr(cntptr, '<')))
  {
    newsz += 3;
    cntptr++;
  } 

  cntptr = xstr;
  
  while((cntptr = strchr(cntptr, '>')))
  {
    newsz += 3;
    cntptr++;
  }

  if (newsz == strlen(xstr)+1)
  {
    return xstr;
  }
  result = malloc(newsz);
  cpptr = xstr;
  dstptr = result;
  while(*cpptr && (dstptr < result+newsz))
  {
    if (*cpptr == '&')
    {
      strncat(dstptr, "&amp;", 5);
      dstptr += 5; 
    } else if (*cpptr == '<') {
      strncat(dstptr, "&lt;", 4);
      dstptr += 4; 
    } else if (*cpptr == '>') {
      strncat(dstptr, "&gt;", 4);
      dstptr += 4;
    } else {
       *dstptr = *cpptr;
       *(dstptr+1) = 0;
       dstptr++;
    }
    cpptr++;
  }
  free(xstr);
  return result;
}
       
   

  
  
static void
replace_cfname(char *filename)
{

  if (context_filename)
    free(context_filename);
  
  context_filename = malloc(strlen(filename)+1);
  strncpy(context_filename, filename, strlen(filename));
  context_filename[strlen(filename)] = 0;
}

static char *
getctx(char *filename, int lineno)
{

    char *ret = NULL;
    char buf[4096] = {0};
    
    if (context_filename && strcmp(context_filename, filename))
    {
        replace_cfname(filename);
        if (context_fp)
        {
            fclose(context_fp);
            context_fp = NULL;
        }
    }

    if (!context_filename)
    {
      replace_cfname(filename);
    }

    if (!context_fp)
    {
       context_fp = fopen(context_filename, "r");
       context_line = 0;
       if (!context_fp)
          return NULL;
    }


    if (lineno <= context_line)
    {
      context_line = 0;
      fseek(context_fp, 0, SEEK_SET);
    } 

    while(fgets(buf, 4096, context_fp))
    {
        if(buf[strlen(buf)-1] == '\n')
        {
            context_line++;
        }
        if (context_line == lineno)
        {
          ret = malloc(strlen(buf)+1);
          strncpy(ret, buf, strlen(buf));
          ret[strlen(buf)] = 0;  
          return ret;
        }
    } 
    return NULL;
}
        
    

static
void insert_vulnerability(vulnerability_t *log)
{
    int                 insert = 0;
    vulnerability_t *   ptr;

    for (ptr = list_head;  ptr != (vulnerability_t *)NULL;  ptr = ptr->next)
    {
        if (ptr->severity < log->severity)
        {
            insert = 1;
            ptr = ptr->prev;
            break;
        }
        if (ptr->type == log->type && ptr->data == log->data)
        {
            for (ptr = ptr->next;  ptr != (vulnerability_t *)NULL;  ptr = ptr->next)
            {
                if (ptr->type != log->type || ptr->data != log->data)
                {
                    ptr = ptr->prev;
                    break;
                }
            }
            break;
        }
    }
    if (ptr == (vulnerability_t *)NULL && !insert)
        ptr = list_tail;

    log->next = (ptr == (vulnerability_t *)NULL ? list_head : ptr->next);
    log->prev = ptr;

    if (log->next != (vulnerability_t *)NULL)
        log->next->prev = log;
    else
        list_tail = log;
    if (log->prev != (vulnerability_t *)NULL)
        log->prev->next = log;
    else
        list_head = log;
}

void log_toctou(toctou_t **table, int first, int last, int check)
{
    int                 i;
    vulnerability_t *   log;

    if (check != -1)
    {
        int count = 0, index = 0;

        for (i = first;  i <= last;  i++)
            count += (table[i]->use);

        log = (vulnerability_t *)malloc(sizeof(vulnerability_t));
        log->filename = current_file;
        log->lineno   = table[check]->lineno;
        log->column   = table[check]->column;
        log->data     = table[check]->data;
        log->type     = RaceConditionCheck;

        if (count > 0)
        {
            log->severity = Medium;
            log->uses     = (toctou_use_t *)malloc(sizeof(toctou_use_t) * (count + 1));

            for (i = first;  i <= last;  i++)
            {
                if (table[i]->use)
                {
                    log->uses[index].name   = table[i]->data->Name;
                    log->uses[index].lineno = table[i]->lineno;
                    log->uses[index].column = table[i]->column;
                    index++;
                }
            }
            log->uses[index].name   = (char *)NULL;
            log->uses[index].lineno = 0;
            log->uses[index].column = 0;

        }
        else
        {
            log->severity = Low;
            log->uses     = (toctou_use_t *)NULL;
        }
        insert_vulnerability(log);
    }
    else
    {
        for (i = first;  i <= last;  i++)
        {
            log = (vulnerability_t *)malloc(sizeof(vulnerability_t));
            log->filename = current_file;
            log->column   = table[i]->column;
            log->lineno   = table[i]->lineno;
            log->data     = table[i]->data;
            log->type     = RaceConditionUse;
            log->severity = Low;
            log->uses     = (toctou_use_t *)NULL;

            insert_vulnerability(log);
        }
    }
}

void log_vulnerability(type_t type, Severity_t severity)
{
    vulnerability_t *   log;

    log = (vulnerability_t *)malloc(sizeof(vulnerability_t));
    log->column   = current_frame->column;
    log->filename = current_file;
    log->lineno   = current_frame->lineno;
    log->data     = current_frame->data;
    log->type     = type;
    log->severity = severity;
    log->uses     = (toctou_use_t *)NULL;

    insert_vulnerability(log);
}

void log_perlbacktick(int lineno, int column, Severity_t severity)
{
    vulnerability_t *   log;

    log = (vulnerability_t *)malloc(sizeof(vulnerability_t));
    log->filename = current_file;
    log->column   = column;
    log->lineno   = lineno;
    log->data     = (Vuln_t *)NULL;
    log->type     = PerlBacktick;
    log->severity = severity;
    log->uses     = (toctou_use_t *)NULL;

    insert_vulnerability(log);
}


void log_phpbacktick(int lineno, int column, Severity_t severity)
{
    vulnerability_t *   log;

    log = (vulnerability_t *)malloc(sizeof(vulnerability_t));
    log->filename = current_file;
    log->column   = column;
    log->lineno   = lineno;
    log->data     = (Vuln_t *)NULL;
    log->type     = PhpBacktick;
    log->severity = severity;
    log->uses     = (toctou_use_t *)NULL;

    insert_vulnerability(log);
}

void log_pythonbacktick(int lineno, int column, Severity_t severity)
{
    vulnerability_t *   log;

    log = (vulnerability_t *)malloc(sizeof(vulnerability_t));
    log->filename = current_file;
    log->column   = column;
    log->lineno   = lineno;
    log->data     = (Vuln_t *)NULL;
    log->type     = PythonBacktick;
    log->severity = severity;
    log->uses     = (toctou_use_t *)NULL;

    insert_vulnerability(log);
}

void log_staticbuffer(type_t type, int lineno, int column, Severity_t severity)
{
    vulnerability_t *   log;

    log = (vulnerability_t *)malloc(sizeof(vulnerability_t));
    log->filename = current_file;
    log->column   = column;
    log->lineno   = lineno;
    log->data     = (Vuln_t *)NULL;
    log->type     = type;
    log->severity = severity;
    log->uses     = (toctou_use_t *)NULL;

    insert_vulnerability(log);
}

void record_input(void)
{
    input_t *   input;

    input = (input_t *)malloc(sizeof(input_t));
    input->column   = current_frame->column;
    input->filename = current_file;
    input->lineno   = current_frame->lineno;
    input->data     = current_frame->data;
    input->next     = (input_t *)NULL;

    if (input_tail != (input_t *)NULL)
        input_tail->next = input;
    else
        input_head = input;
    input_tail = input;
}

static
void cleanup_string(char *str)
{
    int     len;
    char *  c;

    /* strip off leading a trailing whitespace */
    for (c = str;  *c && isspace(*c);  c++);
    for (len = strlen(c);  len > 0 && isspace(*(c + len - 1));  len--);
    *(c + len) = '\0';
    memmove(str, c, len + 1);

    /* squash occurences of multiple whitespace characters to a single one */
    for (c = str + 1;  *c;  c++)
    {
        if (isspace(*c) && isspace(*(c - 1)))
        {
            char *  start;

            for (start = c++;  isspace(*c);  c++);
            memmove(start, c, (len + 1) - (c - str));
            len -= (c - start);
            *(start - 1) = ' ';
        }
    }
}

static char *severities[] = { "Default", "Low", "Medium", "High" };

static void build_xml_vulnerability(vulnerability_t *ptr) {
    int i;
    
    printf("<vulnerability>\n");

    /* Output the severity */
    printf("  <severity>%s</severity>\n",
	   severities[ptr->severity]);

    switch (ptr->type)
    {
    case BOProblem:
      if (ptr->data->BOProblem->FormatArg > 0)
	{
	  printf("  <type>%s</type>\n",
		 ptr->data->Name);
	  printf("  <message>\n");
	  printf("    Check to be sure that the format string passed as argument %d to this\n", ptr->data->BOProblem->FormatArg);
	  printf("    function call does not come from an untrusted source that could have added\n");
	  printf("    formatting characters that the code is not prepared to handle.\n");
	  printf("    Additionally, the format string could contain `%%s' without precision that\n");
	  printf("    could result in a buffer overflow.\n");
	  printf("  </message>\n");
	}
      if (ptr->data->BOProblem->SrcBufArg > 0)
	{
	  printf("  <message>\n");
	  printf("    Check to be sure that argument %d passed to this function call will not\n", ptr->data->BOProblem->SrcBufArg);
	  printf("    copy more data than can be handled, resulting in a buffer overflow.\n");
	  printf("  </message>\n");
	}
      break;

    case FSProblem:
      printf("  <type>%s</type>\n",
	     ptr->data->Name);
      printf("  <message>\n");
      printf("    Check to be sure that the non-constant format string passed as argument %d \n", ptr->data->FSProblem->Arg);
      printf("    to this function call does not come from an untrusted source that could\n");
      printf("    have added formatting characters that the code is not prepared to handle.\n");
      printf("  </message>\n");
      break;

    case InputProblem:
      printf("  <type>%s</type>\n",
	     ptr->data->Name);
      printf("  <message>\n");
      printf("    Argument %d to this function call should be checked to ensure that it does\n", ptr->data->InputProblem->Arg);
      printf("    not come from an untrusted source without first verifying that it contains\n");
      printf("    nothing dangerous.\n");
      printf("  </message>\n");
      break;

    case Info:
      printf("  <type>%s</type>\n",
	     ptr->data->Name);
      printf("  <message>\n");
      if (ptr->data->Info->Description != (char *)NULL) {
	cleanup_string(ptr->data->Info->Description);
	printf("    %s\n", ptr->data->Info->Description);
      }
      if (ptr->data->Info->URL != (char *)NULL)	{
	cleanup_string(ptr->data->Info->URL);
	/* This should possibly be made into it's own tag -- Robert */
	printf("    foSee also:\n %s\n", ptr->data->Info->URL);
      }
      printf("  </message>\n");
      break;

    case RaceConditionCheck:
      printf("  <type>%s</type>\n",
	     ptr->data->Name);
      printf("  <message>\n");
      printf("    A potential TOCTOU (Time Of Check, Time Of Use) vulnerability exists.\n");
      printf("    This is the first line where a check has occured.");
      if (ptr->uses != (toctou_use_t *)NULL && ptr->uses[0].lineno != 0)
	{
	  printf("\n    The following line(s) contain uses that may match up with this check:\n");
	  for (i = 0;  ptr->uses[i].lineno != 0;  i++)
	    printf("    %s%d (%s)", (i == 0 ? "" : ", "), ptr->uses[i].lineno, ptr->uses[i].name);
	  printf("\n");
	}
      else
	{
	  printf("    No matching uses were detected.\n");
	}
      printf("  </message>\n");
      break;

    case RaceConditionUse:
      printf("  <type>fixed size local buffer</type>\n");
      printf("  <message>\n");
      printf("    A potential race condition vulnerability exists here.  Normally a call\n");
      printf("    to this function is vulnerable only when a match check precedes it.  No\n");
      printf("    check was detected, however one could still exist that could not be\n");
      printf("    detected.\n");
      printf("  </message>\n");
      break;

    case StaticLocalBuffer:
      printf("  <type>fixed size global buffer</type>\n");
      printf("  <message>\n");
      printf("    Extra care should be taken to ensure that character arrays that are\n");
      printf("    allocated on the stack are used safely.  They are prime targets for\n");
      printf("    buffer overflow attacks.\n");
      printf("  </message>\n");
      break;

    case StaticGlobalBuffer:
      printf("  <type>%s</type>\n",
	     ptr->data->Name);
      printf("  <message>\n");
      printf("    Extra care should be taken to ensure that character arrays that are\n");
      printf("    allocated with a static size are used safely.  This appears to be a\n");
      printf("    global allocation and is less dangerous than a similar one on the stack.\n");
      printf("    Extra caution is still advised, however.\n");
      printf("  </message>\n");
      break;

    case Reference:
      printf("  <type>%s</type>\n",
	     ptr->data->Name);
      printf("  <message>\n");
      printf("    A function call is not being made here, but a reference is being made to\n");
      printf("    a name that is normally a vulnerable function.  It could be being\n");
      printf("    assigned as a pointer to function.\n\n");
      printf("  </message>\n");
      break;

    case PythonBacktick:
      printf("  <type>%s</type>\n",
	     ptr->data->Name);
      printf("  <message>\n");
      printf("    Do not use a variable that has been derived from untrusted sources\n");
      printf("    within a backtick.  Doing so could allow an attacker to execute\n");
      printf("    arbitrary python code.\n");
      printf("  </message>\n");
      break;

    case PhpBacktick:
    case PerlBacktick:
      printf("  <type>%s</type>\n",
	     ptr->data->Name);
      printf("  <message>\n");
      printf("    The backtick will act just like an call to exec(), so care should be\n");
      printf("    exercised that the string being backtick evaluated does not come from an\n");
      printf("    untrusted source.\n");
      printf("  </message>\n");
      break;

    case None:
      printf("  <type>%s</type>\n",
	     ptr->data->Name);
      printf("  <message>\n");
      printf("    Unknown!?!?\n\n");
      printf("  </message>\n");
      break;
    }
}

static
void report_vulnerability(vulnerability_t *ptr)
{
    int i;

    switch (ptr->type)
    {
        case BOProblem:
            if (ptr->data->BOProblem->FormatArg > 0)
            {
                printf("Check to be sure that the format string passed as argument %d to this function\n", ptr->data->BOProblem->FormatArg);
                printf("call does not come from an untrusted source that could have added formatting\n");
                printf("characters that the code is not prepared to handle.  Additionally, the format\n");
                printf("string could contain `%%s' without precision that could result in a buffer\n");
                printf("overflow.\n");
            }
            if (ptr->data->BOProblem->SrcBufArg > 0)
            {
                printf("Check to be sure that argument %d passed to this function call will not copy\n", ptr->data->BOProblem->SrcBufArg);
                printf("more data than can be handled, resulting in a buffer overflow.\n");
            }
            printf("\n");
            break;

        case FSProblem:
            printf("Check to be sure that the non-constant format string passed as argument %d to\n", ptr->data->FSProblem->Arg);
            printf("this function call does not come from an untrusted source that could have added\n");
            printf("formatting characters that the code is not prepared to handle.\n\n");
            break;

        case InputProblem:
            printf("Argument %d to this function call should be checked to ensure that it does not\n", ptr->data->InputProblem->Arg);
            printf("come from an untrusted source without first verifying that it contains nothing\n");
            printf("dangerous.\n\n");
            break;

        case Info:
            if (ptr->data->Info->Description != (char *)NULL)
            {
                cleanup_string(ptr->data->Info->Description);
                printf("%s\n", ptr->data->Info->Description);
            }
            if (ptr->data->Info->URL != (char *)NULL)
            {
                cleanup_string(ptr->data->Info->URL);
                printf("See also: %s\n", ptr->data->Info->URL);
            }
            printf("\n");
            break;

        case RaceConditionCheck:
            printf("A potential TOCTOU (Time Of Check, Time Of Use) vulnerability exists.  This is\n");
            printf("the first line where a check has occured.");
            if (ptr->uses != (toctou_use_t *)NULL && ptr->uses[0].lineno != 0)
            {
                printf("\nThe following line(s) contain uses that may match up with this check:\n");
                for (i = 0;  ptr->uses[i].lineno != 0;  i++)
                    printf("%s%d (%s)", (i == 0 ? "" : ", "), ptr->uses[i].lineno, ptr->uses[i].name);
                printf("\n");
            }
            else
            {
                printf("  No matching uses were detected.\n");
            }
            printf("\n");
            break;

        case RaceConditionUse:
            printf("A potential race condition vulnerability exists here.  Normally a call to this\n");
            printf("function is vulnerable only when a match check precedes it.  No check was\n");
            printf("detected, however one could still exist that could not be detected.\n\n");
            break;

        case StaticLocalBuffer:
            printf("Extra care should be taken to ensure that character arrays that are allocated\n");
            printf("on the stack are used safely.  They are prime targets for buffer overflow\n");
            printf("attacks.\n\n");
            break;

        case StaticGlobalBuffer:
            printf("Extra care should be taken to ensure that character arrays that are allocated\n");
            printf("with a static size are used safely.  This appears to be a global allocation\n");
            printf("and is less dangerous than a similar one on the stack.  Extra caution is still\n");
            printf("advised, however.\n\n");
            break;

        case Reference:
            printf("A function call is not being made here, but a reference is being made to a name\n");
            printf("that is normally a vulnerable function.  It could be being assigned as a\n");
            printf("pointer to function.\n\n");
            break;

        case PythonBacktick:
            printf("Do not use a variable that has been derived from untrusted sources within a backtick.\n");
            printf("Doing so could allow an attacker to execute arbitrary python code\n\n");
            break;

        case PhpBacktick:
        case PerlBacktick:
            printf("The backtick will act just like an call to exec(), so care should be exercised that the\n");
            printf(" string being backtick evaluated does not come from an untrusted source\n\n");
            break;

        case None:
            printf("Unknown!?!?\n\n");
            break;
    }
}

static
void html_report_inputs(void)
{
    int         count = 0;
    input_t *   next;
    input_t *   ptr;

    if (!(flags & INPUT_MODE))
        return;

    for (ptr = input_head;  ptr != (input_t *)NULL;  ptr = next)  
    {
        next = ptr->next;
        if (!lookup_ignore(ptr->filename, ptr->lineno, ptr->data->Name))
        {
            count++;
            printf("<b>%s</b>: Line %d: function %s<br>\n", ptr->filename, ptr->lineno, ptr->data->Name);
        }
        free(ptr);
    } 
    input_head = input_tail = (input_t *)NULL; 
 
    if (count > 0)
    {
        printf("<br>Double check to be sure that all input accepted from an external data source\n");
        printf("does not exceed the limits of the variable being used to hold it. Also make\n");
        printf("sure that the input cannot be used in such a manner as to alter your program's\n");
	    printf("behaviour in an undesirable way.<br>\n");
    }
}

static
void xml_report_inputs(void)
{
    int         count = 0;
    input_t *   next;
    input_t *   ptr;

    if (!(flags & INPUT_MODE))
        return;

    for (ptr = input_head;  ptr != (input_t *)NULL;  ptr = next)  
    {
        next = ptr->next;
        if (!lookup_ignore(ptr->filename, ptr->lineno, ptr->data->Name))
        {
            count++;
            printf("<input>\n");
            printf("<message>");
            printf("Double check to be sure that all input accepted from an external data source does not exceed the limits of the variable being used to hold it. Also make sure that the input cannot be used in such a manner as to alter your program's behaviour in an undesireable way");
            printf("</message>\n") ;
            printf("<function>%s</function>\n", ptr->data->Name);
            printf("<file><name>%s</name><line>%d</line></file>\n", ptr->filename, ptr->lineno);
            printf("</input>\n");
        }
        free(ptr);
    }
    input_head = input_tail = (input_t *)NULL;
    
}


static
void report_inputs(void)
{
    int         count = 0;
    input_t *   next;
    input_t *   ptr;

    if (!(flags & INPUT_MODE))
        return;

    for (ptr = input_head;  ptr != (input_t *)NULL;  ptr = next)
    {
        next = ptr->next;
        if (!lookup_ignore(ptr->filename, ptr->lineno, ptr->data->Name))
        {
            count++;
            printf("%s: %d: %s\n", ptr->filename, ptr->lineno, ptr->data->Name);
        }
        free(ptr);
    }
    input_head = input_tail = (input_t *)NULL;

    if (count > 0)
    {
        printf("Double check to be sure that all input accepted from an external data source\n");
        printf("does not exceed the limits of the variable being used to hold it.  Also make\n");
        printf("sure that the input cannot be used in such a manner as to alter your program's\n");
        printf("behaviour in an undesirable way.\n\n");
    }
}

void generate_xml() {
  char vuln_reported=0;		/* Have we spewed the vuln message yet? */
  vulnerability_t *   ptr;

  /* Initial necessary cruft */
  /* Loop iterates through all of the problems found */
  for (ptr = list_head;  ptr != (vulnerability_t *)NULL;  ptr = ptr->next) {

    /* Check the severity of the vuln.  If it's below our level, skip 
     * and go to the next one */
    if (ptr->severity != Default && ptr->severity < warning_level) {
      continue;
    }
    
    if (determine_ignorance(ptr))
    {
      continue;
    }

    /* If we haven't reported the vuln message yet for this type, do so. */
    if(!vuln_reported) {
      build_xml_vulnerability(ptr);
      vuln_reported++;
    }

    /* If the filename of this vuln is different from the filename of the 
     * previous vuln, report the filename, or if the vuln type is different*/
    if(ptr->prev==(vulnerability_t *)NULL||
       strcmp(ptr->filename,ptr->prev->filename)|| ptr->type == RaceConditionCheck ||
       ptr->prev->type != ptr->type || ptr->prev->data != ptr->data) {
      printf("  <file>\n    <name>%s</name>\n",
	     ptr->filename);
    }

    /* report the line number of the infraction */
    printf("    <line>%d</line>\n",
	   ptr->lineno); 
    if (flags & SHOW_COLUMNS)
        printf("    <column>%d</column>\n", ptr->column);
    if (flags & SHOW_CONTEXT)
    {
      char *ctx = NULL;
      ctx = getctx(ptr->filename, ptr->lineno);
      if (ctx)
      {
        ctx = xml_escape(ctx);
        printf("<context>%s</context>\n", ctx);
        free(ctx);
      }
    }
    
    /* If the next file or vuln type is different close the file tag */
    if(ptr->next==(vulnerability_t *)NULL||
       strcmp(ptr->filename,ptr->next->filename)|| ptr->type == RaceConditionCheck ||
       ptr->next->type != ptr->type || ptr->next->data != ptr->data) {
      printf("  </file>\n");
    }

    /* If the next vuln is different reset the vuln_reported variable to 0 so
     * we know to report next time */
    if (ptr->next == (vulnerability_t *)NULL || ptr->next->type != ptr->type ||
	ptr->type == RaceConditionCheck || ptr->next->data != ptr->data) {
      printf("</vulnerability>\n");
      vuln_reported=0;
    }

  }
  xml_report_inputs();
 
 if (!(flags & NO_FOOTER))
 {
#ifdef _MSC_VER
	DWORD ttime;
#else
	struct timeval ttime;
#endif
    
	float fsecs;
	
#ifdef _MSC_VER
	ttime = time_finished - time_started;
	fsecs = ttime/1000 + (float)((ttime%1000)/1000);
#else
	diff_times(&time_finished, &time_started, &ttime);
	fsecs = ttime.tv_sec+ (ttime.tv_usec/(double)1000000);
#endif
    printf("<timing>\n");
    printf("<total_lines>%d</total_lines>\n", total_lines);
    printf("<total_time>%f</total_time>\n", fsecs);
    printf("<lines_per_second>%d</lines_per_second>\n", (int)(total_lines/fsecs));
    printf("</timing>\n");
    }

  printf("</rats_output>\n");

}
     
static void build_html_vulnerability(vulnerability_t *ptr) {
    int i;
    

    
    /* Output the severity */
    printf("  <b>Severity: %s</b><br/>\n",
	   severities[ptr->severity]);

    switch (ptr->type)
    {
    case BOProblem:
      if (ptr->data->BOProblem->FormatArg > 0)
	{
	  printf("  Issue: %s<br/>\n",
		 ptr->data->Name);
	  printf("    Check to be sure that the format string passed as argument %d to this\n", ptr->data->BOProblem->FormatArg);
	  printf("    function call does not come from an untrusted source that could have added\n");
	  printf("    formatting characters that the code is not prepared to handle.\n");
	  printf("    Additionally, the format string could contain `%%s' without precision that\n");
	  printf("    could result in a buffer overflow.\n");
	  printf("  <br/>\n");
	}
      if (ptr->data->BOProblem->SrcBufArg > 0)
	{
	  printf("  Issue: %s<br/>\n",
		 ptr->data->Name);
	  printf("    Check to be sure that argument %d passed to this function call will not\n", ptr->data->BOProblem->SrcBufArg);
	  printf("    copy more data than can be handled, resulting in a buffer overflow.\n");
	  printf("  <br/>\n");
	}
      break;

    case FSProblem:
      printf("  Issue: %s<br/>\n",
	     ptr->data->Name);
      printf("    Check to be sure that the non-constant format string passed as argument %d \n", ptr->data->FSProblem->Arg);
      printf("    to this function call does not come from an untrusted source that could\n");
      printf("    have added formatting characters that the code is not prepared to handle.\n");
      printf("  <br/>\n");
      break;

    case InputProblem:
      printf("  Issue: %s<br/>\n",
	     ptr->data->Name);
      printf("    Argument %d to this function call should be checked to ensure that it does\n", ptr->data->InputProblem->Arg);
      printf("    not come from an untrusted source without first verifying that it contains\n");
      printf("    nothing dangerous.\n");
      printf("  <br/>\n");
      break;

    case Info:
      printf("  Issue: %s<br/>\n",
	     ptr->data->Name);
      if (ptr->data->Info->Description != (char *)NULL) {
	cleanup_string(ptr->data->Info->Description);
	printf("    %s\n", ptr->data->Info->Description);
      }
      if (ptr->data->Info->URL != (char *)NULL)	{
	cleanup_string(ptr->data->Info->URL);
	/* This should possibly be made into it's own tag -- Robert */
	printf("    See also:\n %s\n", ptr->data->Info->URL);
      }
      printf("  <br/>\n");
      break;

    case RaceConditionCheck:
      printf("  Issue: %s<br/>\n",
	     ptr->data->Name);
      printf("    A potential TOCTOU (Time Of Check, Time Of Use) vulnerability exists.\n");
      printf("    This is the first line where a check has occured.");
      if (ptr->uses != (toctou_use_t *)NULL && ptr->uses[0].lineno != 0)
	{
	  printf("\n    The following line(s) contain uses that may match up with this check:\n");
	  for (i = 0;  ptr->uses[i].lineno != 0;  i++)
	    printf("    %s%d (%s)", (i == 0 ? "" : ", "), ptr->uses[i].lineno, ptr->uses[i].name);
	  printf("\n");
	}
      else
	{
	  printf("    No matching uses were detected.\n");
	}
      printf("  <br/>\n");
      break;

    case RaceConditionUse:
      printf("  Issue: fixed size local buffer<br/>\n");
      printf("    A potential race condition vulnerability exists here.  Normally a call\n");
      printf("    to this function is vulnerable only when a match check precedes it.  No\n");
      printf("    check was detected, however one could still exist that could not be\n");
      printf("    detected.\n");
      printf("  <br/>\n");
      break;

    case StaticLocalBuffer:
      printf("  Issue: fixed size global buffer<br/>\n");
      printf("    Extra care should be taken to ensure that character arrays that are\n");
      printf("    allocated on the stack are used safely.  They are prime targets for\n");
      printf("    buffer overflow attacks.\n");
      printf("  <br/>\n");
      break;

    case StaticGlobalBuffer:
      printf("  Issue: %s<br/>\n",
	     ptr->data->Name);
      printf("    Extra care should be taken to ensure that character arrays that are\n");
      printf("    allocated with a static size are used safely.  This appears to be a\n");
      printf("    global allocation and is less dangerous than a similar one on the stack.\n");
      printf("    Extra caution is still advised, however.\n");
      printf("  <br/>\n");
      break;

    case Reference:
      printf("  Issue: %s<br/>\n",
	     ptr->data->Name);
      printf("    A function call is not being made here, but a reference is being made to\n");
      printf("    a name that is normally a vulnerable function.  It could be being\n");
      printf("    assigned as a pointer to function.\n\n");
      printf("  <br/>\n");
      break;

    case PythonBacktick:
      printf("  Issue: %s<br/>\n",
	     ptr->data->Name);
      printf("    Do not use a variable that has been derived from untrusted sources\n");
      printf("    within a backtick.  Doing so could allow an attacker to execute\n");
      printf("    arbitrary python code.\n");
      printf("  <br/>\n");
      break;

    case PhpBacktick:
    case PerlBacktick:
      printf("  Issue: %s<br/>\n",
	     ptr->data->Name);
      printf("    The backtick will act just like an call to exec(), so care should be\n");
      printf("    exercised that the string being backtick evaluated does not come from an\n");
      printf("    untrusted source.\n");
      printf("  <br/>\n");
      break;

    case None:
      printf("  Issue: %s<br/>\n",
	     ptr->data->Name);
      printf("    Unknown!?!?\n\n");
      printf("  <br/>\n");
      break;
    }
}

void generate_html() {
  char vuln_reported=0;		/* Have we spewed the vuln message yet? */
  vulnerability_t *   ptr;

  /* Initial necessary cruft */
  printf("<h2>RATS results.\n</h2><br>\n");

  /* Loop iterates through all of the problems found */
  for (ptr = list_head;  ptr != (vulnerability_t *)NULL;  ptr = ptr->next) {

    /* Check the severity of the vuln.  If it's below our level, skip 
     * and go to the next one */
    if (ptr->severity != Default && ptr->severity < warning_level) {
      continue;
    }
    
    if (determine_ignorance(ptr))
    {
      continue;
    }
    /* If we haven't reported the vuln message yet for this type, do so. */
    if(!vuln_reported) {
      build_html_vulnerability(ptr);
      vuln_reported++;
    }

    /* If the filename of this vuln is different from the filename of the 
     * previous vuln, report the filename, or if the vuln type is different*/
    if(ptr->prev==(vulnerability_t *)NULL||
       strcmp(ptr->filename,ptr->prev->filename)|| ptr->type == RaceConditionCheck ||
       ptr->prev->type != ptr->type || ptr->prev->data != ptr->data) {
       printf("<ul>\n");
       if (!(flags & SHOW_CONTEXT))
       {
         printf("File: <b>%s</b><br/>Lines: \n",
	     ptr->filename);
       }
    }

    /* report the line number of the infraction */
   if (!(flags & SHOW_CONTEXT))
   {
      printf("%d",
	   ptr->lineno); 
      if (flags & SHOW_COLUMNS)
        printf("[%d]", ptr->column);
      printf(" ");
    } else {
      char *ctx = NULL;
      printf("File: <b>%s</b> Line:<b>%d", ptr->filename, ptr->lineno);
      if (flags & SHOW_COLUMNS)
        printf("[%d]", ptr->column);
      printf("</b><br>\n");
      ctx = getctx(ptr->filename, ptr->lineno);
      if(ctx)
      {
        printf("%s<br>\n", ctx);
        free(ctx);
      }   
    }

      
      
    
    /* If the next file or vuln type is different close the file tag */
    if(ptr->next==(vulnerability_t *)NULL||
       strcmp(ptr->filename,ptr->next->filename)|| ptr->type == RaceConditionCheck ||
       ptr->next->type != ptr->type || ptr->next->data != ptr->data) {
      printf("  </ul>\n");
    }

    /* If the next vuln is different reset the vuln_reported variable to 0 so
     * we know to report next time */
    if (ptr->next == (vulnerability_t *)NULL || ptr->next->type != ptr->type ||
	ptr->type == RaceConditionCheck || ptr->next->data != ptr->data) {
      vuln_reported=0;
    }

  }

  
  printf("<h3>Inputs detected at the following points</h3>\n");
  
  printf("<ul>\n");
  html_report_inputs();
  printf("</ul>\n");

  printf("<br><br>\n");

 
  if (!(flags & NO_FOOTER))
  {
#ifdef _MSC_VER
	DWORD ttime;
#else
	struct timeval ttime;
#endif
    
	float fsecs;
	
#ifdef _MSC_VER
	ttime = time_finished - time_started;
	fsecs = ttime/1000 + (float)((ttime%1000)/1000);
#else
	diff_times(&time_finished, &time_started, &ttime);
	fsecs = ttime.tv_sec+(ttime.tv_usec/(double)1000000);
#endif


    printf("Total lines analyzed: <b>%d</b><br>\n", total_lines);
    printf("Total time <b>%f</b> seconds<br>\n", fsecs);
    printf("<b>%d</b> lines per second<br>\n", (int)(total_lines/fsecs));
    }

  printf("</body></html>\n");
}
      

static int
time_greater(const struct timeval *a, const struct timeval *b)
{
  if(a->tv_sec > b->tv_sec || (a->tv_sec == b->tv_sec &&
                               a->tv_usec > b->tv_usec))
  {
    return 1;
  }
  return 0;
}

static void
diff_times(const struct timeval *a, const struct timeval *b,
                 struct timeval *result)
{
  const struct timeval *bigger, *lesser;

  if(time_greater(a,b))
  {
    bigger = a; lesser = b;
  } else
  {
      bigger = b; lesser = a;
  }
  if(bigger->tv_usec < lesser->tv_usec)
  {
    result->tv_usec = 1000000 - lesser->tv_usec + bigger->tv_usec;
    result->tv_sec  = bigger->tv_sec - lesser->tv_sec - 1;
  }
  else
  {
    result->tv_usec = bigger->tv_usec - lesser->tv_usec;
    result->tv_sec  = bigger->tv_sec  - lesser->tv_sec;
  }
}


/* returns 1 if you should ignore this, 0 if not */
static int
determine_ignorance(vulnerability_t *ptr)
{

    char *lookup = NULL;

    switch (ptr->type)
    {
        case BOProblem:
        case FSProblem:
        case Info:
        case InputProblem:
        case RaceConditionCheck:
        case RaceConditionUse:
            lookup = ptr->data->Name;
            break;

        case StaticLocalBuffer:
            lookup = "$fixed_buffer$";
            break;

        case StaticGlobalBuffer:
            lookup = "$global_buffer$";
            break;

        case Reference:
            lookup = ptr->data->Name;
            break;

        case PythonBacktick:
            lookup = "$python_backtick$";
            break;

        case PhpBacktick:
            lookup = "$php_backtick$";
            break;

        case PerlBacktick:
            lookup = "$perl_backtick$";
            break;

        case None:
        default:
            lookup = (char *)NULL;
            break;
    }
    if (lookup != NULL)
    {
        if (lookup_ignore(ptr->filename, ptr->lineno, lookup))
        {
            return 1;
        }
    }
    return 0;
}


void generate_report()
{
    char *              name;
    char *              name2 = (char *)NULL;
    int   		doprint = 0;
    int			reported = 0;
    ignore_t *          iptr;
    ignore_t *          inext;
    vulnerability_t *   ptr;
    vulnerability_t *   next;
 

    for (ptr = list_head;  ptr != (vulnerability_t *)NULL;  ptr = ptr->next)
    {
        if (ptr->severity == Default || ptr->severity >= warning_level)
        {
            switch (ptr->type)
            {
                case BOProblem:
                case FSProblem:
                case Info:
                case InputProblem:
                case RaceConditionCheck:
                case RaceConditionUse:
                    name = ptr->data->Name;
                    break;

                case StaticLocalBuffer:
                    name = "fixed size local buffer";
                    break;

                case StaticGlobalBuffer:
                    name = "fixed size global buffer";
                    break;

                case Reference:
                    name = "non-function call reference";

                    name2 = ptr->data->Name;
                    break;
               
                case PythonBacktick: 
                    name = "backtick";
                    break;

                case PhpBacktick:
                    name = "backtick";
                    break;

                case PerlBacktick:
                    name = "backtick";
                    break;

                case None:
                default:
                    name = "Unknown / Database Error";
                    break;
            }
            doprint = 1;
            if (determine_ignorance(ptr))
            {
              doprint =  0;
            }

            if (doprint)
            {
	      if (name2 == (char *)NULL) {
                    printf("%s:%d", ptr->filename, ptr->lineno);
                    if (flags & SHOW_COLUMNS)
                        printf("[%d]", ptr->column);
                    printf(": %s: %s\n", severities[ptr->severity], name);
	      }
	      else {
                   printf("%s:%d", ptr->filename, ptr->lineno);
                    if (flags & SHOW_COLUMNS)
                        printf("[%d]", ptr->column);
                    printf(": %s: %s: %s\n", severities[ptr->severity], name, name2);
              
	      }

             if (flags & SHOW_CONTEXT)
             { 
                 char *ctx = NULL;
                 ctx = getctx(ptr->filename, ptr->lineno);
                 if (ctx)
                 {
                     printf("%s", ctx);
                     free(ctx);
                 }
              } 
	      reported++;
            }

            if (ptr->next == (vulnerability_t *)NULL || ptr->next->type != ptr->type ||
                ptr->type == RaceConditionCheck || ptr->next->data != ptr->data)
            {
                if (reported)
                    report_vulnerability(ptr);
            }
            if (ptr->next && (ptr->next->type != ptr->type))
              reported = 0;

        }
    }

    report_inputs();

    for (iptr = ignore_list;  iptr != (ignore_t *)NULL;  iptr = inext)
    {
        inext = iptr->next;
        if (iptr->token != (char *)NULL)
            free(iptr->token);
        free(iptr);
    }
    ignore_list = (ignore_t *)NULL;

    for (ptr = list_head;  ptr != (vulnerability_t *)NULL;  ptr = next)
    {
        next = ptr->next;
        free(ptr);
    }
    list_head = list_tail = (vulnerability_t *)NULL;
    if (!(flags & NO_FOOTER))
    {
#ifdef _MSC_VER
	DWORD ttime;
#else
	struct timeval ttime;
#endif
    
	float fsecs;
	
#ifdef _MSC_VER
	ttime = time_finished - time_started;
	fsecs = ttime/1000 + (float)(ttime%1000)/1000;
#else
	diff_times(&time_finished, &time_started, &ttime);
	fsecs = ttime.tv_sec+(ttime.tv_usec/(double)1000000);
#endif

      printf("Total lines analyzed: %d\n", total_lines);
      printf("Total time %f seconds\n", fsecs); 
      printf("%d lines per second\n", (int)(total_lines/fsecs));
    }
}

ignore_t *new_ignore(int lineno, char *token)
{
    ignore_t *  ign;

    if ((ign = (ignore_t *)malloc(sizeof(ignore_t))) == (ignore_t *)NULL)
        return (ignore_t *)NULL;
    ign->filename = current_file;
    ign->lineno   = lineno;
    ign->token    = (token == (char *)NULL ? token : strdup(token));
    ign->next     = ignore_list;
    ignore_list   = ign;

    return ign;
}

static
int lookup_ignore(char *filename, int lineno, char *token)
{
    ignore_t *  ptr;

    for (ptr = ignore_list;  ptr != (ignore_t *)NULL;  ptr = ptr->next)
    {
        if (ptr->filename != filename)  /* yes, this is safe and will work */
            continue;
        if (ptr->lineno != lineno)
            continue;
        if (ptr->token == (char *)NULL || !strcmp(ptr->token, token))
            return 1;
    }

    return 0;
}
