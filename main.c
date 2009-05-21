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
// Modified February 17th, 2002 by Mike Ellison (www.code-rock.com)
//              Porting to Win32

#include <stdio.h>
#include <stdlib.h>
#include "getopt.h"
#ifndef _MSC_VER
#include <sys/time.h>
#include <unistd.h>
#else
/* needed for Win32 - mae 02/17/02 */
#include <windows.h>
#endif


#include <sys/stat.h>
#include <ctype.h>
#include <string.h>
#include "report.h"
#include "version.h"

int     flags     = 0;
int     forcelang = 0;
char *  progname  = "a.out";

#ifndef _MSC_VER
#define XML_DB_BASE DATADIR "/"
#else
#define XML_DB_BASE
#endif

char *default_files[] =
{
    XML_DB_BASE "rats.xml",
    XML_DB_BASE "rats-c.xml",
    XML_DB_BASE "rats-python.xml",
    XML_DB_BASE "rats-perl.xml",
    XML_DB_BASE "rats-php.xml",
    XML_DB_BASE "rats-openssl.xml",
	XML_DB_BASE "rats-ruby.xml"
};

#ifdef _MSC_VER
#define strcasecmp  _stricmp

#endif


static long 
get_langcount(char *lang)
{
    Hash lhash;

    lhash = (Hash) HashGet(database, lang);
    if (!lhash)
      return 0;
    return (long)HashCount(lhash);
}
  
static
int load_database(char *filename, int silent)
{
    int         result;
    FILE *      fd;
    char *      buf;
    struct stat st;

    /* Carriage returns seem to kill the XMLParser under win32, so just
     * load it in binary mode. - mae
     */
#ifdef _MSC_VER
    if ((fd = fopen(filename, "rb")) == (FILE *)NULL)
#else
    if ((fd = fopen(filename, "r")) == (FILE *)NULL)
#endif
    {
        if (!silent)
        {
            fprintf(stderr, "Unable to open '%s' for reading.\n", filename);
        }
        return 0;
    }

    fstat(fileno(fd), &st);
    buf = (char *)malloc(st.st_size + 1);
    fread(buf, st.st_size, 1, fd);
    *(buf + st.st_size) = '\0';

    result = (ParseVulnDb(buf, &database) != NULL);
    defaultdb = HashGet(database, "default");
    free(buf);
    return result;
}

void force_language(char *lang) {
  if (!strcasecmp(lang, "python"))
    forcelang = LANG_PYTHON;
  else if (!strcasecmp(lang, "c"))
    forcelang = LANG_C;
  else if (!strcasecmp(lang, "perl"))
    forcelang = LANG_PERL;
  else if (!strcasecmp(lang, "php"))
    forcelang = LANG_PHP;
  else if (!strcasecmp(lang, "ruby"))
    forcelang = LANG_RUBY;
  else {
    fprintf(stderr, "Language %s unknown, using filename extensions instead\n", lang);
  } 
}

static
void usage(void)
{
    printf("RATS v%d.%d - Rough Auditing Tool for Security\n", VERSION_MAJOR, VERSION_MINOR);
    printf("Copyright 2001, 2002 Secure Software Inc\nhttp://www.securesoftware.com\n\n");
    //    printf("Modified for Win32 02/17/02 by Mike Ellison (www.code-rock.com)\n\n");
    printf("usage: %s [-adhilrwxR] [--help] [--database|--db]  name1 name2 ... namen\n\n", progname);
    printf("    -a <fun>       report any occurence of function 'fun' in the source file(s)\n");
    printf("    -d <filename>  specify an alternate vulnerability database.\n");
    printf("    --db\n");
    printf("    --database\n");
    printf("    -h             display usage information (what you\'re reading)\n");
    printf("    --help\n");
    printf("    -i             report functions that accept external input\n");
    printf("    --input\n");
    printf("    -l <language>  force the specified langauge to be used\n");
    printf("    --language <language>\n");
    printf("    -r             include references that are not function calls\n");
    printf("    --references\n");
    printf("    -w <1,2,3>     set warning level (default %d)\n", warning_level);
    printf("    --warning <1,2,3>\n");
    printf("    -x             do not load default databases\n");
    printf("    -R             don't recurse subdirectories scanning for matching files\n");
    printf("    --no-recursion\n");
    printf("    --xml          Output in XML.\n");
    printf("    --html         Output in HTML.\n");
    printf("    --follow-symlinks\n");
    printf("                   Follow symlinks and process files found.\n");
    printf("    --noheader\n");
    printf("		       Don't print initial header in output\n");
    printf("    --nofooter\n");
    printf("                   Don't show timing information footer at end of analysis\n");
    printf("    --quiet\n");
    printf("                   Don't print status information regarding what file is being analyzed\n");
    printf("    --resultsonly\n");
    printf("                   No header, footer, or status information\n");
    printf("    --columns\n");
    printf("                   Show column number of hte line where the problem occured.\n");
    printf("    --context\n");
    printf("                   Display the line of code that caused the problem report\n");
}

void
output_header(int flags)
{

  char **keys = NULL;
  char **ksav = NULL;

  if (flags & NO_HEADER)
      return;

  keys = HashKeys(database);
  ksav = keys;

  while(keys && *keys)
  {
    long lcnt = 0;
    lcnt = get_langcount(*keys);
    printf("Entries in %s database: %ld\n", *keys, lcnt);
    keys++;
  }
  HashFreeKeys(database, ksav);
}


void
output_xmlheader(int flags)
{

  char **keys = NULL;
  char **ksav = NULL;


  printf("<?xml version=\"1.0\"?>");
  printf("<rats_output>\n");
  
  if (flags & NO_HEADER)
      return;

  keys = HashKeys(database);
  ksav = keys;
  
  printf("<stats>\n"); 
  while(keys && *keys)
  {
    long lcnt = 0;
    lcnt = get_langcount(*keys);
    printf("<dbcount lang=\"%s\">%ld</dbcount>\n", *keys, lcnt);
    keys++;
  }
  printf("</stats>\n");
  HashFreeKeys(database, ksav);
}

void
output_htmlheader(int flags)
{ 

  char **keys = NULL;
  char **ksav = NULL;


  printf("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">\n");
  printf("<html>\n");
  printf("<head></head>\n");
  printf("<body>\n");

  if (flags & NO_HEADER)
    return;

  keys = HashKeys(database);
  ksav = keys;

  while(keys && *keys)
  { 
    long lcnt = 0;
    lcnt = get_langcount(*keys);
    printf("Entries in %s database: <b>%ld</b><br>\n", *keys, lcnt);
    keys++;
  }
  printf("<br><br>");
  HashFreeKeys(database, ksav);
}   

int main(int argc, char **argv)
{
    int     dbloaded = 0, i, load_default = 1;
    Vuln_t *uservul = (Vuln_t *)NULL;
    Hash    defh = (Hash)NULL;

#ifdef _MSC_VER
    char *  tslash;
#endif

    int option_index=0;
    static struct option long_options[] = {
      {"help",0,0,0},
      {"database",required_argument,0,0},
      {"db",required_argument,0,0},
      {"input",0,0,0},
      {"language",required_argument,0,0},
      {"references",0,0,0},
      {"warning",required_argument,0,0},
      {"no-recursion",0,0,0},
      {"xml",0,0,0},
      {"html",0,0,0},
      {"noheader", 0,0,0},
      {"nofooter", 0,0,0},
      {"quiet", 0,0,0},
      {"resultsonly", 0,0,0},
      {"follow-symlinks",0,0,0},
      {"columns", 0,0,0},
      {"context", 0,0,0},
      {"all-static", 0,0,0},
    };
    progname = argv[0];
    flags|=RECURSIVE_FILE_SCAN;

    while ((i = getopt_long(argc, argv, "a:d:hil:Rrw:x",

			    long_options,&option_index)) != -1)
    {
        switch (i)
        {
	case 0:
	  if(!strcmp(long_options[option_index].name,"help")) {
	    usage();
	    exit(1);
	    return 1;
	  }
	  if(!strcmp(long_options[option_index].name,"database")||
	     !strcmp(long_options[option_index].name,"db")) {
	    if (load_database(optarg, 0))
	      dbloaded++;
	    break;
	  }
	  if(!strcmp(long_options[option_index].name,"input")) {
	    flags |= INPUT_MODE;
	    break;
	  }
	  if(!strcmp(long_options[option_index].name,"language")) {
	    force_language(optarg);
	    break;
	  }
	  if(!strcmp(long_options[option_index].name,"references")) {
	    flags |= INCLUDE_ALL_REFERENCES;
	    break;
	  }
	  if(!strcmp(long_options[option_index].name,"warning")) {	  
	    warning_level = 4 - atoi(optarg);
	    if (warning_level < 1)
	      warning_level = 1;
	    if (warning_level > 3)
	      warning_level = 3;
	    break;
	  }
	  
	  if(!strcmp(long_options[option_index].name,"no-recurssion")) {	  
	    flags &= ~RECURSIVE_FILE_SCAN;
	    break;
	  }
	  if(!strcmp(long_options[option_index].name,"xml")) {
	    flags |= XML_OUTPUT;
	    break;
	  }
	  if(!strcmp(long_options[option_index].name,"html")) {
	    flags |= HTML_OUTPUT;
	    break;
	  }
	  if(!strcmp(long_options[option_index].name,"follow-symlinks")) {
	    flags |= FOLLOW_SYMLINK;
	    break;
	  }
          if (!strcmp(long_options[option_index].name, "noheader"))
          {
            flags |= NO_HEADER;
            break;
          }

          if (!strcmp(long_options[option_index].name, "nofooter"))
          {
            flags |= NO_FOOTER;
            break;
          }
          if (!strcmp(long_options[option_index].name, "quiet"))
          {
            flags |= NO_STATUS;
            break;
          }
          if (!strcmp(long_options[option_index].name, "columns"))
          {
            flags |= SHOW_COLUMNS;
            break;
          }
          if (!strcmp(long_options[option_index].name, "context"))
          {
            flags |= SHOW_CONTEXT;
            break;
          }

          if (!strcmp(long_options[option_index].name, "all-static"))
          {
            flags |= ALL_STATIC;
            break;
          }

          if (!strcmp(long_options[option_index].name, "resultsonly"))
          {
            flags |= NO_HEADER;
            flags |= NO_FOOTER;
            flags |= NO_STATUS;
            break;
          }


	  break;

	case 'a':
	  if (!database)
	    database = HashInit();
	  if (!(defh = (Hash)HashGet(database, "default")))
	    {
	      defh = HashInit();
	      HashInsert(database, defh, "default");
	    }
	  uservul = (Vuln_t *)malloc(sizeof(Vuln_t));
	  InitVuln(uservul);
	  uservul->Name = (char *)malloc(strlen(optarg) + 1);
	  strncpy(uservul->Name, optarg, strlen(optarg));
	  uservul->Name[strlen(optarg)] = '\0';
	  uservul->Info = (Info_t *)malloc(sizeof(Info_t));
	  InitInfo(uservul->Info);
	  uservul->Info->Severity = Medium;
	  uservul->Info->Description = (char *)malloc(34);
	  strcpy(uservul->Info->Description, "Reporting user specified function");
	  
	  HashInsert(defh, uservul, optarg);
	  if (!defaultdb)
	    defaultdb = (Hash)HashGet(database, "default");
	  break;
	  
	case 'd':
	  if (load_database(optarg, 0))
	    dbloaded++;
	  break;
	  
	case 'h':
	  usage();
	  exit(1);
	  return 1;
	  
	case 'i':
	  flags |= INPUT_MODE;
	  break;
	  
	case 'l':
	  force_language(optarg);
	  break;
	  
	case 'r':
	  flags |= INCLUDE_ALL_REFERENCES;

	  break;
	  
	case 'w':
	  warning_level = 4 - atoi(optarg);
	  if (warning_level < 1)
	    warning_level = 1;
	  if (warning_level > 3)
	    warning_level = 3;
	  break;
	  
	case 'x':
	  load_default = 0;
	  break;
	  
	case 'R':
	  flags &= ~RECURSIVE_FILE_SCAN;
	  break;
	  
	default:
	  exit(1);
	  return 1;
        }
    }
    
    if (load_default)
    {
        /* Load the vulnerability database into memory */
        int i;

#ifdef _MSC_VER
        /* Under win32, instead of using DATADIR, we find the executable path
         * and just use its directory to look for the .xml files. - mae
         */
        char    actualPath[_MAX_PATH + 1];

        if (!GetModuleFileName(GetModuleHandle(NULL), actualPath, _MAX_PATH))
        {
            fprintf(stderr,"Error getting module path under win32?\n");
            exit(1);
            return 1;
        }

        if (!(tslash = strrchr(actualPath, '\\')))
        {
            fprintf(stderr,"Error getting current path under win32?\n");
            exit(1);
            return 1;
        }
        *(tslash + 1) = '\0';
#endif
        for (i = 0;  i < sizeof(default_files) / sizeof(char *);  i++)
        {
#ifdef _MSC_VER
            /* under win32, use the path of the executeable and append the
             * default file to it - mae
             */
            char * curxml;

            curxml = (char *)malloc(strlen(actualPath) +
                                    strlen(default_files[i]) + 1);
            if (!curxml)
            {
                fprintf(stderr,"Out of memory allocating path.\n");
                exit(1);
                return 1;
            }
            strcpy(curxml, actualPath);
            strcat(curxml,default_files[i]);

            if (load_database(curxml, 1))
                dbloaded++;
            free(curxml);
#else
            if (load_database(default_files[i], 1))
                dbloaded++;
#endif
        }
    }

    if (!dbloaded)  
    {
        fprintf(stderr, "No database able to be loaded, exiting.\n");
        exit(1);
        return 1;
    }

    if (flags & XML_OUTPUT)
    {
        output_xmlheader(flags);
    } else if (flags & HTML_OUTPUT) {
        output_htmlheader(flags);
    } else {
        output_header(flags);
    }

#ifdef _MSC_VER
	time_started = GetTickCount();
#else
    gettimeofday(&time_started,NULL);
#endif
    if (optind >= argc)
    {
        process_file("<stdin>", forcelang);

    }
    else
    {
        while (optind < argc)
        {
            char *  filename;
            filename = argv[optind++];

            process_file(filename, forcelang);
        }
    }
#ifdef _MSC_VER
	time_finished = GetTickCount();
#else
    gettimeofday(&time_finished, NULL);
#endif
    if(flags & XML_OUTPUT) {
      generate_xml();
    }
    else if(flags & HTML_OUTPUT) {
      generate_html();
    }
    else {
      generate_report();
    }

    exit(0);
    return 0;
}


