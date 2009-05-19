AC_INIT(rats-c.xml)
AC_PROG_CC()
AC_PROG_LEX()
AC_PROG_INSTALL
LDFLAGS="$LDFLAGS -L/usr/local/lib"
CFLAGS="$CFLAGS -I/usr/local/include"
CPPFLAGS="$CPPFLAGS -I/usr/local/include"

AC_ARG_WITH(expat-lib,
    [  --with-expat-lib[=path] ],
    [LDFLAGS="$LDFLAGS -L$withval"],
    )
AC_ARG_WITH(expat-include,
    [  --with-expat-include[=path] ],
    [CFLAGS="$CFLAGS -I$withval" 
     CPPFLAGS="$CPPFLAGS -I$withval"]
    )
AC_CHECK_LIB(expat, XML_ParserCreate, [],AC_MSG_ERROR("Expat library not found. You may need to use the --with-expat-lib\[=path\] command line switch to specify which directory the expat libraries are located"))
AC_CHECK_HEADERS(expat.h, [expat_h_found="yes"], [expat_h_found="no"])
AC_CHECK_HEADERS(xmlparse.h, [xmlparse_h_found="yes"], [xmlparse_h_found="no"])


if test "$xmlparse_h_found" = "no" && test "$expat_h_found" = "no"
then
  AC_MSG_ERROR("Unable to locate xmlparse.h or expat.h. You may need to use the --with-expat-include\[=path\] to specify which directory the expat include files are located") 
fi

AC_OUTPUT(Makefile)
