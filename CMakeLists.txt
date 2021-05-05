cmake_minimum_required(VERSION 3.15)

project(RATS)

find_package(EXPAT REQUIRED)


if(WIN32)


  find_library(EXPAT_DLL NAMES libexpat.dll REQUIRED)

  message("EXPAT_DLL : ${EXPAT_DLL}")

  set(CMAKE_INSTALL_SYSTEM_RUNTIME_LIBS 
    ${EXPAT_DLL}
  )
endif()

set(CMAKE_INSTALL_SYSTEM_RUNTIME_COMPONENT Runtime)
set(CMAKE_INSTALL_SYSTEM_RUNTIME_DESTINATION ${CMAKE_INSTALL_BINDIR})
set(CMAKE_INSTALL_SYSTEM_RUNTIME_LIBS_NO_WARNINGS TRUE)

if(MSVC)
  set(CMAKE_INSTALL_SYSTEM_RUNTIME_DESTINATION 
  #${CMAKE_INSTALL_BINDIR}/${CMAKE_BUILD_TYPE}
  )
endif()

if(DEBUG)
  set(CMAKE_INSTALL_DEBUG_LIBRARIES TRUE)
endif()
include(InstallRequiredSystemLibraries)


add_executable(rats 
    engine.c
    getopt.c
    hash.c
    kazhash.c
    lex.yyc.c
    lex.yyp.c
    lex.yyperl.c
    lex.yyphp.c
    lex.yyruby.c
    main.c
    report.c
    vuln_db.c
)


set(DATADIR "share/rats" CACHE STRING "Data directory")

target_compile_definitions(rats PRIVATE 
#  -DDATADIR=${DATADIR} 
  -DHAVE_EXPAT_H
  -DYY_NO_UNISTD_H
  )

target_link_libraries(rats PRIVATE EXPAT::EXPAT)

install(TARGETS rats DESTINATION bin)
install(FILES rats-c.xml rats-openssl.xml rats-perl.xml rats-python.xml rats-ruby.xml DESTINATION "${DATADIR}")
#install(FILES ${EXPAT_LIBRARIES} DESTINATION bin)
#[[
  ./mkinstalldirs /c/devroot/bin /c/devroot/lib /c/devroot/man /c/devroot/man/man1 /c/devroot/share
mkdir /c/devroot/man
mkdir /c/devroot/man/man1
/usr/bin/install -c rats /c/devroot/bin
/usr/bin/install -c -m 644 rats-python.xml /c/devroot/share
/usr/bin/install -c -m 644 rats-c.xml /c/devroot/share
/usr/bin/install -c -m 644 rats-perl.xml /c/devroot/share
/usr/bin/install -c -m 644 rats-php.xml /c/devroot/share
/usr/bin/install -c -m 644 rats-ruby.xml /c/devroot/share
/usr/bin/install -c -m 644 rats-openssl.xml /c/devroot/share
/usr/bin/install -c -m 644 rats.1       /c/devroot/man/man1
]]

include(cpack)