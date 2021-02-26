cmake_minimum_required(VERSION 3.15)

project(RATS)

find_package(EXPAT REQUIRED)

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


set(DATADIR "" CACHE STRING "Data directory")

target_compile_definitions(rats PRIVATE 
  -DDATADIR=${DATADIR} 
  -DHAVE_EXPAT_H
  -DYY_NO_UNISTD_H
  )

target_link_libraries(rats PRIVATE EXPAT::EXPAT)

install(TARGETS rats DESTINATION ${CMAKE_INSTALL_PREFIX}/bin)