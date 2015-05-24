# Victor J. Roemer <vroemer@badsec.org>
#
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT([u2json], [1], [victor@badsec.org])
AC_CONFIG_SRCDIR([src/unified2json.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([-Wall -Werror foreign color-tests parallel-tests])

#
# Checks for programs.
#
AC_PROG_CC
AC_PROG_CC_C99
AC_PROG_INSTALL

AC_ARG_WITH([libjansson],AS_HELP_STRING([--with-libjansson=PATH],[Specify prefix directory for the installed libjansson.]))
AC_CHECK_LIB([jansson],[json_pack],,AC_MSG_ERROR([
    Error! libjansson library/headers not found.
    Get it from github.com/FIXME OR use the --with-libjansson option if its installed in an unusual place.]))

AC_ARG_WITH([libunified2],AS_HELP_STRING([--with-libunified2=PATH],[Specify prefix directory for the installed libunified2.]))
AC_CHECK_LIB([unified2],[Unified2New],,AC_MSG_ERROR([
    Error! libunified2 library/headers not found.
    Get it from github.com/wtfbbqhax/libunified2 use the --with-libunified2 option if its installed in an unusual place.]))

#AC_ARG_WITH([libpacket],AS_HELP_STRING([--with-libpacket=PATH],[Specify prefix directory for the installed libpacket.]))
#AC_CHECK_LIB([packet],[packet_decode],,AC_MSG_ERROR([
#    Error! libpacket library/headers not found.
#    Get it from github.com/wtfbbqhax/libpacket OR use the --with-libpacket option if its installed in an unusual place.])) 

#AC_CHECK_LIB([check], [srunner_create])
#AM_CONDITIONAL([HAVE_LIB_CHECK],
#    test "x$ac_cv_check_srunner_create" == "xyes")

AC_DEFINE([JANSSON_FLAGS], [0], [Flags for json_dumpf()])
#
# Checks for header files.
#
AC_HEADER_STDC

#AC_CHECK_HEADERS([check.h])
#AM_CONDITIONAL([HAVE_LIB_CHECK], [test "x$ac_cv_header_check_h" == "xyes"])

#
# Checks for typedefs, structures, and compiler characteristics.
#
AC_C_INLINE
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T

AC_CONFIG_FILES([Makefile src/Makefile])

AC_OUTPUT
