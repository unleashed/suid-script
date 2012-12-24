#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

PACKAGE=suid-script
VERSION=0.1.0

AC_PREREQ([2.64])

AC_INIT([suid-script], [0.1.0], [unledev@gmail.com])
AC_CONFIG_SRCDIR([src/suid-script.c])

AM_INIT_AUTOMAKE($PACKAGE, $VERSION)

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h limits.h stdlib.h string.h sys/param.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UID_T

# Checks for library functions.
AC_FUNC_GETGROUPS
AC_FUNC_MALLOC
AC_CHECK_FUNCS([realpath])

AC_OUTPUT(Makefile src/Makefile)
