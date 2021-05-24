#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT(suid-script, 0.1.1, [alex@flawedcode.org], , [https://github.com/unleashed/suid-script])
AC_CONFIG_SRCDIR([src/suid-script.c])
AC_CONFIG_HEADERS([src/config.h])
AM_INIT_AUTOMAKE([foreign subdir-objects dist-xz])
AM_MAINTAINER_MODE([enable])

AC_USE_SYSTEM_EXTENSIONS
# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h grp.h limits.h errno.h stdio.h stdlib.h string.h sys/fsuid.h sys/param.h sys/stat.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UID_T

# Checks for library functions.
AC_FUNC_GETGROUPS
AC_FUNC_MALLOC
AC_FUNC_STAT
AC_CHECK_FUNCS([realpath execve getuid geteuid getgid getegid setuid setgid setfsuid setfsgid getresuid getresgid])

AC_ARG_ENABLE([verbose], AS_HELP_STRING([--enable-verbose], [Enable extra information dumped to stderr]), [
	       AC_DEFINE([VERBOSE], [1], [Define if you want verbose information dumped to stderr])
	       ], [], [enable_verbose=no])

AC_ARG_WITH([3scale], AS_HELP_STRING([--with-3scale], [Build with 3scalers support]), [], [with_3scale=check])

AS_IF([test "x$with_3scale" != "xno"], [
   PKG_PROG_PKG_CONFIG([0.24])
   PKG_CHECK_MODULES([THREESCALERS], [threescalers],
		     AC_DEFINE([HAVE_THREESCALERS], [1], [Define if you have the threescalers library])
		     AC_CHECK_HEADERS([threescalers/threescalers.h])
		     AC_CHECK_FUNCS([encoding_encode_s])
	     )
#	AC_CHECK_LIB([threescalers], [encoding_encode_s], [
#		      AC_SUBST([THREESCALERS], ["-lthreescalers"])
#		      AC_DEFINE([HAVE_THREESCALERS], [1], [Define if you have threescalers])
#		      ],
#		      [if test "x$with_3scale" != "xcheck"; then
#		       		AC_MSG_FAILURE(
#					       [--with-3scale was given, but test for threescalers failed])
#			fi
#			], -lthreescalers)
#])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
