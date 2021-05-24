#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT(suid-script, 0.1.1, [alex@flawedcode.org], , [https://github.com/unleashed/suid-script])
AC_CONFIG_SRCDIR([src/suid-script.c])
AC_CONFIG_HEADERS([src/config.h])
AC_USE_SYSTEM_EXTENSIONS
AM_INIT_AUTOMAKE

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

AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT
