dnl
dnl configure.ac - autoconf script for tegra-fuse-tool
dnl
dnl Copyright (c) 2019-2023, Matthew Madison
dnl

AC_INIT([tegra-fuse-tool], [1.2.0])
AC_DEFINE([FUSETOOL_VERSION_MAJOR], [1], [Major version])
AC_DEFINE([FUSETOOL_VERSION_MINOR], [2], [Minor version])
AC_DEFINE([FUSETOOL_VERSION_MAINT], [0], [Maintenance level])
AM_INIT_AUTOMAKE([subdir-objects foreign])
AM_SILENT_RULES([yes])
AC_COPYRIGHT([
Copyright (c) 2019-2023, Matthew Madison
])
AC_CONFIG_MACRO_DIR([m4])

AC_PREREQ([2.69])
LT_PREREQ([2.4])
LT_INIT([])

AC_CANONICAL_HOST
AC_PROG_INSTALL
AC_PROG_CC
AC_PROG_CC_C_O

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
