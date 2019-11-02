# Makefile for tegra-fuse-tool
#
# Copyright (c) 2019 Matthew Madison
#

AUTOMAKE_OPTIONS = subdir-objects foreign
ACLOCAL_AMFLAGS = -I m4
SUBDIRS =
DIST_SUBDIRS =

prefix = /usr
exec_prefix = /usr
datadir = $(prefix)/share
sbindir = $(exec_prefix)/sbin

tfincdir = $(includedir)/tegra-fuse

lib_LTLIBRARIES = libtegra-fuse.la
libtegra_fuse_la_SOURCES = tegra-fuse.c
libtegra_fuse_la_CPPFLAGS = -D_GNU_SOURCE
tfinc_HEADERS = tegra-fuse.h

bin_PROGRAMS = tegra-fuse-tool
tegra_fuse_tool_SOURCES = tegra-fuse-tool.c
tegra_fuse_tool_CPPFLAGS = -D_GNU_SOURCE
tegra_fuse_tool_LDADD = libtegra-fuse.la
