bin_PROGRAMS = suid-script
nodist_suid_script_SOURCES = src/version_data.h

BUILT_SOURCES = src/version_data.h
DISTCLEANFILES = src/version_data.h

suid_script_SOURCES = src/suid-script.c

src/version_data.h: Makefile
	scripts/make-version

install-exec-hook:
	chown root:root $(DESTDIR)$(bindir)/suid-script
	chmod u+s $(DESTDIR)$(bindir)/suid-script

#threescalers_CFLAGS = $(THREESCALERS_CFLAGS)
#threescalers_LIBRARIES = $(THREESCALERS_LIBS)
