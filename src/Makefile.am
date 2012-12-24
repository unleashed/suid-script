bin_PROGRAMS = suid-script
nodist_suid_script_SOURCES = version_data.h

BUILT_SOURCES = version_data.h
DISTCLEANFILES = version_data.h

suid_script_SOURCES = suid-script.c

version_data.h: Makefile
	../scripts/make-version

install-exec-hook:
	chown root:root $(DESTDIR)$(bindir)/suid-script
	chmod u+s $(DESTDIR)$(bindir)/suid-script
