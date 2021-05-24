bin_PROGRAMS = suid-script
nodist_suid_script_SOURCES = src/version_data.h

BUILT_SOURCES = src/version_data.h
DISTCLEANFILES = src/version_data.h

suid_script_SOURCES = src/suid-script.c
suid_script_CFLAGS = $(THREESCALERS_CFLAGS)
suid_script_LDADD = $(THREESCALERS_LIBS)

src/version_data.h: Makefile
	scripts/make-version

install-exec-hook:
	$(MKDIR_P) $(DESTDIR)$(bindir)
	chown root:root $(DESTDIR)$(bindir)/suid-script
	chmod u+s $(DESTDIR)$(bindir)/suid-script
