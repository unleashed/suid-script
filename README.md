# suid-script

This package provides a tool to allow shell scripts to run honoring setuid
modes.

This allows a non-privileged user to run those scripts just as she would run
any other setuid binary. In order for this to happen securely you have to
install the setuid script without world nor group writable permissions and
enable the setuid and/or setgid permissions.

`suid-script` will run the shell script using the uid and gid of the user
owner and group owner if their respective setuid/setgid bits are enabled and
the script has no world or group writable permissions.

## Requirements

* A Unix-like OS.
* A shell script at /bin/sh

## Build & Install

This requires the GNU Autotools to build.

```
$ ./autogen.sh
$ ./configure && make && make install
```

## Shell script

The shebang line of shell scripts will NOT be respected. Instead, this
program will run `/bin/sh - <your_script>`. You can however easily work around
this limitation by adding code to the script in which you test whether the
right shell is being used, and exec() again via the right one if not.

## FAQ

Q: Why?
A: Because it's been useful to me a couple times.

Q: Is this secure?
A: Likely not.

Q: Couldn't this use capabilities?
A: Patches welcome!

Q: Does it work on <Unix-like OS>?
A: It has been tested to work on Linux, FreeBSD and NetBSD.

Q: Is there a Debian/Ubuntu package?
A: There is a contrib package under `debian` that might or might not work. At
some point this was actually shipping, but nowadays it is untested.

Q: It does not work.
A: That's not a question. But check to see that `suid-script` is installed with
setuid root and that the script also has, at least, setuid <user>, and that it
is not world or group writable.

Q: Why does the script break?
A: Either it requires a different shell than the system's `/bin/sh` and you
need to detect that it is running under not-the-right-shell and exec() itself
via the right one, or the different user/group under which it runs changes its
semantics.

Q: Is this being actively developed?
A: No, this is just a hack to get one job done - but: patches welcome!
