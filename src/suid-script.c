/*
 * setuid shell script wrapper - Copyright (c) 2008, 2012 Alejandro Martinez Ruiz <alex@flawedcode.org>
 *
 * Licensed under the terms of the GNU General Public License version 3 or, at your option,
 * any later version.  Visit http://www.fsf.org for details.
 *
 * About security concerns: http://www.faqs.org/faqs/unix-faq/faq/part4/section-7.html
 * This program is immune to the problems described there. The executed shell script is responsible for
 * setting up and/or cleaning up its own environment for security purposes.
 *
 * Los shell scripts usan la uid REAL para ejecutar cualquier programa externo. No solo es que la usen,
 * sino que SOBRESCRIBEN con ella TODAS las demas (efectiva, salvada, fsuid). Ditto para grupos.
 *
 * root u+s script ejecutado por uid 100 => programas invocados en script, con todas uids 100.
 * user u+s script ejecutado por uid 100 => programas invocados en script, con todas uids 100.
 *
 * [ojo, en realidad los comandos internos del shell y redirecciones si funcionan como setuid.
 *  es decir, echo hola > fichero_privilegiado funciona, pero no rm fichero_privilegiado ]
 *
 * En la practica esto significa que para poder ejecutar un shell script setuid a un usuario diferente
 * al nuestro, hay que cambiar nuestra uid real a ella.
 *
 * Para cambiar nuestra uid real, hay que hacerlo con permisos de root. Eso significa que la unica
 * forma de hacer que un shell script se ejecute como si fuera setuid-alguien, es haciendo este
 * programa setuid-root, que cambie su uid/gid real a la del script destino, y exec().
 *
 * Alternativamente, en Linux, la uid real la puede cambiar tambien un usuario sin privilegios,
 * PERO SOLO a su uid efectiva. Eso significa que se puede hacer el programa setuid ese usuario
 * si solo lo vamos a usar para programas de un uid especifico.
 *
 * Para pasar de user X a user Y, no necesitamos pasar primero por setuid(root), pero si tenerlo
 * como uid efectiva (solo root puede cambiar la uid real o, en linux, cualquiera puede cambiarla
 * tambien a su uid efectiva-).
 *
 * Politica de ejecucion:
 *
 *	- Los enlaces se desreferencian antes de nada.
 *	- Programas world-writable/group-writable solo se ejecutan con la uid real original (el user invocador).
 *	- Cualquier otro programa no setuid se ejecuta con la uid real original.
 *	- Programas setuid/setgid se ejecutan como el user/grupo del fichero(*)
 *
 * (*) al cambiar la uid real en lugar de la efectiva por requerimiento de los shell scripts, se pierde
 *     la uid salvada. Eso significa que el programa en cuestion NO tendra los permisos del usuario que
 *     invoca el wrapper.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "version_data.h"

#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRINGS_H
#include <string.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif
#ifdef HAVE_GRP_H
#include <grp.h>
#endif

#ifdef HAVE_SYS_FSUID_H
#include <sys/fsuid.h>
#endif

#if NGROUPS > 256
#define MYNGROUPS 256
#else
#define MYNGROUPS NGROUPS
#endif

#ifdef HAVE_THREESCALERS_THREESCALERS_H
#include <threescalers/threescalers.h>
#endif

struct my_creds {
	uid_t uid;      /* real uid: usuario original, solo lo cambia root */
	uid_t euid;     /* effective uid: usuario que cuenta para la mayoria de permisos */
	uid_t suid;     /* saved uid: usuario salvado anterior, permite recuperarlo como effective */
#ifdef HAVE_SETFSUID
	uid_t fsuid;    /* filesystem uid: usuario para chequeos de fs, generalmente euid, solo lo cambia root */
#endif
	gid_t gid;      /* ditto para grupos */
	gid_t egid;
	gid_t sgid;
#ifdef HAVE_SETFSUID
	uid_t fsgid;
#endif
	int ngids;
	GETGROUPS_T gids[MYNGROUPS];  /* grupos adicionales: minimo de (NGROUPS, 256) */
};

char actualpath[PATH_MAX+1];    /* path sin symlinks al ejecutable */

int get_my_creds(struct my_creds *creds)
{
	int ret = -1;

#ifdef HAVE_GETRESUID
	if (getresuid(&creds->uid, &creds->euid, &creds->suid) < 0)
	       goto out;
#else
	{
	uid_t uid;

	uid = getuid();
	if (uid < 0) {
		goto out;
	}
	creds->uid = uid;

	uid = geteuid();
	if (uid < 0) {
		goto out;
	}
	creds->euid = uid;
	// cannot access saved-user-id in these cases
	creds->suid = -1;
	}
#endif
#ifdef HAVE_GETRESGID
	if (getresgid(&creds->gid, &creds->egid, &creds->sgid) < 0)
		goto out;
#else
	{
	gid_t gid;

	gid = getgid();
	if (gid < 0) {
		goto out;
	}
	creds->gid = gid;

	gid = getegid();
	if (gid < 0) {
		goto out;
	}
	creds->egid = gid;
	// cannot access saved-user-id in these cases
	creds->sgid = -1;
	}
#endif

	/*
	 * La forma de conseguir las fsuids es seteandolas
	 *
	 * Solo el super usuario puede setearlas a algo arbitrario, asi que:
	 *
	 *      - si lo somos, no pasa nada, las llamadas funcionaran, nos daran las ids, y las restauraremos.
	 *      - si no lo somos, no pasa nada, las llamadas funcionaran, nos daran las ids, y las restauraremos.(*)
	 *
	 * Notese que un usuario solo puede cambiar los valores a las uids/gids reales, efectivas o salvadas.
	 * Eso significa que si ha habiado un cambio a un usuario en euid, se ha cambiado tambien la fsuid y
	 * esta solo puede variar mientras sea a ruid, euid, o saved-uid. De la misma forma la restauramos.
	 *
	 * (*) Es decir, un usuario solo puede mover fsuid entre ruid, euid y saved-uid, con lo que el codigo que
	 *     sigue siempre va a funcionar (porque no puede haber en fsuid otra cosa que uno de esos 3 valores
	 *     para quien no sea root).
	 */
#ifdef HAVE_SETFSUID
	creds->fsuid = setfsuid(creds->euid);
	/* la restauramos */
	setfsuid(creds->fsuid);
#endif
#ifdef HAVE_SETFSGID
	creds->fsgid = setfsgid(creds->egid);
	/* la restauramos */
	setfsgid(creds->fsgid);
#endif

	ret = getgroups(MYNGROUPS, creds->gids);
	creds->ngids = ret;

#ifdef MAIN_GID_NOT_IN_GIDS
	{
	unsigned int i;

	/* eliminar grupo principal, mas que nada por aburrimiento */
	for (i = 0; i < creds->ngids; i++) {
		if (creds->gids[i] == (GETGROUPS_T) creds->egid) {
			creds->gids[i] = creds->gids[--creds->ngids];
			break;
		}
	}
	}
#endif

	out:
		return ret;
}

void print_my_creds(const struct my_creds *creds)
{
	unsigned int i;

	fprintf(stderr, "uid = %d\t- euid = %d\t- suid = %d\t- "
#ifdef HAVE_SETFSUID
			"fsuid = %d\n"
#endif
		"gid = %d\t- egid = %d\t- sgid = %d\t- "
#ifdef HAVE_SETFSUID
		"fsgid = %d\n"
#endif
		"ngids = %d\ngids =", creds->uid, creds->euid, creds->suid,
#ifdef HAVE_SETFSUID
		creds->fsuid,
#endif
		creds->gid, creds->egid, creds->sgid,
#ifdef HAVE_SETFSUID
		creds->fsgid,
#endif
		creds->ngids);
	for (i = 0; i < creds->ngids; i++)
		fprintf(stderr, " %d", creds->gids[i]);

	fprintf(stderr, "\n");
}

int change_to_ug(const uid_t uid, const gid_t gid)
{
	int ret;

#ifdef VERBOSE
	fprintf(stderr, "getting uid=%d gid=%d\n", uid, gid);
#endif

	/* we must set first the gid, as changing uid first would mean setgid could fail on us */

	/* maybe use setreu/gid() */
	ret = setgid(gid);

	if (ret >= 0 && getgid() != gid) {
		/* we had a saved set-group-id of 0, it takes a 2nd call to get real gid */
		setgid(gid);
	}

	ret = setuid(uid);

	/*
	 * now we try to make uid the real user id (SAME as above with groups):
	 *
	 * this only makes sense for super user (who knows the numeric uid anyway?) as he's the only one who can set
	 * a real user id. So the previous setuid() could just set the effective uid IF euid was not root and saved-user-id
	 * WAS. In this case real user id is still some poor user, so a second call to setuid() will change the real user
	 * id to root
	 *
	 * Note that we're doing this for anyone just to avoid caring about knowing if this joe is a super user.
	 */
	if (ret >= 0 && getuid() != uid) {
		/* we had a saved set-user-id of 0, it takes a 2nd call to get real uid */
		ret = setuid(uid);
	}

	return ret;
}

int do_stat(const char *path, struct stat *sb)
{
	/*
	 * Acerca de races:
	 *
	 * No nos importan. Tenemos un path _CASI_ sin symlinks (hay una mini race), y de ahi tomamos las credenciales.
	 *
	 * No se ejecutan programas con go+w o sin setuid o setgid sin privilegios, asi que las carreras son:
	 *
	 * 1. Contra alguien que pueda escribir en esos ficheros antes del exec (o sea, el owner).
	 * 2. Contra alguien que pueda borrar un componente del path y redirigirlo (un usuario que tenga permisos ahi)
	 *
	 * En 1, si quien puede escribir ya es el owner, nosotros no le vamos a dar ningun privilegio mas, ya que primero
	 * nos convertiremos en el owner _si_ es un setuid (y si no en el mismo usuario que nos invoca).
	 *
	 * En 2, no se deben poner setuids a usuarios diferentes de los owners del path completo si no se confia en ellos.
	 * En particular, no solo owners, sino cualesquiera que puedan modificar/borrar componentes del path.
	 *
	 * Todo esto NO se puede arreglar de manera atomica. No nos dan la opcion, algo como un execfd() o fexec() a la fstat().
	 * (aunque cabe pensar en que fstat() tiene el problema de que hay que hacer un open con permisos adecuados..., alguien
	 * deberia arreglar eso para no requerirlo).
	 *
	 * Basicamente, si se da cualquiera de estas circunstancias, el problema de seguridad esta en otro lugar, no en este
	 * wrapper, asi que poco podemos hacer.
	 */
	if (realpath(path, actualpath) == NULL)
		return -1;
#ifdef VERBOSE
	fprintf(stderr, "realpath: %s\n", actualpath);
#endif
	return stat(actualpath, sb);
}

int itchy_bitchy_scratchy_perm_witch(const char *path)
{
	struct my_creds creds;
	struct stat st;
	uid_t uid;
	gid_t gid;
	int need_change_uid = 0, need_change_gid = 0;

	get_my_creds(&creds);

	if (do_stat(path, &st) < 0)
		return -1;

	if (st.st_mode & (S_IWOTH | S_IWGRP)) {
		/* world-writable or group-writable, drop all privileges */
		uid = creds.uid;
		gid = creds.gid;

		goto out;
	}

	if (st.st_mode & S_ISUID && st.st_uid != creds.uid) {
		need_change_uid = 1;
	}

	if (st.st_mode & S_ISGID && st.st_gid != creds.gid) {
		need_change_gid = 1;
	}

	gid = (need_change_gid) ? st.st_gid : creds.gid;
	uid = (need_change_uid) ? st.st_uid : creds.uid;

out:
	change_to_ug(uid, gid);

	return 0;
}

void print_creds()
{
	struct my_creds creds;

	get_my_creds(&creds);
	print_my_creds(&creds);
}

int main(int argc, char *argv[], char *envp[])
{
	char **args;
#ifdef VERBOSE
	/* used to enumerate command arguments */
	int i;
#endif

#ifdef HAVE_THREESCALERS
	const FFICow *fc = encoding_encode_s("ho?tia");
	if (fc->tag == Borrowed) {
		printf("borrowed!\n");
		printf("str: %s\n", fc->borrowed);
	} else {
		printf("owned\n");
		printf("own: %12s\n", fc->owned.ptr);
	}

	fficow_free(fc);
#endif

	if (argc < 2) {
		fprintf(stderr, "%s %s (%s)\n%s\n\nusage: %s <suid_program> [params]\n\n"
				"Please ensure <suid_program> is a non-world, non-group writable setuid script.\n",
				PACKAGE_NAME, VERSION_STRING, BUILD_DATE, PACKAGE_URL, *argv);
#ifdef VERBOSE
		fprintf(stderr, "\nLaunch creds:\n");
		print_creds();
#endif

		goto out;
	}

#ifdef VERBOSE
	fprintf(stderr, "Launch creds:\n");
	print_creds();
#endif

	if (itchy_bitchy_scratchy_perm_witch(argv[1]) < 0) {
		perror("perms");
		goto out;
	}

#ifdef VERBOSE
	fprintf(stderr, "Script creds:\n");
	print_creds();
#endif

	args = (char **) malloc(sizeof(char **) * (argc + 2));	/* we need space for a terminating NULL parameter */
	if (args == NULL) {
		fprintf(stderr, "Not enough memory\n");
		goto out;
	}

	args[0] = "/bin/sh";
	args[1] = "-";	/* disallow further options to sh (this is to allow you to name your script something like "-i" securely) */
	args[2] = actualpath;
	if (argc > 2)
		memcpy(&args[3], &argv[2], sizeof(char **) * (argc - 2));
	args[argc+1] = NULL;

#ifdef VERBOSE
	fprintf(stderr, "COMMAND:");
	for (i = 0; i < argc+1; i++)
		fprintf(stderr, " %s", args[i]);
	fprintf(stderr, "\n");
#endif
	execve(args[0], &args[0], envp);
	perror("execve");
	free(args);

out:
	/* Failed to run the script - See http://www.gnu.org/software/libc/manual/html_node/Exit-Status.html */
	return 128;
}
