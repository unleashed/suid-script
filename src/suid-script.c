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

#define _GNU_SOURCE
#define _BSD_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <grp.h>

#if NGROUPS > 256
#define MYNGROUPS 256
#else
#define MYNGROUPS NGROUPS
#endif

struct my_creds {
	uid_t uid;      /* real uid: usuario original, solo lo cambia root */
	uid_t euid;     /* effective uid: usuario que cuenta para la mayoria de permisos */
	uid_t suid;     /* saved uid: usuario salvado anterior, permite recuperarlo como effective */
	uid_t fsuid;    /* filesystem uid: usuario para chequeos de fs, generalmente euid, solo lo cambia root */
	gid_t gid;      /* ditto para grupos */
	gid_t egid;
	gid_t sgid;
	uid_t fsgid;
	int ngids;
	gid_t gids[MYNGROUPS];  /* grupos adicionales: minimo de (NGROUPS, 256) */
};

char actualpath[PATH_MAX+1];    /* path sin symlinks al ejecutable */

int get_my_creds(struct my_creds *creds)
{
	int ret = -1;

	if (getresuid(&creds->uid, &creds->euid, &creds->suid) < 0 ||
	    getresgid(&creds->gid, &creds->egid, &creds->sgid) < 0)
	goto out;

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
	creds->fsuid = setfsuid(creds->euid);
	creds->fsgid = setfsgid(creds->egid);
	/* las restauramos */
	setfsuid(creds->fsuid);
	setfsgid(creds->fsgid);

	ret = getgroups(MYNGROUPS, creds->gids);
	creds->ngids = ret;

#ifdef MAIN_GID_NOT_IN_GIDS
	{
	unsigned int i;

	/* eliminar grupo principal, mas que nada por aburrimiento */
	for (i = 0; i < creds->ngids; i++) {
		if (creds->gids[i] == creds->egid) {
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

	fprintf(stderr, "uid = %d\t- euid = %d\t- suid = %d\t- fsuid = %d\n"
		"gid = %d\t- egid = %d\t- sgid = %d\t- fsgid = %d\n"
		"ngids = %d\ngids =", creds->uid, creds->euid, creds->suid, creds->fsuid,
		creds->gid, creds->egid, creds->sgid, creds->fsgid, creds->ngids);
	for (i = 0; i < creds->ngids; i++)
		fprintf(stderr, " %d", creds->gids[i]);

	fprintf(stderr, "\n");
}

int change_to_ug(const uid_t uid, const gid_t gid)
{
	int ret;

#ifdef VERBOSE
	printf("getting uid=%d gid=%d\n", uid, gid);
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
	printf("realpath: %s\n", actualpath);
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

int main(int argc, char *argv[], char *envp[])
{
	char **args;
#ifdef VERBOSE
	struct my_creds creds;
	int i;

	printf("INITIAL:\n");
	get_my_creds(&creds);
	print_my_creds(&creds);
#endif

	if (argc < 2) {
		fprintf(stderr, "usage: %s <suid_program> [params]\n", *argv);
		goto out;
	}

	if (itchy_bitchy_scratchy_perm_witch(argv[1]) < 0) {
		perror("perms");
		goto out;
	}

#ifdef VERBOSE
	printf("FINAL:\n");
	get_my_creds(&creds);
	print_my_creds(&creds);
#endif

	args = (char **) malloc(sizeof(char **) * (argc + 2));	/* we need space for a terminating NULL parameter */
	if (args == NULL) {
		fprintf(stderr, "Not enough memory\n");
		goto out;
	}

	args[0] = "/bin/bash";
	args[1] = "-";	/* disallow further options to sh (this is to allow you to name your script something like "-i" securely) */
	args[2] = actualpath;
	if (argc > 2)
		memcpy(&args[3], &argv[2], sizeof(char **) * (argc - 2));
	args[argc+1] = NULL;

#ifdef VERBOSE
	printf("COMMAND:");
	for (i = 0; i < argc+1; i++)
		printf(" %s", args[i]);
	printf("\n");
#endif
	execve(args[0], &args[0], envp);
	perror("execve");
	free(args);

out:
	/* Failed to run the script - See http://www.gnu.org/software/libc/manual/html_node/Exit-Status.html */
	return 128;
}
