#include <libcryptsetup.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <pwd.h>
#include <strings.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <security/pam_modules.h>

#ifndef UNUSED
# define UNUSED __attribute__((unused))
#endif

static int	get_userinfo(char **user, struct passwd **passwd)
{
  if ((*user = getlogin()) == NULL)
    {
      perror("getlogin() failed");
      return (1);
    }
  if ((*passwd = getpwnam(*user)) == NULL || (*passwd)->pw_dir == NULL)
    {
      perror("getpwnam failed");
      return (1);
    }
  return (0);
}

static int	cryptsetup(char *user, char *container)
{
  struct crypt_device	*cd;

  if (crypt_init(&cd, container) < 0)
    {
      perror("crypt_init failed");
      return (1);
    }
  if (crypt_load(cd, CRYPT_LUKS1, NULL) < 0)
    {
      perror("crypt_load failed");
      crypt_free(cd);
      return (1);
    }
  if (crypt_activate_by_passphrase(cd, user, CRYPT_ANY_SLOT, "", 0,
				   CRYPT_ACTIVATE_IGNORE_ZERO_BLOCKS) < 0)
    {
      perror("crypt_activate_by_passphrase failed");
      return (1);
    }
  crypt_free(cd);
  return (0);
}

static int	secure_mount(char *source, char *target, struct passwd *passwd)
{
  if (mkdir(target, 0600) == -1)
    {
      perror("mkdir failed");
      return (1);
    }
  if (mount(source, target, "ext3", 0, NULL) == -1)
    {
      perror("mount failed");
      return (1);
    }
  if (chown(target, passwd->pw_uid, passwd->pw_gid) == -1)
    {
      perror("chown failed");
      return (1);
    }
  if (chmod(target, S_IRUSR | S_IWUSR | S_IXUSR) == -1)
    {
      perror("chmod failed");
      return (1);
    }
  return (0);
}

static int	mount_container(char *user, struct passwd *passwd)
{
  char			*source;
  char			*target;
  size_t		length;

  length = strlen("/dev/mapper/") + strlen(user) + 1;
  if ((source = malloc(length)) == NULL)
    {
      perror("malloc failed");
      return (1);
    }
  bzero(source, length);
  strcat(strcat(source, "/dev/mapper/"), user);
  length = strlen(passwd->pw_dir) + strlen("/secure_data-rw") + 1;
  if ((target = malloc(length)) == NULL)
    {
      free(source);
      perror("malloc failed");
      return (1);
    }
  bzero(target, length);
  strcat(strcat(target, passwd->pw_dir), "/secure_data-rw");
  if (secure_mount(source, target, passwd) == 1)
    {
      free(source);
      free(target);
      return (1);
    }
  return (0);
}

PAM_EXTERN int	pam_sm_open_session(UNUSED pam_handle_t *pamh,
				    UNUSED int flags, UNUSED int argc,
				    UNUSED const char **argv)
{
  char			*user;
  char			*container;
  struct passwd		*passwd;
  size_t		length;

  if (get_userinfo(&user, &passwd) == 1)
    return (PAM_SESSION_ERR);
  length = strlen("/home/luks/") + strlen(user) + 1;
  if ((container = malloc(length)) == NULL)
    {
      perror("malloc failed");
      return (PAM_SESSION_ERR);
    }
  bzero(container, length);
  strcat(strcat(container, "/home/luks/"), user);
  if (cryptsetup(user, container) == 1 ||
      mount_container(user, passwd) == 1)
    {
      free(container);
      return (PAM_SESSION_ERR);
    }
  return (PAM_SUCCESS);
}
