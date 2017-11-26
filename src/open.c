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
      perror("getlogin() failed\n");
      return (1);
    }
  if ((*passwd = getpwnam(*user)) == NULL || (*passwd)->pw_dir == NULL)
    {
      perror("getpwnam failed\n");
      return (1);
    }
  return (0);
}

static int	cryptsetup(char *user)
{
  struct crypt_device	*cd;

  if (crypt_init(&cd, user) < 0)
    {
      perror("crypt_init failed\n");
      return (1);
    }
  if (crypt_load(cd, CRYPT_LUKS1, NULL) < 0)
    {
      perror("crypt_load failed\n");
      crypt_free(cd);
      return (1);
    }
  if (crypt_activate_by_passphrase(cd, user, CRYPT_ANY_SLOT, "", 0,
				   CRYPT_ACTIVATE_IGNORE_ZERO_BLOCKS) < 0)
    {
      perror("crypt_activate_by_passphrase failed\n");
      return (1);
    }
  crypt_free(cd);
  return (0);
}

static int	secure_mount(char *source, char *target, struct passwd *passwd)
{
  if (mount(source, target, "ext3", 0, NULL) == -1)
    {
      free(source);
      free(target);
      perror("mount failed\n");
      return (1);
    }
  if (chown(target, passwd->pw_uid, passwd->pw_gid) == -1)
    {
      free(source);
      free(target);
      perror("chown failed\n");
      return (1);
    }
  if (chmod(target, S_IRUSR | S_IWUSR) == -1)
    {
      free(source);
      free(target);
      perror("chmod failed\n");
      return (1);
    }
  free(source);
  free(target);
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
      perror("malloc failed\n");
      return (1);
    }
  bzero(source, length);
  strcat(strcat(source, "/dev/mapper/"), user);
  length = strlen(passwd->pw_dir) + strlen("/secure_data_rw") + 1;
  if ((target = malloc(length)) == NULL)
    {
      free(source);
      perror("malloc failed\n");
      return (1);
    }
  bzero(target, length);
  strcat(strcat(target, passwd->pw_dir), "secure_data_rw");
  if (secure_mount(source, target, passwd) == 1)
    return (1);
  return (0);
}

PAM_EXTERN int	pam_sm_open_session(UNUSED pam_handle_t *pamh,
				    UNUSED int flags, UNUSED int argc,
				    UNUSED const char **argv)
{
  char			*user;
  struct passwd		*passwd;

  if (get_userinfo(&user, &passwd) == 1 ||
      cryptsetup(user) == 1 ||
      mount_container(user, passwd) == 1)
    return (PAM_SESSION_ERR);
  return (PAM_SUCCESS);
}
