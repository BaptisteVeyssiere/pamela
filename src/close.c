#include <libcryptsetup.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <stdio.h>
#include <security/pam_modules.h>

static int	get_userinfo(char **user, struct passwd **passwd)
{
  if ((*user = getlogin()) == NULL)
    {
      perror("getlogin failed\n");
      return (1);
    }
  if ((*passwd = getpwnam(*user)) == NULL || (*passwd)->pw_dir == NULL)
    {
      perror("getpwnam failed\n");
      return (1);
    }
  return (0);
}

static int	umount_container(char *user, struct passwd *passwd)
{
  char		*target;
  size_t	length;

  length = strlen(passwd->pw_dir) + strlen("/secure_data_rw") + 1;
  if ((target = malloc(length)) == NULL)
    {
      perror("malloc failed\n");
      return (1);
    }
  bzero(target, length);
  strcat(strcat(target, passwd->pw_dir), "/secure_data_rw");
  if (umount(target) == -1)
    {
      free(target);
      perror("umount failed\n");
      return (1);
    }
  free(target);
  return (0);
}

static int	cryptunsetup(char *user)
{
  struct crypt_device	*cd;
  
  if (crypt_init_by_name(&cd, user) < 0)
    {
      perror("crypt_init_by_name failed\n");
      return (1);
    }
  if (crypt_deactivate(cd, user) < 0)
    {
      perror("crypt_deactivated\n");
      return (1);
    }
  crypt_free(cd);
  return (0);
}

int	pam_sm_close_session(int argc, char **argv)
{
  char		*user;
  struct passwd	*passwd;
  
  if (get_userinfo(&user, &passwd) == 1 ||
      umount_container(user, passwd) == 1 ||
      cryptunsetup(user) == 1)
    return (PAM_SESSION_ERR);
  return (PAM_SUCCESS);
}
