#include "pamela.h"

static int	umount_container(struct passwd *passwd)
{
  char		*target;

  if (allocate_and_concat(&target, passwd->pw_dir, "/secure_data-rw") == 1)
    return (1);
  if (umount(target) == -1)
    {
      free(target);
      perror("umount");
      return (1);
    }
  if (rmdir(target) == -1)
    {
      free(target);
      perror("rmdir");
      return (1);
    }
  free(target);
  return (0);
}

static int		cryptunsetup(char *user)
{
  struct crypt_device	*cd;
  
  if (crypt_init_by_name(&cd, user) < 0)
    {
      perror("crypt_init_by_name");
      return (1);
    }
  if (crypt_deactivate(cd, user) < 0)
    {
      perror("crypt_deactivated");
      return (1);
    }
  crypt_free(cd);
  return (0);
}

PAM_EXTERN int	pam_sm_close_session(pam_handle_t *pamh,
				     UNUSED int flags, UNUSED int argc,
				     UNUSED const char **argv)
{
  char		*user;
  struct passwd	*passwd;

  if (get_userinfo(&user, &passwd, pamh) == 1 ||
      umount_container(passwd) == 1 ||
      cryptunsetup(user) == 1)
    return (PAM_SESSION_ERR);
  return (PAM_SUCCESS);
}
