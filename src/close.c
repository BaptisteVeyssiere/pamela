#include "pamela.h"

int	umount_container(struct passwd *passwd)
{
  char	*target;

  if (allocate_and_concat(&target, passwd->pw_dir, "/secure_data-rw") == 1)
    return (1);
  /* unmount the partition */
  if (umount(target) == -1)
    {
      free(target);
      perror("umount");
      return (1);
    }
  /* delete mounting point */
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

  /* init cryptsetup context to manipulate luks data */
  if (crypt_init_by_name(&cd, user) < 0)
    {
      perror("crypt_init_by_name");
      return (1);
    }
  /* close container */
  if (crypt_deactivate(cd, user) < 0)
    {
      crypt_free(cd);
      perror("crypt_deactivate");
      return (1);
    }
  crypt_free(cd);
  return (0);
}

/*
** Entry point
** This function is called when the user log off
*/
PAM_EXTERN int	pam_sm_close_session(pam_handle_t *pamh,
				     UNUSED int flags, UNUSED int argc,
				     UNUSED const char **argv)
{
  char		*user;
  struct passwd	*passwd;

  /* retrieve user infos, unmount the container and close it */
  if (get_userinfo(&user, &passwd, pamh) == 1 ||
      umount_container(passwd) == 1 ||
      cryptunsetup(user) == 1)
    return (PAM_SESSION_ERR);
  return (PAM_SUCCESS);
}
