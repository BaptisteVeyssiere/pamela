#include "pamela.h"

static int		change_pass(char *old, char *new, pam_handle_t *pamh)
{
  struct crypt_device	*cd;
  char			*user;
  struct passwd		*passwd;

  /* get user informations and unmount partition */
  if (get_userinfo(&user, &passwd, pamh) == 1 ||
      umount_container(passwd) == 1)
    return (1);
  /* init cryptsetup context */
  if (crypt_init_by_name(&cd, user) < 0)
    {
      perror("crypt_init_by_name");
      return (1);
    }
  /* change access token to the container */
  if (crypt_keyslot_change_by_passphrase(cd, CRYPT_ANY_SLOT,
					 CRYPT_ANY_SLOT, old,
					 32, new, 32) < 0)
    {
      crypt_free(cd);
      perror("crypt_keyslot_change_by_passphrase");
      return (1);
    }
  crypt_free(cd);
  /* remount the container */
  if (mount_container(user, passwd) == 1)
    return (1);
  return (0);
}

/*
** Entry point
** This function is called when the user try to change his password
*/
PAM_EXTERN int	pam_sm_chauthtok(pam_handle_t *pamh, int flags,
			 UNUSED int argc, UNUSED const char **argv)
{
  char		*old;
  char		*new;
  unsigned char	*oldhash;
  unsigned char	*newhash;

  /* return if prelim call (before new password request) */
  if (flags & PAM_PRELIM_CHECK)
    return (PAM_IGNORE);
  /* change ruid to allow luks manipulation */
  if (setuid(0) == -1)
    {
      perror("setuid");
      return (1);
    }
  /* get old password */
  if (get_item(pamh, PAM_OLDAUTHTOK, (const void **)&old) == 1)
    return (PAM_AUTHTOK_RECOVERY_ERR);
  /* get new password */
  if (get_item(pamh, PAM_AUTHTOK, (const void **)&new) == 1)
    return (PAM_AUTHTOK_ERR);
  if (old == NULL || new == NULL)
    return (PAM_SUCCESS);
  /* create hashs of the passwords and change access token to the container */
  if (allocate_and_get_sha256(old, &oldhash) == 1 ||
      allocate_and_get_sha256(new, &newhash) == 1 ||
      change_pass((char*)oldhash, (char*)newhash, pamh) == 1)
    return (PAM_AUTHTOK_ERR);
  return (PAM_SUCCESS);
}
