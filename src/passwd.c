#include "pamela.h"

int	change_pass(char *old, char *new, pam_handle_t *pamh)
{
  struct crypt_device	*cd;
  char			*container;
  char			*user;
  struct passwd		*passwd;

  if (get_userinfo(&user, &passwd, pamh) == 1 ||
      concat(&container, "/home/luks/", user) == 1)
    return (1);
  if (crypt_init(&cd, container) < 0)
    {
      free(container);
      perror("crypt_init failed");
      return (1);
    }
  if (crypt_keyslot_change_by_passphrase(cd, 0, 0, old, strlen(old),
					 new, strlen(new)) < 0)
    {
      free(container);
      crypt_free(cd);
      perror("crypt_keyslot_change_by_passphrase failed");
      return (1);
    }
  free(container);
  crypt_free(cd);
  return (0);
}

int	pam_sm_chauthtok(pam_handle_t *pamh, UNUSED int flags,
			 UNUSED int argc, UNUSED const char **argv)
{
  char	*old;
  char	*new;

  if (get_item(pamh, PAM_AUTHTOK, (const void **)&new) == 1)
    return (PAM_AUTHTOK_ERR);
  if (get_item(pamh, PAM_OLDAUTHTOK, (const void **)&old) == 1)
    return (PAM_AUTHTOK_RECOVERY_ERR);
  if (old == NULL || new == NULL)
    return (PAM_SUCCESS);
  if (change_pass(old, new, pamh) == 1)
    return (PAM_AUTHTOK_ERR);
  return (PAM_SUCCESS);
}
