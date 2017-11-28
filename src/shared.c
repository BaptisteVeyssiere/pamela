#include "pamela.h"

int	get_userinfo(char **user, struct passwd **passwd, pam_handle_t *pamh)
{
  if (pam_get_user(pamh, (const char **)user, NULL) != PAM_SUCCESS)
    {
      perror("pam_get_user");
      return (1);
    }
  if ((*passwd = getpwnam(*user)) == NULL || (*passwd)->pw_dir == NULL)
    {
      perror("getpwnam");
      return (1);
    }
  return (0);
}

int	concat(char **dest, char *first, char *sec)
{
  size_t		length;
  
  length = strlen(first) + strlen(sec) + 1;
  if ((*dest = malloc(length)) == NULL)
    {
      perror("malloc");
      return (1);
    }
  bzero(*dest, length);
  strcat(strcat(*dest, first), sec);
  return (0);
}

int	get_item(pam_handle_t *pamh, int item, const void **dest)
{
  if (pam_get_item(pamh, item, dest) != PAM_SUCCESS ||
      *dest == NULL)
    return (1);
  return (0);
}
