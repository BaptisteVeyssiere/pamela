#include "pamela.h"

/*
** Used to check if username doesn't contain invalid characters
*/
int		is_user_invalid(const char *user)
{
  unsigned int	size = strlen(user);
  char		c;
  
  for (unsigned int i = 0; i < size; ++i)
    {
      c = user[i];
      if ((c < 'A' || (c > 'Z' && c < 'a') || c > 'z')
	  && c != '-' && c != '_' && (c < '0' || c > '9'))
	{
	  fprintf(stderr, "Invalid user name: only accept alphanumerical, underscore and dash characters\n");
	  return (1);
	}
    }
  return (0);
}

/*
** Used to get sha256 hash of the string data
*/
int		allocate_and_get_sha256(const char *data,
					unsigned char **digest)
{
  SHA256_CTX	context;
  
  if (data == NULL) {
    return (1);
  }
  if ((*digest = malloc(33)) == NULL) {
    perror("malloc");
    return (1);
  }
  SHA256_Init(&context);
  SHA256_Update(&context, data, strlen(data));
  SHA256_Final(*digest, &context);
  return (0);
}

/*
** Retrieve data about the user
*/
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

/*
** Concatenate 2 strings and allocate memory to store the result
*/
int		allocate_and_concat(char **dest, char *first, char *sec)
{
  size_t	length;
  
  length = strlen(first) + strlen(sec) + 1;
  if ((*dest = malloc(length)) == NULL)
    {
      perror("malloc");
      return (1);
    }
  if (sprintf(*dest, "%s%s", first, sec) < 0)
    {
      perror("sprintf");
      return (1);
    }
  return (0);
}

/*
** Get PAM item
*/
int	get_item(pam_handle_t *pamh, int item, const void **dest)
{
  if (pam_get_item(pamh, item, dest) != PAM_SUCCESS)
    {
      perror("pam_get_item");
      return (1);
    }
  if (*dest == NULL)
    {
      fprintf(stderr, "Invalid NULL pointer\n");
      return (1);
    }
  return (0);
}
