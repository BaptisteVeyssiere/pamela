#include "pamela.h"

int				is_mounted(const char *container)
{
  struct crypt_device		*cd;
  struct crypt_params_luks1	params = {
    .hash = "sha256",
    .data_alignment = 0,
    .data_device = NULL
  };
  
  if (crypt_init(&cd, container) < 0)
    return (0);
  if (crypt_format(cd, CRYPT_LUKS1, "aes",
		   "xts-plain64", NULL, NULL, 32, &params) < 0)
    {
      crypt_free(cd);
      return (1);
    }
  crypt_free(cd);
  return (0);
}

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

int	get_item(pam_handle_t *pamh, int item, const void **dest)
{
  if (pam_get_item(pamh, item, dest) != PAM_SUCCESS ||
      *dest == NULL)
    return (1);
  return (0);
}
