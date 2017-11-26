#include "pamela.h"

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
  if (chmod(target, S_IRUSR | S_IWUSR) == -1)
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

  if (concat(&source, "/dev/mapper/", user) == 1)
    return (1);
  if (concat(&target, passwd->pw_dir, "/secure_data-rw") == 1)
    {
      free(source);
      return (1);
    }
  if (secure_mount(source, target, passwd) == 1)
    {
      free(source);
      free(target);
      return (1);
    }
  return (0);
}

static int	cryptsetup(char *user, char *container, int new,
			   pam_handle_t *pamh)
{
  struct crypt_device		*cd;
  char				*command;
  struct crypt_params_luks1	params = {
    .hash = "sha1",
    .data_alignment = 0,
    .data_device = NULL
  };
  char				*password;

  if (get_item(pamh, PAM_AUTHTOK, (const void **)&password) == 1)
    return (1);
  if (crypt_init(&cd, container) < 0)
    {
      perror("crypt_init failed");
      return (1);
    }
  if (new == 1 && crypt_format(cd, CRYPT_LUKS1, "aes", "xts-plain64", NULL, NULL, 32, &params) < 0)
    {
      crypt_free(cd);
      perror("crypt_format failed");
      return (1);
    }
  if (crypt_keyslot_add_by_volume_key(cd, CRYPT_ANY_SLOT, NULL, 0,
				      password, strlen(password)) < 0)
    {
      crypt_free(cd);
      perror("crypt_keyslot_add_by_volume_key failed");
      return (1);
    }
  if (crypt_load(cd, CRYPT_LUKS1, NULL) < 0)
    {
      perror("crypt_load failed");
      crypt_free(cd);
      return (1);
    }
  if (crypt_activate_by_passphrase(cd, user, CRYPT_ANY_SLOT, password,
				   strlen(password),
				   CRYPT_ACTIVATE_IGNORE_ZERO_BLOCKS) < 0)
    {
      perror("crypt_activate_by_passphrase failed");
      return (1);
    }
  if (new == 1 && (concat(&command, "/sbin/mkfs.ext3 /dev/mapper/", user) == 1
		   || system(command) < 0))
    return (1);
  crypt_free(cd);
  return (0);
}

static int	check_or_create(char *container, char *user,
				pam_handle_t *pamh, struct passwd *passwd)
{
  char	*command;
  
  if (access(container, F_OK) != -1)
    return (cryptsetup(user, container, 0, pamh));
  if (concat(&command, "dd if=/dev/urandom bs=10M count=1 of=", container) == 1
      || system(command) < 0)
    return (1);
  if (chown(container, passwd->pw_uid, passwd->pw_gid) == -1)
    {
      perror("chown failed");
      return (1);
    }
  if (chmod(container, S_IRUSR | S_IWUSR) == -1)
    {
      perror("chmod failed");
      return (1);
    }
  if (cryptsetup(user, container, 1, pamh) == 1)
    return (1);
  return (0);
}

PAM_EXTERN int	pam_sm_open_session(pam_handle_t *pamh, UNUSED int flags,
				    UNUSED int argc, UNUSED const char **argv)
{
  char			*user;
  char			*container;
  struct passwd		*passwd;

  if (get_userinfo(&user, &passwd) == 1 ||
      concat(&container, "/home/luks/", user) == 1)
    return (PAM_SESSION_ERR);
  if (check_or_create(container, user, pamh, passwd) == 1 ||
      mount_container(user, passwd) == 1)
    {
      free(container);
      return (PAM_SESSION_ERR);
    }
  return (PAM_SUCCESS);
}