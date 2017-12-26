#include "pamela.h"

static int	secure_mount(char *source, char *target, struct passwd *passwd)
{
  /* create mounting directory */
  if (mkdir(target, 0600) == -1)
    {
      perror("mkdir");
      return (1);
    }
  /* mount the partition to the directory */
  if (mount(source, target, "ext3", 0, NULL) == -1)
    {
      perror("mount");
      return (1);
    }
  /* set owner of the directory */
  if (chown(target, passwd->pw_uid, passwd->pw_gid) == -1)
    {
      perror("chown");
      return (1);
    }
  /* set permissions of the directory (rwx for the owner) */
  if (chmod(target, S_IRUSR | S_IWUSR | S_IXUSR) == -1)
    {
      perror("chmod");
      return (1);
    }
  return (0);
}

int	mount_container(char *user, struct passwd *passwd)
{
  char		*source;
  char		*target;

  if (allocate_and_concat(&source, "/dev/mapper/", user) == 1)
    return (1);
  if (allocate_and_concat(&target, passwd->pw_dir, "/secure_data-rw") == 1)
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
  free(source);
  free(target);
  return (0);
}

/*
** cryptsetup stuff
** if new equals 1, then the container is formatted to initialize it
*/
static int			cryptsetup(char *user, char *container,
					   int new, const char *password)
{
  struct crypt_device		*cd;
  char				*command;
  struct crypt_params_luks1	params = {
    .hash = "sha256",
    .data_alignment = 0,
    .data_device = NULL
  };
  unsigned char			*hash;

  /* create sha256 hash of the password and init cryptsetup context */
  if (allocate_and_get_sha256(password, &hash) == 1 ||
      crypt_init(&cd, container) < 0)
    {
      perror("crypt_init");
      return (1);
    }
  /* if new container, it's formatted */
  if (new == 1 && crypt_format(cd, CRYPT_LUKS1, "aes",
			       "xts-plain64", NULL, NULL, 32, &params) < 0)
    {
      crypt_free(cd);
      perror("crypt_format");
      return (1);
    }
  /* Add the hash as access token */
  if (new == 1 && crypt_keyslot_add_by_volume_key(cd, CRYPT_ANY_SLOT, NULL, 0,
						  (char*)hash, 32) < 0)
    {
      crypt_free(cd);
      perror("crypt_keyslot_add_by_volume_key");
      return (1);
    }
  /* load LUKS header */
  if (crypt_load(cd, CRYPT_LUKS1, NULL) < 0)
    {
      perror("crypt_load");
      crypt_free(cd);
      return (1);
    }
  /* open container */
  if (crypt_activate_by_passphrase(cd, user, CRYPT_ANY_SLOT, (char*)hash,
				   32, CRYPT_ACTIVATE_IGNORE_ZERO_BLOCKS) < 0)
    {
      perror("crypt_activate_by_passphrase");
      return (1);
    }
  /* format the partition */
  if (new == 1 &&
      (allocate_and_concat(&command, "/sbin/mkfs.ext3 /dev/mapper/", user) == 1
       || system(command) < 0))
    return (1);
  crypt_free(cd);
  return (0);
}

static int	check_or_create(char *container, char *user,
				struct passwd *passwd, const char *password)
{
  char	*command;

  /* condition true if the container has already been created */
  if (access(container, F_OK) != -1)
    return (cryptsetup(user, container, 0, password));
  /* build command string that will create space for the container (10 Mo) */
  if (allocate_and_concat(&command, "dd if=/dev/urandom bs=10M count=1 of=",
			  container) == 1
      || system(command) < 0)
    return (1);
  /* set file owner */
  if (chown(container, passwd->pw_uid, passwd->pw_gid) == -1)
    {
      perror("chown");
      return (1);
    }
  /* set file permissions (r+w for the owner) */
  if (chmod(container, S_IRUSR | S_IWUSR) == -1)
    {
      perror("chmod");
      return (1);
    }
  /* open LUKS container */
  if (cryptsetup(user, container, 1, password) == 1)
    return (1);
  return (0);
}

/*
** Entry point
** This function is called when the user is trying to authenticate
*/
PAM_EXTERN int	pam_sm_authenticate(pam_handle_t *pamh,
				    UNUSED int flags, UNUSED int argc,
				    UNUSED const char **argv)
{
  char			*user;
  char			*container;
  struct passwd		*passwd;
  char			*password;

  /* get password */
  if (pam_get_item(pamh, PAM_AUTHTOK, (const void **)&password) != PAM_SUCCESS)
    return (PAM_AUTH_ERR);
  /* get informations about the user */
  /* build a string container the full path to his LUKS container */
  if (get_userinfo(&user, &passwd, pamh) == 1 || is_user_invalid(user) == 1 ||
      allocate_and_concat(&container, "/home/luks/", user) == 1)
    return (PAM_AUTH_ERR);
  /* open or create LUKS container and mount it */
  if (check_or_create(container, user, passwd, password) == 1 ||
      mount_container(user, passwd) == 1)
    {
      free(container);
      return (PAM_AUTH_ERR);
    }
  return (PAM_IGNORE);
}
