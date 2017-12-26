#ifndef PAMELA_H_
# define PAMELA_H_

# define UNUSED __attribute__((unused))
# define PAM_SM_PASSWORD

# include <libcryptsetup.h>
# include <unistd.h>
# include <stdio.h>
# include <sys/types.h>
# include <pwd.h>
# include <strings.h>
# include <string.h>
# include <stdlib.h>
# include <sys/mount.h>
# include <sys/stat.h>
# include <security/pam_modules.h>
# include <openssl/sha.h>

/*
** shared.c
*/
int	is_user_invalid(const char *user);
int	allocate_and_get_sha256(const char *data, unsigned char **digest);
int	get_userinfo(char **user, struct passwd **passwd, pam_handle_t *pamh);
int	allocate_and_concat(char **dest, char *first, char *sec);
int	get_item(pam_handle_t *pamh, int item, const void **dest);

/*
** close.c
*/
int	umount_container(struct passwd *passwd);

/*
** open.c
*/
int	mount_container(char *user, struct passwd *passwd);

#endif /* !PAMELA_H_ */
