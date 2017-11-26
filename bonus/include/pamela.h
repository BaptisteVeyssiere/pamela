#ifndef PAMELA_H_
# define PAMELA_H_

# define UNUSED __attribute__((unused))

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

int	get_userinfo(char **user, struct passwd **passwd);
int	concat(char **dest, char *first, char *sec);
int	get_item(pam_handle_t *pamh, int item, const void **dest);

#endif /* !PAMELA_H_ */
