#include <unistd.h>
#include <stdio.h>
#include <security/pam_modules.h>

int	pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  printf("Session close\n");
  sleep(3);
  return (PAM_SUCCESS);
}

int	pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  print("Session open\n");
  return (PAM_SUCCESS);
}
