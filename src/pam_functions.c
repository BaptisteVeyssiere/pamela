#include "pamela.h"

PAM_EXTERN int	pam_sm_setcred(UNUSED pam_handle_t *pamh, UNUSED int flags,
			       UNUSED int argc, UNUSED const char **argv)
{
  return (PAM_SUCCESS);
}

PAM_EXTERN int	pam_sm_acct_mgmt(UNUSED pam_handle_t *pamh,UNUSED int flags,
				 UNUSED int argc, UNUSED const char **argv)
{
  return (PAM_SUCCESS);
}

PAM_EXTERN int	pam_sm_open_session(UNUSED pam_handle_t *pamh,
				    UNUSED int flags, UNUSED int argc,
				    UNUSED const char **argv)
{
  return (PAM_SUCCESS);
}
