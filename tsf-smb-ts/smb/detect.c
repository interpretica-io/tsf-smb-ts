/** @file
 * @brief SMB Group
 *
 * Which SMB tooling the agent has, and listing a server's shares.
 *
 * Copyright (C) 2026 Interpretica Unipessoal Lda
 */

#define TE_TEST_NAME    "smb/detect"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"

#include "tapi_smb.h"
#include "tsapi_cybersec.h"

#define T_MS 30000

int
main(int argc, char **argv)
{
    tsapi_cybersec_session sess;
    tapi_smb_backend backend;
    tapi_smb_target target = TAPI_SMB_TARGET_INIT;
    te_vec shares = TE_VEC_INIT(tapi_smb_share_info);
    tapi_smb_share_info *s;
    bool saw_public = false;

    TEST_START;

    TEST_STEP("Open a session to the agent");
    CHECK_RC(tsapi_cybersec_session_init(&sess, "pco_smb_detect"));

    TEST_STEP("An SMB client is present");
    if (!tapi_smb_available(sess.factory, TAPI_SMB_AUTO, T_MS))
        TEST_VERDICT("No SMB client on the agent");

    TEST_STEP("It is Samba, not macOS or Windows");
    CHECK_RC(tapi_smb_detect(sess.factory, T_MS, &backend));
    if (backend != TAPI_SMB_SAMBA)
        TEST_VERDICT("A Linux agent was detected as %s",
                     tapi_smb_backend2str(backend));

    TEST_STEP("The capability table says what it should");
    if (!tapi_smb_supports(TAPI_SMB_SAMBA, TAPI_SMB_FEAT_SERVE) ||
        !tapi_smb_supports(TAPI_SMB_SAMBA, TAPI_SMB_FEAT_DIALECT) ||
        tapi_smb_supports(TAPI_SMB_MACOS, TAPI_SMB_FEAT_DIALECT) ||
        tapi_smb_supports(TAPI_SMB_MACOS, TAPI_SMB_FEAT_SERVE))
    {
        TEST_VERDICT("The capability table is wrong");
    }

    TEST_STEP("List the shares of localhost as alice");
    target.server = "localhost";
    target.user = "alice";
    target.password = "s3cret";
    CHECK_RC(tapi_smb_list(sess.factory, TAPI_SMB_SAMBA, &target, T_MS,
                           &shares));
    TE_VEC_FOREACH(&shares, s)
    {
        RING("share '%s' (%s)%s%s", s->name, s->is_disk ? "disk" : "other",
             s->comment != NULL ? ": " : "",
             s->comment != NULL ? s->comment : "");
        if (strcmp(s->name, "public") == 0 && s->is_disk)
            saw_public = true;
    }
    if (!saw_public)
        TEST_VERDICT("The 'public' disk share was not listed");

    TEST_STEP("A wrong password is refused with EACCES");
    target.password = "wrong";
    {
        te_vec none = TE_VEC_INIT(tapi_smb_share_info);
        te_errno rc = tapi_smb_list(sess.factory, TAPI_SMB_SAMBA, &target,
                                    T_MS, &none);

        tapi_smb_shares_free(&none);
        if (TE_RC_GET_ERROR(rc) != TE_EACCES)
            TEST_VERDICT("A wrong password gave %r, not EACCES", rc);
    }

    TEST_SUCCESS;

cleanup:
    tapi_smb_shares_free(&shares);
    tsapi_cybersec_session_fini(&sess);
    TEST_END;
}
