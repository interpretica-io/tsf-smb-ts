/** @file
 * @brief SMB Group
 *
 * What a connection negotiates, and the dialect bounds a target sets.
 *
 * Copyright (C) 2026 Interpretica Unipessoal Lda
 */

#define TE_TEST_NAME    "smb/negotiate"

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
    tapi_smb_target target = TAPI_SMB_TARGET_INIT;
    tapi_smb_conn_info info;
    te_string status = TE_STRING_INIT;

    TEST_START;

    TEST_STEP("Open a session to the agent");
    CHECK_RC(tsapi_cybersec_session_init(&sess, "pco_smb_negotiate"));

    target.server = "localhost";
    target.user = "alice";
    target.password = "s3cret";

    TEST_STEP("A default connection negotiates the newest dialect");
    CHECK_RC(tapi_smb_connect_info(sess.factory, TAPI_SMB_SAMBA, &target,
                                   "public", T_MS, &info));
    tapi_smb_conn_info_log(&info);
    if (info.dialect != TAPI_SMB_DIALECT_SMB3_11)
        TEST_VERDICT("The default dialect was %s, expected SMB3.1.1",
                     tapi_smb_dialect2str(info.dialect));
    tapi_smb_conn_info_free(&info);

    TEST_STEP("Capping the dialect at SMB2.1 is obeyed");
    target.max_dialect = TAPI_SMB_DIALECT_SMB2_10;
    CHECK_RC(tapi_smb_connect_info(sess.factory, TAPI_SMB_SAMBA, &target,
                                   "public", T_MS, &info));
    tapi_smb_conn_info_log(&info);
    if (info.dialect != TAPI_SMB_DIALECT_SMB2_10)
        TEST_VERDICT("With a cap of SMB2.1 the dialect was %s",
                     tapi_smb_dialect2str(info.dialect));
    tapi_smb_conn_info_free(&info);
    target.max_dialect = TAPI_SMB_DIALECT_ANY;

    TEST_STEP("A connection can be reached, and can_connect says so");
    if (!tapi_smb_can_connect(sess.factory, TAPI_SMB_SAMBA, &target,
                              "public", T_MS, &status))
        TEST_VERDICT("can_connect said no to a good target: %s", status.ptr);

    TEST_STEP("macOS is refused a dialect it cannot force");
    target.min_dialect = TAPI_SMB_DIALECT_SMB3_00;
    {
        tapi_smb_conn_info none;
        te_errno rc = tapi_smb_connect_info(sess.factory, TAPI_SMB_MACOS,
                          &target, "public", T_MS, &none);

        if (TE_RC_GET_ERROR(rc) != TE_EOPNOTSUPP)
            TEST_VERDICT("macOS with a dialect bound gave %r, not EOPNOTSUPP",
                         rc);
    }

    TEST_SUCCESS;

cleanup:
    te_string_free(&status);
    tsapi_cybersec_session_fini(&sess);
    TEST_END;
}
