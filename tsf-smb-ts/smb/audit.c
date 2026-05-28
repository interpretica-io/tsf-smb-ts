/** @file
 * @brief SMB Group
 *
 * The posture of the SMB server on the agent. The server is set up to
 * fail on purpose - SMB1 turned on, a guest-writable share - so that
 * the assertion is that the audit reports the planted weakness.
 *
 * Copyright (C) 2026 Interpretica Unipessoal Lda
 */

#define TE_TEST_NAME    "smb/audit"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"

#include "tapi_smb.h"
#include "tapi_smb_audit.h"
#include "tsapi_cybersec.h"

#define T_MS 30000

int
main(int argc, char **argv)
{
    tsapi_cybersec_session sess;
    tapi_smb_target target = TAPI_SMB_TARGET_INIT;
    tapi_smb_policy policy = {0};
    tapi_cybersec_report report;

    tapi_cybersec_report_init(&report);

    TEST_START;

    TEST_STEP("Open a session to the agent");
    CHECK_RC(tsapi_cybersec_session_init(&sess, "pco_smb_audit"));
    if (!tsapi_cybersec_have(&sess, "python3"))
        TEST_SKIP("There is no python3 on the agent to negotiate with");

    TEST_STEP("Audit the SMB server on the agent");
    target.server = "localhost";
    policy.guest_share = "public";
    CHECK_RC(tapi_smb_audit(sess.factory, TAPI_SMB_SAMBA, &target, &policy,
                            T_MS, &report));
    tapi_cybersec_report_log(&report);

    TEST_STEP("SMB1 is on, and reported");
    /*
     * The server was built with "server min protocol = NT1", so it
     * answers an SMB1 negotiate; a report that misses it is the
     * failure this test exists to catch.
     */
    TSAPI_CYBERSEC_EXPECT(&report, "smb.smb1-enabled");

    TEST_STEP("The public share is guest-writable, and reported");
    TSAPI_CYBERSEC_EXPECT(&report, "smb.guest-writable");

    TEST_SUCCESS;

cleanup:
    tapi_cybersec_report_free(&report);
    tsapi_cybersec_session_fini(&sess);
    TEST_END;
}
