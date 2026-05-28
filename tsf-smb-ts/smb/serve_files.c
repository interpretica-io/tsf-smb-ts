/** @file
 * @brief SMB Group
 *
 * The agent serves a share of its own, connects back to it, and every
 * file operation is checked against what appears on the served
 * directory - so one agent is both server and client.
 *
 * Copyright (C) 2026 Interpretica Unipessoal Lda
 */

#define TE_TEST_NAME    "smb/serve_files"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"
#include "tapi_rpc_stdio.h"

#include "tapi_smb.h"
#include "tapi_smb_file.h"
#include "tapi_smb_share.h"
#include "tsapi_cybersec.h"

#define T_MS  30000
#define SHARE "tsfshare"

int
main(int argc, char **argv)
{
    tsapi_cybersec_session sess;
    tapi_smb_served served = TAPI_SMB_SERVED_INIT;
    tapi_smb_target target = TAPI_SMB_TARGET_INIT;
    bool serving = false;
    te_string dir = TE_STRING_INIT;
    te_string content = TE_STRING_INIT;
    te_vec entries = TE_VEC_INIT(tapi_smb_dirent);
    tapi_smb_dirent *e;
    bool saw_file = false;
    bool saw_dir = false;

    TEST_START;

    TEST_STEP("Open a session and check the agent can serve");
    CHECK_RC(tsapi_cybersec_session_init(&sess, "pco_smb_serve"));
    if (!tapi_smb_can_serve(sess.factory, TAPI_SMB_SAMBA, T_MS))
        TEST_SKIP("The agent may not serve a usershare");

    TEST_STEP("Serve a scratch directory");
    CHECK_RC(tsapi_cybersec_scratch(&sess, "smb-serve", &dir));
    /*
     * The SMB user (alice) is not the agent's own user, so she cannot
     * write to a directory the agent made with its default mode. The
     * share is a test fixture, so it is opened wide on purpose.
     */
    {
        te_string cmd = TE_STRING_INIT;

        te_string_append(&cmd, "chmod 0777 %s", dir.ptr);
        rpc_system(sess.pco, cmd.ptr);
        te_string_free(&cmd);
    }
    served.name = SHARE;
    served.path = dir.ptr;
    served.comment = "tsf served share";
    served.writable = true;
    CHECK_RC(tapi_smb_serve(sess.factory, TAPI_SMB_SAMBA, &served, T_MS));
    serving = true;

    TEST_STEP("A client can list the server");
    target.server = "localhost";
    target.user = "alice";
    target.password = "s3cret";
    {
        te_vec shares = TE_VEC_INIT(tapi_smb_share_info);
        tapi_smb_share_info *s;
        bool found = false;

        CHECK_RC(tapi_smb_list(sess.factory, TAPI_SMB_SAMBA, &target, T_MS,
                               &shares));
        TE_VEC_FOREACH(&shares, s)
            if (strcmp(s->name, SHARE) == 0)
                found = true;
        tapi_smb_shares_free(&shares);
        /*
         * A usershare is reached by name whether or not it is
         * enumerated to a browse, so the file round-trip below is the
         * real proof that it is served; the enumeration is only noted.
         */
        RING("The served share %s in the browse list",
             found ? "is" : "is not");
    }

    TEST_STEP("Write a file, and read it back byte for byte");
    CHECK_RC(tapi_smb_write(sess.factory, TAPI_SMB_SAMBA, &target, SHARE,
                            "hello.txt", "tsf-smb\ncontent\n", 16, T_MS));
    CHECK_RC(tapi_smb_read(sess.factory, TAPI_SMB_SAMBA, &target, SHARE,
                           "hello.txt", T_MS, &content));
    if (strcmp(content.ptr, "tsf-smb\ncontent\n") != 0)
        TEST_VERDICT("The file came back as '%s'", content.ptr);

    TEST_STEP("exists() is true for it and false for what is not there");
    if (!tapi_smb_exists(sess.factory, TAPI_SMB_SAMBA, &target, SHARE,
                         "hello.txt", T_MS))
        TEST_VERDICT("exists() is false for a file that is there");
    if (tapi_smb_exists(sess.factory, TAPI_SMB_SAMBA, &target, SHARE,
                        "nothere.txt", T_MS))
        TEST_VERDICT("exists() is true for a file that is not");

    TEST_STEP("Make a directory, and list the share");
    CHECK_RC(tapi_smb_mkdir(sess.factory, TAPI_SMB_SAMBA, &target, SHARE,
                            "sub", T_MS));
    CHECK_RC(tapi_smb_ls(sess.factory, TAPI_SMB_SAMBA, &target, SHARE, "",
                         T_MS, &entries));
    TE_VEC_FOREACH(&entries, e)
    {
        RING("entry '%s' %s %ld", e->name, e->is_dir ? "dir" : "file",
             e->size);
        if (strcmp(e->name, "hello.txt") == 0 && !e->is_dir && e->size == 16)
            saw_file = true;
        if (strcmp(e->name, "sub") == 0 && e->is_dir)
            saw_dir = true;
    }
    if (!saw_file)
        TEST_VERDICT("hello.txt (16 bytes) not in the listing");
    if (!saw_dir)
        TEST_VERDICT("the directory 'sub' not in the listing");

    TEST_STEP("Remove the file and the directory");
    CHECK_RC(tapi_smb_unlink(sess.factory, TAPI_SMB_SAMBA, &target, SHARE,
                             "hello.txt", T_MS));
    if (tapi_smb_exists(sess.factory, TAPI_SMB_SAMBA, &target, SHARE,
                        "hello.txt", T_MS))
        TEST_VERDICT("the file is still there after unlink");
    CHECK_RC(tapi_smb_rmdir(sess.factory, TAPI_SMB_SAMBA, &target, SHARE,
                            "sub", T_MS));

    TEST_STEP("Getting a file that is not there is ENOENT");
    {
        te_errno rc = tapi_smb_get_to_engine(sess.factory, TAPI_SMB_SAMBA,
                          &target, SHARE, "gone.txt",
                          "/tmp/tsf_should_not_appear", T_MS);

        if (TE_RC_GET_ERROR(rc) != TE_ENOENT)
            TEST_VERDICT("get of a missing file gave %r, not ENOENT", rc);
    }

    TEST_SUCCESS;

cleanup:
    if (serving)
        tapi_smb_unserve(sess.factory, TAPI_SMB_SAMBA, SHARE, T_MS);
    tapi_smb_dirents_free(&entries);
    te_string_free(&dir);
    te_string_free(&content);
    tsapi_cybersec_session_fini(&sess);
    TEST_END;
}
