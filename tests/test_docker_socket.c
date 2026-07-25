/* test_docker_socket.c */
#define _POSIX_C_SOURCE 200809L
#include "test_main.h"
#include "probes.h"
#include "audit.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int test_docker_socket_missing(void)
{
    ZP_TEST_BEGIN("docker_socket_missing");
    struct zp_evidence_chain c;
    zp_evidence_chain_init(&c, "docker_socket");
    struct audit_ctx ctx;
    audit_ctx_init(&ctx, 4, 32);
    int rc = zp_probe_docker_socket(&c, "/", &ctx);
    ASSERT_EQ_INT(rc, ZP_OK);
    zp_evidence_chain_release(&c);
    audit_ctx_release(&ctx);
    ZP_TEST_END("docker_socket_missing", 1);
    return ZP_TEST_PASS;
}

int test_docker_socket_handles_no_socket(void)
{
    ZP_TEST_BEGIN("docker_socket_handles_no_socket");
    struct zp_evidence_chain c;
    zp_evidence_chain_init(&c, "docker_socket");
    struct audit_ctx ctx;
    audit_ctx_init(&ctx, 4, 32);
    int rc = zp_probe_docker_socket(&c, "/nonexistent", &ctx);
    ASSERT_EQ_INT(rc, ZP_OK);
    ASSERT_EQ_INT(c.count, 0);
    zp_evidence_chain_release(&c);
    audit_ctx_release(&ctx);
    ZP_TEST_END("docker_socket_handles_no_socket", 1);
    return ZP_TEST_PASS;
}
