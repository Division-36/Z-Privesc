/*
 * docker_socket.c - Docker control socket exposure detector
 *
 * Looks for /var/run/docker.sock and /run/docker.sock, checks mode
 * bits, and (optionally) attempts a non-destructive HTTP ping over
 * the socket to confirm reachability.
 *
 * Author: Zierax (Ziad Salah) <zs.01117875692@gmail.com>
 */

#define _POSIX_C_SOURCE 200809L

#include "z_privesc.h"
#include "probes.h"
#include "truthimatics.h"
#include "audit.h"
#include "util.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>

static const char *SOCKET_PATHS[] = {
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/run/docker/docker.sock",
};

static int docker_ping(const char *path)
{
    int fd = zp_socket_connect_unix(path);
    if (fd < 0) {
        return -1;
    }
    static const char req[] = "GET /_ping HTTP/1.0\r\n\r\n";
    ssize_t w = write(fd, req, sizeof(req) - 1);
    if (w < 0) {
        close(fd);
        return -1;
    }
    char buf[256];
    ssize_t r = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (r <= 0) {
        return -1;
    }
    buf[r] = '\0';
    if (strstr(buf, "200 OK") != NULL) {
        return 0;
    }
    return -1;
}

int zp_probe_docker_socket(struct zp_evidence_chain *c,
                              const char *root, struct audit_ctx *ctx)
{
    (void)ctx;
    if (c == NULL) {
        return ZP_ERR_INVAL;
    }
    if (root == NULL) {
        root = "/";
    }
    for (size_t i = 0; i < sizeof(SOCKET_PATHS) / sizeof(SOCKET_PATHS[0]);
         i++) {
        char rpath[4096];
        if (strcmp(root, "/") == 0) {
            snprintf(rpath, sizeof(rpath), "%s", SOCKET_PATHS[i]);
        } else if (zp_path_join(rpath, sizeof(rpath), root, SOCKET_PATHS[i])
                   != ZP_OK) {
            continue;
        }
        struct stat st;
        if (lstat(rpath, &st) != 0) {
            continue;
        }
        if (!S_ISSOCK(st.st_mode)) {
            continue;
        }
        bool user_reachable = zp_file_writable(rpath);
        bool world_open     = (st.st_mode & S_IWOTH) != 0;
        int  pinged         = docker_ping(rpath);
        char id[ZP_EVIDENCE_ID_MAX];
        snprintf(id, sizeof(id), "DOCK-%03zu", i + 1);
        char desc[ZP_DESC_MAX];
        snprintf(desc, sizeof(desc),
                 "Docker socket %s present (mode %04o, world-writable=%s, "
                 "writable-by-user=%s, ping=%s)",
                 SOCKET_PATHS[i], st.st_mode & 0777,
                 world_open ? "yes" : "no",
                 user_reachable ? "yes" : "no",
                 pinged == 0 ? "ok" : "fail");
        char rem[ZP_REMEDIATION_MAX];
        snprintf(rem, sizeof(rem),
                 "Restrict socket: chmod 660 %s, add user to docker group "
                 "explicitly", SOCKET_PATHS[i]);
        float weight;
        enum zp_severity sev;
        if (user_reachable && pinged == 0) {
            weight = 0.99f;
            sev    = ZP_SEV_CRITICAL;
        } else if (world_open) {
            weight = 0.85f;
            sev    = ZP_SEV_HIGH;
        } else {
            weight = 0.4f;
            sev    = ZP_SEV_LOW;
        }
        zp_evidence_add(c, id, SOCKET_PATHS[i], desc, rem, weight,
                          ZP_VERDICT_DETERMINISTIC, sev);
    }
    return ZP_OK;
}
