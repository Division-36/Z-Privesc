/*
 * util.c - System helpers for Z-Privesc
 *
 * Hosts shared utilities: build-id, path joining, file/socket probing,
 * and the only hashing primitive in the project (BLAKE2b-256, used
 * exclusively to derive the per-build suffix of the build ID).
 *
 * Author: Zierax (Ziad Salah) <zs.01117875692@gmail.com>
 */

#define _POSIX_C_SOURCE 200809L

#include "z_privesc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <dirent.h>
#include <pwd.h>
#include <grp.h>

#include "log.h"
#include "zp_crypto.h"

const char *zp_build_id(void)
{
    return BUILD_ID;
}

const char *zp_version(void)
{
    return VERSION;
}

int zp_path_join(char *out, size_t cap, const char *a, const char *b)
{
    if (out == NULL || cap == 0 || a == NULL || b == NULL) {
        return ZP_ERR_INVAL;
    }
    size_t la = strlen(a);
    size_t lb = strlen(b);
    bool   sep = (la > 0 && a[la - 1] != '/');
    size_t need = la + (sep ? 1 : 0) + lb + 1;
    if (need > cap) {
        return ZP_ERR_INVAL;
    }
    if (sep) {
        snprintf(out, cap, "%s/%s", a, b);
    } else {
        snprintf(out, cap, "%s%s", a, b);
    }
    return ZP_OK;
}

int zp_path_normalize(char *path)
{
    if (path == NULL || path[0] == '\0') {
        return ZP_ERR_INVAL;
    }
    bool abs = (path[0] == '/');
    char *p = path;
    while (*p == '.' && p[1] == '/') {
        memmove(p, p + 2, strlen(p + 2) + 1);
    }
    char *out = path;
    char *seg[1024];
    int   depth = 0;
    char *tok   = strtok(path, "/");
    while (tok != NULL) {
        if (strcmp(tok, ".") == 0) {
        } else if (strcmp(tok, "..") == 0) {
            if (depth > 0) {
                depth--;
            }
        } else {
            seg[depth++] = tok;
            if (depth >= 1024) {
                return ZP_ERR_INVAL;
            }
        }
        tok = strtok(NULL, "/");
    }
    out[0] = '\0';
    for (int i = 0; i < depth; i++) {
        if (abs || i > 0) {
            strcat(out, "/");
        }
        strcat(out, seg[i]);
    }
    if (out[0] == '\0') {
        strcpy(out, abs ? "/" : ".");
    }
    return ZP_OK;
}

int zp_stat_follow(const char *path, struct stat *st)
{
    if (path == NULL || st == NULL) {
        return ZP_ERR_INVAL;
    }
    if (stat(path, st) != 0) {
        return ZP_ERR_IO;
    }
    return ZP_OK;
}

int zp_lstat(const char *path, struct stat *st)
{
    if (path == NULL || st == NULL) {
        return ZP_ERR_INVAL;
    }
    if (lstat(path, st) != 0) {
        return ZP_ERR_IO;
    }
    return ZP_OK;
}

int zp_file_readable(const char *path)
{
    if (path == NULL) {
        return 0;
    }
    return access(path, R_OK) == 0;
}

int zp_file_writable(const char *path)
{
    if (path == NULL) {
        return 0;
    }
    return access(path, W_OK) == 0;
}

int zp_path_is_dir(const char *path)
{
    struct stat st;
    if (zp_stat_follow(path, &st) != ZP_OK) {
        return 0;
    }
    return S_ISDIR(st.st_mode) ? 1 : 0;
}

int zp_path_is_socket(const char *path)
{
    struct stat st;
    if (zp_stat_follow(path, &st) != ZP_OK) {
        return 0;
    }
    return S_ISSOCK(st.st_mode) ? 1 : 0;
}

int zp_world_writable(const struct stat *st)
{
    if (st == NULL) {
        return 0;
    }
    return (st->st_mode & S_IWOTH) ? 1 : 0;
}

int zp_socket_connect_unix(const char *path)
{
    if (path == NULL) {
        return -1;
    }
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    size_t pl = strlen(path);
    if (pl >= sizeof(addr.sun_path)) {
        close(fd);
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(addr.sun_path, path, pl);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int zp_read_proc_self_status_field(const char *field, char *out, size_t cap)
{
    if (field == NULL || out == NULL || cap == 0) {
        return ZP_ERR_INVAL;
    }
    FILE *f = fopen("/proc/self/status", "r");
    if (f == NULL) {
        return ZP_ERR_IO;
    }
    char line[512];
    size_t flen = strlen(field);
    int    rc   = ZP_ERR_IO;
    while (fgets(line, sizeof(line), f) != NULL) {
        if (strncmp(line, field, flen) == 0 && line[flen] == ':') {
            const char *v = line + flen + 1;
            while (*v == ' ' || *v == '\t') {
                v++;
            }
            size_t l = strlen(v);
            while (l > 0 && (v[l - 1] == '\n' || v[l - 1] == '\r')) {
                l--;
            }
            char *vc = (char *)v;
            vc[l] = '\0';
            if (l >= cap) {
                l = cap - 1;
            }
            memcpy(out, v, l);
            out[l] = '\0';
            rc = ZP_OK;
            break;
        }
    }
    fclose(f);
    return rc;
}

int zp_dir_open(DIR **out, const char *path)
{
    if (out == NULL || path == NULL) {
        return ZP_ERR_INVAL;
    }
    *out = opendir(path);
    if (*out == NULL) {
        return ZP_ERR_IO;
    }
    return ZP_OK;
}

void zp_dir_close(DIR *d)
{
    if (d != NULL) {
        closedir(d);
    }
}

uint64_t zp_monotonic_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

int zp_hostname(char *out, size_t cap)
{
    if (out == NULL || cap == 0) {
        return ZP_ERR_INVAL;
    }
    if (gethostname(out, cap) != 0) {
        return ZP_ERR_IO;
    }
    out[cap - 1] = '\0';
    return ZP_OK;
}

int zp_username(char *out, size_t cap)
{
    if (out == NULL || cap == 0) {
        return ZP_ERR_INVAL;
    }
    struct passwd *pw = getpwuid(getuid());
    if (pw == NULL) {
        return ZP_ERR_IO;
    }
    size_t l = strlen(pw->pw_name);
    if (l >= cap) {
        l = cap - 1;
    }
    memcpy(out, pw->pw_name, l);
    out[l] = '\0';
    return ZP_OK;
}

int zp_kernel_version(char *out, size_t cap)
{
    if (out == NULL || cap == 0) {
        return ZP_ERR_INVAL;
    }
    FILE *f = fopen("/proc/version", "r");
    if (f == NULL) {
        return ZP_ERR_IO;
    }
    if (fgets(out, (int)cap, f) == NULL) {
        fclose(f);
        return ZP_ERR_IO;
    }
    fclose(f);
    size_t l = strlen(out);
    while (l > 0 && (out[l - 1] == '\n' || out[l - 1] == '\r')) {
        out[--l] = '\0';
    }
    return ZP_OK;
}

void *zp_malloc(size_t n)
{
    void *p = malloc(n);
    if (p == NULL) {
        zp_log_error("out of memory allocating %zu bytes", n);
        abort();
    }
    return p;
}

void *zp_calloc(size_t nmemb, size_t size)
{
    void *p = calloc(nmemb, size);
    if (p == NULL) {
        zp_log_error("out of memory allocating %zu * %zu bytes", nmemb,
                        size);
        abort();
    }
    return p;
}

char *zp_strdup(const char *s)
{
    if (s == NULL) {
        return NULL;
    }
    size_t l = strlen(s);
    char  *p = zp_malloc(l + 1);
    memcpy(p, s, l + 1);
    return p;
}
