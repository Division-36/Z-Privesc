/*
 * util.h - Public utilities (companion to util.c)
 *
 * Author: Zierax (Ziad Salah) <zs.01117875692@gmail.com>
 */

#ifndef Z_PRIVESC_UTIL_H
#define Z_PRIVESC_UTIL_H

#include <stdint.h>
#include <stddef.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>

int      zp_path_join(char *out, size_t cap, const char *a, const char *b);
int      zp_path_normalize(char *path);
int      zp_stat_follow(const char *path, struct stat *st);
int      zp_lstat(const char *path, struct stat *st);
int      zp_file_readable(const char *path);
int      zp_file_writable(const char *path);
int      zp_path_is_dir(const char *path);
int      zp_path_is_socket(const char *path);
int      zp_world_writable(const struct stat *st);
int      zp_socket_connect_unix(const char *path);
int      zp_read_proc_self_status_field(const char *field,
                                           char *out, size_t cap);
int      zp_dir_open(DIR **out, const char *path);
void     zp_dir_close(DIR *d);
uint64_t zp_monotonic_ns(void);
int      zp_hostname(char *out, size_t cap);
int      zp_username(char *out, size_t cap);
int      zp_username_for_uid(uid_t uid, char *out, size_t cap);
int      zp_user_in_group(const char *user, const char *group,
                          char *gid_out, size_t gid_cap);
int      zp_primary_gid_for_uid(uid_t uid, gid_t *out);
int      zp_kernel_version(char *out, size_t cap);
void    *zp_malloc(size_t n);
void    *zp_calloc(size_t nmemb, size_t size);
char    *zp_strdup(const char *s);

#endif
