/*
 * log.c - Unified logger for Z-Privesc
 *
 * Mirrors the Z-Jail logging style: timestamped, level-prefixed, color
 * aware, and thread-safe via a single static mutex.
 *
 * Author: Zierax (Ziad Salah) <zs.01117875692@gmail.com>
 */

#define _POSIX_C_SOURCE 200809L

#include "z_privesc.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>

enum zp_log_level {
    ZP_LL_DEBUG = 0,
    ZP_LL_INFO  = 1,
    ZP_LL_WARN  = 2,
    ZP_LL_ERROR = 3
};

static enum zp_log_level g_level     = ZP_LL_INFO;
static bool                 g_quiet     = false;
static bool                 g_color     = true;
static pthread_mutex_t      g_log_mtx   = PTHREAD_MUTEX_INITIALIZER;

void zp_log_set_level(int level)
{
    if (level < ZP_LL_DEBUG) {
        level = ZP_LL_DEBUG;
    }
    if (level > ZP_LL_ERROR) {
        level = ZP_LL_ERROR;
    }
    g_level = (enum zp_log_level)level;
}

void zp_log_set_quiet(bool quiet)
{
    g_quiet = quiet;
}

void zp_log_set_color(bool enable)
{
    g_color = enable;
}

static const char *level_tag(enum zp_log_level l)
{
    switch (l) {
    case ZP_LL_DEBUG: return "DBG";
    case ZP_LL_INFO:  return "INF";
    case ZP_LL_WARN:  return "WRN";
    case ZP_LL_ERROR: return "ERR";
    }
    return "???";
}

static const char *level_color(enum zp_log_level l)
{
    if (!g_color) {
        return "";
    }
    switch (l) {
    case ZP_LL_DEBUG: return "\x1b[90m";
    case ZP_LL_INFO:  return "\x1b[36m";
    case ZP_LL_WARN:  return "\x1b[33m";
    case ZP_LL_ERROR: return "\x1b[31m";
    }
    return "";
}

static void format_ts(char *buf, size_t cap)
{
    struct timespec ts;
    struct tm       tm;
    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r(&ts.tv_sec, &tm);
    strftime(buf, cap, "%Y-%m-%dT%H:%M:%S", &tm);
}

static void vlog(enum zp_log_level l, const char *fmt, va_list ap)
{
    if (g_quiet && l < ZP_LL_ERROR) {
        return;
    }
    if (l < g_level) {
        return;
    }
    char ts[32];
    format_ts(ts, sizeof(ts));
    pthread_mutex_lock(&g_log_mtx);
    fprintf(stderr, "%s%s %s%-3s\x1b[0m [z-privesc] ",
            g_color ? "\x1b[90m" : "", ts, level_color(l), level_tag(l));
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    fflush(stderr);
    pthread_mutex_unlock(&g_log_mtx);
}

void zp_log_debug(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vlog(ZP_LL_DEBUG, fmt, ap);
    va_end(ap);
}

void zp_log_info(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vlog(ZP_LL_INFO, fmt, ap);
    va_end(ap);
}

void zp_log_warn(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vlog(ZP_LL_WARN, fmt, ap);
    va_end(ap);
}

void zp_log_error(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vlog(ZP_LL_ERROR, fmt, ap);
    va_end(ap);
}

void zp_log_progress(const char *fmt, ...)
{
    if (g_quiet) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    pthread_mutex_lock(&g_log_mtx);
    fprintf(stderr, "%s==>%s ", g_color ? "\x1b[1;34m" : "",
            g_color ? "\x1b[0m" : "");
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    fflush(stderr);
    pthread_mutex_unlock(&g_log_mtx);
    va_end(ap);
}
