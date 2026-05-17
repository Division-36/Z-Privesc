/*
 * log.h - Public logger API (companion to log.c)
 *
 * Mirrors the Z-Jail log API: four severity levels + a progress helper.
 * Pulled into a separate header so probes and the runner can log without
 * dragging in z_privesc.h internals.
 *
 * Author: Zierax (Ziad Salah) <zs.01117875692@gmail.com>
 */

#ifndef Z_PRIVESC_LOG_H
#define Z_PRIVESC_LOG_H

void zp_log_set_level(int level);
void zp_log_set_quiet(bool quiet);
void zp_log_set_color(bool enable);

void zp_log_debug(const char *fmt, ...);
void zp_log_info(const char *fmt, ...);
void zp_log_warn(const char *fmt, ...);
void zp_log_error(const char *fmt, ...);
void zp_log_progress(const char *fmt, ...);

#endif
