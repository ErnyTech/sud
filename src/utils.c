// SPDX-License-Identifier: GPL-3.0-only
/*
 *  sud/src/utils.c
 *
 *  Copyright (C) Erny <erny@castellotti.net>
 *  Copyright (C) Kat <kat@castellotti.net>
 */

#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sud/sud.h>
#include <sud/utils.h>
#include <unistd.h>

int path_vformat(char path[PATH_MAX], const char *format, va_list arglist) {
    int rc;

    rc = vsnprintf(path, PATH_MAX, format, arglist);

    if (rc < 0) {
        SUD_DEBUG_ERRNO();
        return -1;
    }

    if (rc > PATH_MAX) {
        return -1;
    }

    return rc;
}

int path_format(char path[PATH_MAX], const char *format, ...) {
    int rc;
    va_list arglist;

    va_start(arglist, format);
    rc = path_vformat(path, format, arglist);
    va_end(arglist);

    return rc;
}

int open_path_vformat(int flag, const char *format, va_list arglist) {
    int rc;
    char path[PATH_MAX];

    rc = path_vformat(path, format, arglist);

    if (rc < 0) {
        return -1;
    }

    rc = open(path, flag);
    if (rc < 0) {
        SUD_DEBUG_ERRNO();
        return -1;
    }

    return rc;
}

int open_path_format(int flag, const char *format, ...) {
    int rc;
    va_list arglist;

    va_start(arglist, format);
    rc = open_path_vformat(flag, format, arglist);
    va_end(arglist);

    return rc;
}

int readf_link(char out[PATH_MAX], const char *format, ...) {
    int rc;
    char file[PATH_MAX];
    va_list arglist;

    va_start(arglist, format);
    rc = path_vformat(file, format, arglist);
    va_end(arglist);
    if (rc < 0) {
        return -1;
    }

    rc = readlink(file, out, PATH_MAX - 1);
    if (rc <= 0 || rc >= PATH_MAX - 1) {
        if (rc < 0) {
            SUD_DEBUG_ERRNO();
        }

        return -1;
    }

    out[rc] = '\0';
    return rc;
}

ssize_t readfn_file(char *out, ssize_t n, const char *format, ...) {
    int fd;
    ssize_t size;
    va_list arglist;

    va_start(arglist, format);
    fd = open_path_vformat(O_RDONLY | O_CLOEXEC, format, arglist);
    va_end(arglist);
    if (fd < 0) {
        return -1;
    }

    size = read(fd, out, n);
    if (size <= 0 || size >= n) {
        if (size < 0) {
            SUD_DEBUG_ERRNO();
        }

        close(fd);
        return -1;
    }

    close(fd);
    return size;
}

ssize_t get_arg_max() {
    ssize_t arg_max;

    arg_max = sysconf(_SC_ARG_MAX);
    if (arg_max < SUD_MIN_ARG) {
        SUD_DEBUG_ERRNO();
        return -1;
    }

    return arg_max;
}

int get_process_info_conn(int unix_conn, process_info_t *obj) {
    int rc;
    int result = -1;
    int tty_fd = -1;
    ssize_t arg_max;
    char *envp_buf;
    ssize_t size;
    int i_args;
    struct ucred peercred;
    socklen_t ucred_len = sizeof(peercred);

    /* init */
    obj->stdin = -1;
    obj->stdout = -1;
    obj->stderr = -1;
    obj->tty = -1;
    obj->argc = 0;
    obj->envp_len = 0;

    arg_max = get_arg_max();
    if (arg_max < 0) {
        goto exit;
    }

    /* unix socket conn */
    rc = getsockopt(unix_conn, SOL_SOCKET, SO_PEERCRED, &peercred, &ucred_len);
    if (rc < 0) {
        SUD_DEBUG_ERRNO();
        goto exit;
    }

    obj->pid = peercred.pid;
    obj->uid = peercred.uid;
    obj->gid = peercred.gid;

    /* stdio fds */
    obj->stdin = open_path_format(O_RDONLY | O_CLOEXEC, "/proc/%d/fd/%d", obj->pid, 0);
    if (obj->stdin < 0) {
        goto exit;
    }

    obj->stdout = open_path_format(O_WRONLY | O_CLOEXEC, "/proc/%d/fd/%d", obj->pid, 1);
    if (obj->stdout < 0) {
        goto exit;
    }

    obj->stderr = open_path_format(O_WRONLY | O_CLOEXEC, "/proc/%d/fd/%d", obj->pid, 2);
    if (obj->stderr < 0) {
        goto exit;
    }

    if (isatty(obj->stdin)) {
        tty_fd = 0;
    } else if (isatty(obj->stdin)) {
        tty_fd = 1;
    } else if (isatty(obj->stdin)) {
        tty_fd = 2;
    }

    if (tty_fd >= 0) {
        obj->tty = open_path_format(O_RDWR | O_CLOEXEC, "/proc/%d/fd/%d", obj->pid, tty_fd);
        if (obj->tty < 0) {
            goto exit;
        }
    } else {
        obj->tty = -1;
    }

    /* cwd */
    rc = readf_link(obj->cwd, "/proc/%d/cwd", obj->pid);
    if (rc < 0) {
        goto exit;
    }

    /* exe */
    rc = readf_link(obj->exe, "/proc/%d/exe", obj->pid);
    if (rc < 0) {
        goto exit;
    }

    /* cmdline */
    i_args = 0;

    obj->internal_arg_buf = malloc(arg_max * sizeof(char));
    if (!obj->internal_arg_buf) {
        SUD_DEBUG_ERRNO();
        goto exit;
    }

    size = readfn_file(obj->internal_arg_buf, arg_max, "/proc/%d/cmdline", obj->pid);
    if (size < 0) {
        goto exit;
    }

    for (char *ptr = obj->internal_arg_buf; *ptr != '\0'; ptr += (strlen(ptr) + 1)) {
        obj->argc++;
    }

    obj->argv = malloc((obj->argc + 1) * sizeof(char *));
    if (!obj->argv) {
        SUD_DEBUG_ERRNO();
        goto exit;
    }

    for (char *ptr = obj->internal_arg_buf; *ptr != '\0'; ptr += (strlen(ptr) + 1)) {
        obj->argv[i_args++] = ptr;
    }

    obj->argv[i_args] = nullptr;
    obj->internal_arg_buf_len = size;

    /* envp */
    i_args = 0;
    envp_buf = obj->internal_arg_buf + obj->internal_arg_buf_len;

    size = readfn_file(envp_buf, arg_max - size, "/proc/%d/environ", obj->pid);
    if (size < 0) {
        goto exit;
    }

    for (char *ptr = envp_buf; *ptr != '\0'; ptr += (strlen(ptr) + 1)) {
        obj->envp_len++;
    }

    obj->envp = malloc((obj->envp_len + 1) * sizeof(char *));
    if (!obj->envp) {
        SUD_DEBUG_ERRNO();
        goto exit;
    }

    for (char *ptr = envp_buf; *ptr != '\0'; ptr += (strlen(ptr) + 1)) {
        obj->envp[i_args++] = ptr;
    }

    obj->envp[i_args] = nullptr;
    obj->internal_arg_buf_len += size;
    result = 0;

exit:
    if (result < 0) {
        free_process_info(obj);
    }

    return result;
}

void free_process_info(process_info_t *obj) {
    if (obj->stdin >= 0) {
        close(obj->stdin);
    }

    if (obj->stdout >= 0) {
        close(obj->stdout);
    }

    if (obj->stderr >= 0) {
        close(obj->stderr);
    }

    if (obj->argv) {
        free(obj->argv);
    }

    if (obj->envp) {
        free(obj->envp);
    }

    if (obj->internal_arg_buf) {
        free(obj->internal_arg_buf);
    }
}

char *getenv_envp_str(const char *name, char **envp) {
    size_t name_len = strlen(name);

    for (char **p = envp; *p != nullptr; p++) {
        if (strlen(*p) <= name_len + 1) {
            continue;
        }

        if ((*p)[name_len] != '=') {
            continue;
        }

        if (strncmp(name, *p, name_len) == 0) {
            return *p;
        }
    }

    return nullptr;
}

char *getenv_envp(const char *name, char **envp) {
    char *p = getenv_envp_str(name, envp);

    if (!p) {
        return nullptr;
    }

    return p + strlen(name) + 1;
}
