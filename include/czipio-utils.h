#ifndef __czipio_H__
#define __czipio_H__

#include <inttypes.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>

typedef int (*czipio_dir_visitor)(const char *const, const char *const, mode_t, void *);

char *czipio_strdup(const char *const source);
char *czipio_strdup_printf(const char *const format, ...);
int czipio_directory_walk(const char *const path, czipio_dir_visitor function, void *data);
const uint8_t *czipio_sha256digest(const uint8_t *const entrada, size_t length);
uint8_t *czipio_pbkdf2_hmac(const char *const password,
    const uint8_t *const salt, int iterations, int keylen);
bool czipio_file_exists(const char *const path);
bool czipio_directory_exists(const char *const path);
void czipio_remove_directory(const char *const path);
bool czipio_check_md5_digest(const char *const md5sum, const uint8_t *const content, size_t length);

#endif /* __czipio_H__ */
