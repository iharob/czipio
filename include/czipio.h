#ifndef __HTIOFFICE_czipio_H__
#define __HTIOFFICE_czipio_H__

#include <stdlib.h>
#include <stdint.h>

typedef struct czipio_file czipio_file;
typedef struct czipio_entry czipio_entry;

czipio_file *czipio_open(const char *const path);
czipio_file *czipio_create(const char *const path);
void czipio_close(czipio_file *zip);
const czipio_entry *czipio_find(const czipio_file *const zip, const char *const cual);
void czipio_list(const czipio_file *const zip, int indent);
void czipio_append_directory(czipio_file *zip, const char *const path);
void czipio_append_file(czipio_file *zip, const char *const name);

uint8_t *czipio_uncipher(czipio_entry *file, int32_t *size);
uint8_t *czipio_pbkdf2_hmac(const char *const password, const uint8_t *const salt, int iterations, int keylen);

#endif /* __HTIOFFICE_czipio_H__ */
