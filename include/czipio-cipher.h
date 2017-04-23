#ifndef __HTIOFFICE_HTICHIPHER_CONTEXT_H__
#define __HTIOFFICE_HTICHIPHER_CONTEXT_H__

#include <stdint.h>

typedef struct czipio_cipher czipio_cipher;

const uint8_t *czipio_cipher_context_key(const czipio_cipher *const context);
const uint8_t *czipio_cipher_context_initialization_vector(const czipio_cipher *const context);
void czipio_cipher_context_free(czipio_cipher *context);

#endif /* __HTIOFFICE_HTICHIPHER_CONTEXT_H__ */
