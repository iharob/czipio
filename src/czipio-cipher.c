#include <czipio-cipher.h>
#include <stdlib.h>

typedef struct czipio_cipher
{
    uint8_t *key;
    int key_length;
    uint8_t *initialization_vector;
} czipio_cipher;

const uint8_t *
czipio_cipher_context_key(const czipio_cipher *const context)
{
    if (context == NULL)
        return NULL;
    return context->key;
}

const uint8_t *
czipio_cipher_context_initialization_vector(const czipio_cipher *const context)
{
    if (context == NULL)
        return NULL;
    return context->initialization_vector;
}

void
czipio_cipher_context_free(czipio_cipher *context)
{
    if (context == NULL)
        return;
    if (context->key != NULL)
        free(context->key);
    if (context->initialization_vector != NULL)
        free(context->initialization_vector);
    free(context);
}
