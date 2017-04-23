#ifndef __HTIOFFICE_czipio_entry_H__
#define __HTIOFFICE_czipio_entry_H__

#include <stdint.h>
#include <stdlib.h>

typedef struct czipio_cipher czipio_cipher;
typedef struct czipio_entry czipio_entry;
typedef struct czipio_entry_stream czipio_entry_stream;
typedef enum czipio_entry_mime_type czipio_entry_mime_type;

enum czipio_entry_mime_type {
    UNKNOWN_MIME_TYPE = -1,
    PNG_IMAGE,
    JPEG_IMAGE,
    TIFF_IMAGE,
    MP3_AUDIO,
    MP4_VIDEO,
    WEBM_VIDEO
};

uint8_t *czipio_entry_content(const czipio_entry *const file);
czipio_cipher *czipio_entry_cipher_context(const czipio_entry *const file);
size_t czipio_entry_size(const czipio_entry *const file);
void czipio_entry_set_size(czipio_entry *file, size_t size);
czipio_entry *czipio_entry_new(const char *const name);
void czipio_entry_set_content(czipio_entry *file, uint8_t * const content, int32_t size);
czipio_entry *czipio_entry_append_file(czipio_entry *list, czipio_entry *const file);
void czipio_entry_free(czipio_entry *archivos);
czipio_entry *czipio_entry_next(czipio_entry *file);
const char *czipio_entry_name(const czipio_entry *const file);
int czipio_entry_save(const czipio_entry *const file, const char *const path);
czipio_entry_mime_type czipio_entry_getmime(const czipio_entry *const file);
// Streaming API
czipio_entry_stream *czipio_entry_stream_reader(const czipio_entry *const entry);
czipio_entry_stream *czipio_entry_stream_writer(czipio_entry *const entry);
ssize_t czipio_entry_stream_fread(czipio_entry_stream *const handle, void *buffer, ssize_t size);
ssize_t czipio_entry_stream_fwrite(czipio_entry_stream *const handle, void *buffer, ssize_t size);
off_t czipio_entry_stream_fseek(czipio_entry_stream *const handle, off_t off, int whence);
int czipio_entry_stream_fclose(czipio_entry_stream *const handle);
size_t czipio_entry_stream_size(czipio_entry_stream *const handle);

#endif /* __HTIOFFICE_czipio_entry_H__ */
