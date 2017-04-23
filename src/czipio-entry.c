#include <czipio-entry.h>
#include <czipio-cipher.h>

#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <errno.h>

#include <sys/stat.h>

struct czipio_entry_stream {
    const czipio_entry *reader;
    czipio_entry *writer;
    size_t offset;
};

struct czipio_entry {
    size_t size;
    uint8_t *content;
    char *name;
    /* Estructura de Lista */
    struct czipio_entry *first;
    struct czipio_entry *previous;
    struct czipio_entry *next;
    struct czipio_entry *last;
    /* Private */
    czipio_cipher *cipher_ctx;
};

struct mime_type {
    const char *extension;
    czipio_entry_mime_type type;
};

static const struct mime_type mime_types[] = {
      {".jpeg", JPEG_IMAGE}
    , {".jpg", JPEG_IMAGE}
    , {".mp3", MP3_AUDIO}
    , {".m4a", MP4_VIDEO}
    , {".mp4", MP4_VIDEO}
    , {".png", PNG_IMAGE}
    , {".tif", TIFF_IMAGE}
    , {".tiff", TIFF_IMAGE}
    , {".webm", WEBM_VIDEO}
};

uint8_t *
czipio_entry_content(const czipio_entry *const file)
{
    if (file == NULL)
        return NULL;
    return file->content;
}

czipio_cipher *
czipio_entry_cipher_context(const czipio_entry *const file)
{
    if (file == NULL)
        return NULL;
    return file->cipher_ctx;
}


size_t
czipio_entry_size(const czipio_entry *const file)
{
    if (file == NULL)
        return 0.0;
    return file->size;
}

void
czipio_entry_set_size(czipio_entry *file, size_t size)
{
    if (file == NULL)
        return;
    file->size = size;
}

czipio_entry *
czipio_entry_new(const char *const name)
{
    czipio_entry *entry;
    entry = malloc(sizeof(*entry));
    if (entry == NULL)
        return NULL;
    entry->name = strdup(name);
    entry->first = NULL;
    entry->previous = NULL;
    entry->next = NULL;
    entry->last = NULL;
    entry->cipher_ctx = NULL;
    entry->content = NULL;
    entry->size = 0;
    return entry;
}

void
czipio_entry_set_content(czipio_entry *file, uint8_t *const content, int32_t size)
{
    if (file == NULL)
        return;
    file->content = NULL;
    file->size = 0;
    if ((content == NULL) || (size == 0))
        return;
    file->content = malloc(size);
    if (file->content == NULL)
        return;
    file->size = size;

    memcpy(file->content, content, file->size);
}

czipio_entry *
czipio_entry_append_file(czipio_entry *list, czipio_entry *const file)
{
    if (file == NULL)
        return list;
    if (list == NULL) {
        list = file;
        list->first = file;
        list->last  = file;
    } else {
        czipio_entry *last;
        last = list->last;
        if (last != NULL) {
            file->previous = last;
            last->next = file;
        }
        list->last = file;
        file->first = list->first;
        file->last = list->last;
    }
    return list;
}


void
czipio_entry_free(czipio_entry *list)
{
    while (list != NULL) {
        czipio_entry *next;
        next = list->next;
        if (list->cipher_ctx != NULL)
            czipio_cipher_context_free(list->cipher_ctx);
        if (list->content != NULL)
            free(list->content);
        if (list->name != NULL)
            free(list->name);
        free(list);
        list = next;
    }
}

czipio_entry *
czipio_entry_next(czipio_entry *file)
{
    if (file == NULL)
        return NULL;
    return file->next;
}

const char *
czipio_entry_name(const czipio_entry *const file)
{
    if (file == NULL)
        return NULL;
    return file->name;
}

static int
czipio_mkdirs_helper(const char *const head, size_t length)
{
    char *path;
    struct stat st;
    path = malloc(length + 1);
    if (path == NULL)
        return -1;
    memcpy(path, head, length);
    path[length] = '\0';

    if ((stat(path, &st) == -1) && (mkdir(path, S_IRWXU) == -1))
        goto error;
    if (chdir(path) == -1)
        goto error;
    free(path);
    return 0;
error:
    free(path);
    return -1;
}

static int
czipio_mkdirs(const char *const path)
{
    const char *head;
    const char *tail;

    head = path;
    tail = strchr(head, '/');
    if (tail == NULL)
        return 0;
    while (tail != NULL) {
        ptrdiff_t length;
        length = tail - head + 1;
        if (length == 0)
            return -1;
        if (czipio_mkdirs_helper(head, length) == -1)
            return -1;
        head = tail + 1;
        tail = strchr(head, '/');
    }
    return 0;
}

int
czipio_entry_save(const czipio_entry *const file, const char *const path)
{
    int result;
    int fd;
    if (czipio_mkdirs(path) == -1)
        return -1;
    fd = open(path, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd == -1)
        return -1;
    result = 0;
    if (write(fd, file->content, file->size) != file->size)
        result = -1;
    close(fd);
    return result;
}

static int
czipio_entry_compare_mime_types(const void *const lhs, const void *const rhs)
{
    return strcmp(((struct mime_type *) lhs)->extension, ((struct mime_type *) rhs)->extension);
}

czipio_entry_mime_type
czipio_entry_getmime(const czipio_entry *const entry)
{
    size_t count;
    size_t size;
    struct mime_type *found;
    struct mime_type key;
    key.extension = strchr(entry->name, '.');
    if (key.extension == NULL)
        return UNKNOWN_MIME_TYPE;
    size = sizeof(key);
    count = sizeof(mime_types) / size;
    found = bsearch(&key, mime_types, count, size, czipio_entry_compare_mime_types);
    if (found == NULL)
        return UNKNOWN_MIME_TYPE;
    return found->type;
}

czipio_entry_stream *
czipio_entry_stream_reader(const czipio_entry *const entry)
{
    czipio_entry_stream *stream;
    stream = malloc(sizeof(*stream));
    if (stream == NULL)
        return NULL;
    stream->reader = entry;
    stream->writer = NULL;
    stream->offset = 0;
    return stream;
}

czipio_entry_stream *
czipio_entry_stream_writer(czipio_entry *const entry)
{
    czipio_entry_stream *stream;
    stream = malloc(sizeof(*stream));
    if (stream == NULL)
        return NULL;
    stream->reader = NULL;
    stream->writer = entry;
    stream->offset = 0;
    return stream;
}

ssize_t
czipio_entry_stream_fread(czipio_entry_stream *const stream, void *buffer, ssize_t size)
{
    const uint8_t *content;
    size_t copied;
    // Compute the size that can be copied
    copied = size;
    if (copied > czipio_entry_size(stream->reader) - stream->offset)
        copied = czipio_entry_size(stream->reader) - stream->offset;
    // Get a pointer to the content
    content = czipio_entry_content(stream->reader);
    // Copy the data to the buffer
    memcpy(buffer, content + stream->offset, copied);
    // Update the offset
    stream->offset += copied;
    return copied;
}

ssize_t
czipio_entry_stream_fwrite(czipio_entry_stream *const handle, void *buffer, ssize_t size)
{
    czipio_entry *entry;
    entry = handle->writer;
    if (size + handle->offset > entry->size) {
        void *content;
        content = realloc(entry->content, size + handle->offset);
        if (content == NULL)
            return -1L;
        entry->content = content;
    }
    memcpy(entry->content + handle->offset, buffer, size);
    handle->offset += size;
    entry->size += size;
    return size;
}

off_t
czipio_entry_stream_fseek(czipio_entry_stream *const handle, off_t off, int whence)
{
    czipio_entry_stream *stream;
    size_t size;
    stream = handle;
    size = czipio_entry_size(stream->reader);
    switch (whence) {
    case SEEK_CUR:
        if ((stream->offset + off >= size) || ((ssize_t) (stream->offset + off) < 0L))
            return -1;
        stream->offset += off;
        break;
    case SEEK_END:
        if ((ssize_t) (size - off - 1) < 0L)
            return -1;
        stream->offset = size - off - 1;
        break;
    case SEEK_SET:
        if (off >= size)
            return -1;
        stream->offset = off;
        break;
    }
    return stream->offset;
}

int
czipio_entry_stream_fclose(czipio_entry_stream *const handle)
{
    free(handle);
    return 0;
}

size_t
czipio_entry_stream_size(czipio_entry_stream *stream)
{
    return czipio_entry_size(stream->reader);
}
