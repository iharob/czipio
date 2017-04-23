#include <czipio.h>
#include <czipio-cipher.h>
#include <czipio-entry.h>
#include <czipio-utils.h>

#include <openssl/evp.h>
#include <sys/stat.h>

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include <errno.h>

#include <zlib.h>

#include <ctype.h>

#define CENTRAL_DIRECTORY_HEADER_SIGNATURE 0x02014b50
#define LOCAL_FILE_HEADER_SIGNATURE 0x04034b50
#define END_CENTRAL_DIRECTORY_SIGNATURE 0x06054b50
#define CHUNK_SIZE 0x40000

typedef int (*htioffice_progress_function)(const char *const, float);

#define ZLIB_COMPRESS_DECOMPRESS(type, level)                                   \
static void *                                                                   \
czipio_##type(czipio_decomp_read getchunk, czipio_decomp *const decomp)         \
{                                                                               \
    return czipio_get_chunk(                                                    \
        getchunk,                                                               \
        decomp,                                                                 \
        czipio_##type##_initialize,                                             \
        type##End,                                                              \
        level,                                                                  \
        type                                                                    \
    );                                                                          \
}                                                                               \
static uint8_t *                                                                \
czipio_##type##_buffer(const uint8_t *buffer, int32_t *size)                    \
{                                                                               \
    czipio_decomp decomp;                                                       \
    uint8_t *result;                                                            \
                                                                                \
    decomp.object = (uint8_t *) buffer;                                         \
    decomp.offset = 0;                                                          \
    decomp.size = *size;                                                        \
    decomp.direction = (strcmp(#type, "inflate") == 0) ? Uncompress : Compress; \
                                                                                \
    result = czipio_##type(czipio_buffer_decomp_get_chunk, &decomp);            \
    *size = decomp.size;                                                        \
                                                                                \
    return result;                                                              \
}                                                                               \
static uint8_t *                                                                \
czipio_##type##_stream(FILE *stream, int32_t size, int32_t *totalsize)          \
{                                                                               \
    czipio_decomp decomp;                                                       \
    uint8_t *buffer;                                                            \
                                                                                \
    decomp.object = stream;                                                     \
    decomp.offset = ftell(stream);                                              \
    decomp.size = size;                                                         \
    decomp.direction = (strcmp(#type, "inflate") == 0) ? Uncompress : Compress; \
    buffer = czipio_##type(czipio_stream_decomp_get_chunk, &decomp);            \
    *totalsize = decomp.size;                                                   \
                                                                                \
    return buffer;                                                              \
}

typedef struct czipio_stream
{
    uint8_t *data;
    size_t size;
    size_t capacity;
} czipio_stream;

typedef enum czipio_decomp_direction {
    Compress,
    Uncompress
} czipio_decomp_direction;

typedef struct czipio_decomp
{
    void *object;
    size_t offset;
    size_t size;
    czipio_decomp_direction direction;
} czipio_decomp;

typedef struct czipio_decomp_context
{
    void *data;
    size_t size;
} czipio_decomp_context;
typedef int (*czipio_decomp_read)(czipio_decomp_context *const, size_t, czipio_decomp *const);

typedef enum compression_methods
{
    Stored, // The file is stored (no compression)
    Shrunk, // The file is Shrunk
    ReducedX1, // The file is Reduced with compression factor 1
    ReducedX2, // The file is Reduced with compression factor 2
    ReducedX3, // The file is Reduced with compression factor 3
    ReducedX4, // The file is Reduced with compression factor 4
    Imploded, // The file is Imploded
    Tokenized, // Reserved for Tokenizing compression algorithm
    Deflated, // The file is Deflated
    EnhancedDeflated, // Enhanced Deflating using Deflate64(tm)
    PKWAREImploded, // PKWARE Data Compression Library Imploding (old IBM TERSE)
    Reserved01, // Reserved by PKWARE
    Bzip2, // File is compressed using BZIP2 algorithm
    Reserved02, // Reserved by PKWARE
    LZMA, // LZMA (EFS)
    Reserved03, // Reserved by PKWARE
    Reserved04, // Reserved by PKWARE
    Reserved05, // Reserved by PKWARE
    TerseIBM, // File is compressed using IBM TERSE (new)
    IBMLZ777, // IBM LZ77 z Architecture (PFS)
    WavPack, // WavPack compressed data
    PPMdvI // PPMd version I, Rev 1
} compression_methods;

typedef struct __attribute__((packed)) local_file_header
{
    int32_t signature;
    int16_t version;
    int16_t flag;
    int16_t compression_method;
    int16_t last_modification_time;
    int16_t last_modification_date;
    int32_t crc32;
    int32_t compressed_size;
    int32_t uncompressed_size;
    int16_t name_length;
    int16_t extra_field_length;
} local_file_header;

typedef struct __attribute__((packed)) central_directory_header
{
    int32_t signature;
    int16_t creator_version;
    int16_t version;
    int16_t flag;
    int16_t compression_method;
    int16_t last_modification_time;
    int16_t last_modification_date;
    int32_t crc32;
    int32_t compressed_size;
    int32_t uncompressed_size;
    int16_t name_length;
    int16_t extra_field_length;
    int16_t comment_length;
    int16_t file_initial_disk_number;
    int16_t file_internal_attributes;
    int32_t file_external_attributes;
    int32_t local_file_header_offset;
} central_directory_header;

typedef struct __attribute__((packed)) data_descriptor
{
    int32_t crc32;
    int32_t compressed_length;
    int32_t uncompressed_length;
} data_descriptor;

typedef struct __attribute__((packed)) end_central_directory
{
    int32_t signature;
    int16_t disk_number;
    int16_t central_directory_number;
    int16_t disk_central_directory_record_count;
    int16_t central_directory_record_count;
    int32_t central_directory_length;
    int32_t central_directory_offset;
    int16_t comment_length;
} end_central_directory;

typedef enum FileMode
{
    ReadOnly,
    WriteOnly
} FileMode;

typedef struct czipio_file
{
    czipio_entry *files;
    char *root;
    FileMode mode;
    char *target;
    size_t strip_from_path;
} czipio_file;

static uint8_t *czipio_inflate_buffer(const uint8_t *buffer, int32_t *);
static uint8_t *czipio_inflate_stream(FILE *stream, int32_t size, int32_t *);
static uint8_t *czipio_deflate_buffer(const uint8_t *buffer, int32_t *);
static uint8_t *czipio_deflate_stream(FILE *stream, int32_t size, int32_t *);
static char *czipio_read_srting(FILE *file, size_t length);
static end_central_directory czipio_read_central_directory_end(FILE *file);
static uint8_t *czipio_read_content(FILE *archivo, central_directory_header *central_directory, int32_t *size);
static czipio_entry *czipio_extract_file(FILE *file, central_directory_header *header);
static czipio_file *czipio_read_central_directory(FILE *file);
static char *czipio_read_srting(FILE *file, size_t longitud);
static end_central_directory czipio_read_central_directory_end(FILE *file);

static int
czipio_inflate_initialize(z_stream *zstream, int level)
{
    return inflateInit2(zstream, level);
}

static int
czipio_deflate_initialize(z_stream *zstream, int level)
{
    return deflateInit(zstream, level);
}


static void
czipio_zstream_initialize(z_stream *zstream)
{
    zstream->zalloc = Z_NULL;
    zstream->zfree = Z_NULL;
    zstream->opaque = Z_NULL;
}

static void
czipio_stream_initialize(czipio_stream *stream)
{
    stream->size = 0;
    stream->data = malloc(CHUNK_SIZE);
    if (stream->data == NULL) {
        stream->capacity = 0;
    } else {
        stream->capacity = CHUNK_SIZE;
    }
}

static void
czipio_stream_write(czipio_stream *stream, void *data, size_t size)
{
    if ((data == NULL) || (size == 0))
        return;
    if ((stream->capacity < stream->size + size) || (stream->data == NULL)) {
        void *buffer;
        if (size < CHUNK_SIZE) {
            size = CHUNK_SIZE;
        } else {
            size = (size / CHUNK_SIZE + 1) * CHUNK_SIZE;
        }
        buffer = realloc(stream->data, stream->size + size);
        if (buffer == NULL)
            return;
        stream->data = buffer;
        stream->capacity = stream->size + size;
    }
    memcpy(stream->data + stream->size, data, size);
    stream->size += size;
}

static void
czipio_stream_close(czipio_stream *const stream)
{
    void *pointer;
    pointer = realloc(stream->data, stream->size + 1);
    if (pointer == NULL)
        return;
    stream->data = pointer;
    stream->data[stream->size] = '\0';
    stream->capacity = stream->size + 1;
}

static void
czipio_stream_terminate(czipio_stream *const stream)
{
    free(stream->data);

    stream->data = NULL;
    stream->capacity = 0;
    stream->size = 0;
}

static bool
czipio_decomp_done(int status, int flush, size_t available, czipio_decomp *decomp)
{
    bool result;
    result = true;
    switch (decomp->direction) {
    case Compress:
        result = (flush == Z_FINISH);
        break;
    case Uncompress:
        result = ((available <= 0) || (status == Z_STREAM_END));
        break;
    }
    return result;
}

static void *
czipio_get_chunk(czipio_decomp_read getchunk,
                 czipio_decomp *const decomp,
                 int (*initialize)(z_stream *, int),
                 int (*end)(z_stream *),
                 int level,
                 int (*io)(z_stream *, int))
{
    int status;
    int flush;
    z_stream zstream;
    czipio_decomp_context context;
    czipio_stream stream;
    size_t available;
    size_t finalsize;
    size_t offset;

    czipio_zstream_initialize(&zstream);
    czipio_stream_initialize(&stream);

    if (initialize(&zstream, level) != Z_OK)
        return NULL;
    finalsize = 0;
    offset = 0;
    do {
        uint8_t input[CHUNK_SIZE];
        size_t have;
        context.data = input;
        context.size = sizeof(input);
        if ((flush = getchunk(&context, offset, decomp)) == -1)
            goto abort;
        zstream.next_in = context.data;
        zstream.avail_in = context.size;
        do {
            uint8_t output[CHUNK_SIZE];
            zstream.avail_out = sizeof(output);
            zstream.next_out = output;
            status = io(&zstream, flush);
            switch (status) {
            case Z_NEED_DICT:
                goto abort;
            case Z_DATA_ERROR:
                goto abort;
            case Z_MEM_ERROR:
                goto abort;
            }
            have = CHUNK_SIZE - zstream.avail_out;
            finalsize += have;
            offset += zstream.avail_in;
            czipio_stream_write(&stream, output, have);
        } while (zstream.avail_out == 0);
        available = zstream.avail_in;
    } while (czipio_decomp_done(status, flush, available, decomp) == false);
    decomp->size = finalsize;
    czipio_stream_close(&stream);

    end(&zstream);

    return stream.data;

abort:
    czipio_stream_terminate(&stream);
    end(&zstream);

    return NULL;
}

static char *
czipio_read_srting(FILE *file, size_t length)
{
    char *string;
    string = NULL;
    if ((file == NULL) || (feof(file) == 1))
        goto abort;
    string = malloc(length + 1);
    if (string == NULL)
        goto abort;
    if (fread(string, 1, length, file) != length)
        goto abort;
    string[length] = '\0';
    return string;
abort:
    if (string != NULL)
        free(string);
    return NULL;
}

uint8_t *
czipio_uncipher(czipio_entry *file, int32_t *size)
{
    uint8_t *unciphered;
    uint8_t *result;
    const czipio_cipher *cifrado;
    EVP_CIPHER_CTX *ctx;
    int result_length;
    const uint8_t *content;
    size_t file_size;

    content = czipio_entry_content(file);
    file_size = czipio_entry_size(file);
    if ((file == NULL) || (content == NULL))
        return NULL;
    cifrado = czipio_entry_cipher_context(file);
    if (cifrado != NULL) {
        czipio_cipher *context;
        const uint8_t *content;
        const uint8_t *key;
        const uint8_t *init_vector;

        content = czipio_entry_content(file);
        context = czipio_entry_cipher_context(file);
        key = czipio_cipher_context_key(context);
        init_vector = czipio_cipher_context_initialization_vector(context);

        ctx = EVP_CIPHER_CTX_new();
        if (ctx == NULL)
            return NULL;
        EVP_DecryptInit(ctx, EVP_aes_256_cbc(), key, init_vector);
        unciphered = malloc(file_size);
        if (unciphered == NULL) {
            EVP_CIPHER_CTX_free(ctx);
            return NULL;
        }
        EVP_DecryptUpdate(ctx, unciphered, &result_length, content, file_size);
        EVP_CIPHER_CTX_free(ctx);

        result = czipio_inflate_buffer(unciphered, size);
        free(unciphered);
    } else {
        result = malloc(1 + file_size);
        if (result == NULL)
            return NULL;
        memcpy(result, content, 1 + file_size);
    }

    return result;
}

static int
czipio_buffer_decomp_get_chunk(czipio_decomp_context *const context,
    size_t offset, czipio_decomp *const decomp)
{
    int result;
    context->data = (void *) (decomp->object + offset);
    context->size = decomp->size - offset;
    if (decomp->direction == Uncompress) {
        result = Z_NO_FLUSH;
    } else {
        result = (decomp->size <= context->size) ? Z_FINISH : Z_NO_FLUSH;
    }
    return result;
}

static int
czipio_stream_decomp_get_chunk(czipio_decomp_context *const context,
    size_t offset, czipio_decomp *const decomp)
{
    size_t size;
    int result;
    if (fseek(decomp->object, decomp->offset + offset, SEEK_SET) != 0)
        return -1;
    size = decomp->size - offset;
    if (size > context->size)
        size = context->size;
    context->size = fread(context->data, 1, size, decomp->object);
    if (decomp->direction == Uncompress) {
        result = Z_NO_FLUSH;
    } else {
        result = (feof(decomp->object) != 0) ? Z_FINISH : Z_NO_FLUSH;
    }
    return result;
}

ZLIB_COMPRESS_DECOMPRESS(inflate, -MAX_WBITS)
ZLIB_COMPRESS_DECOMPRESS(deflate, Z_DEFAULT_COMPRESSION)

static uint8_t *
czipio_read_content(FILE *file, central_directory_header *central_directory, int32_t *size)
{
    uint8_t *content;
    local_file_header header;
    size_t uncompressed;
    size_t position;

    content = NULL;
    if ((file == NULL) || (central_directory == NULL))
        return NULL;
    position = ftell(file);

    fseek(file, central_directory->local_file_header_offset, SEEK_SET);
    if (fread(&header, sizeof(local_file_header), 1, file) != 1)
        goto abort;
    fseek(file, header.name_length, SEEK_CUR);
    fseek(file, header.extra_field_length, SEEK_CUR);

    uncompressed = central_directory->uncompressed_size;
    switch (header.compression_method) {
    case Stored:
        if (uncompressed != (size_t) central_directory->compressed_size)
            goto abort;
        content = malloc(uncompressed + 1);
        if (content == NULL)
            goto abort;
        if (fread(content, 1, uncompressed, file) != uncompressed)
            goto abort;
        *size = uncompressed;
        content[uncompressed] = '\0';
        break;
    case Deflated:
        content = czipio_inflate_stream(file, central_directory->compressed_size, size);
        break;
    default:
        break;
    }
    fseek(file, position, SEEK_SET);

    return content;
abort:
    fseek(file, position, SEEK_SET);
    if (content != NULL)
        free(content);
    return NULL;
}

static end_central_directory
czipio_read_central_directory_end(FILE *file)
{
    end_central_directory eocd;
    memset(&eocd, 0, sizeof(eocd));
    fseek(file, -sizeof(eocd), SEEK_END);
    if (fread(&eocd, sizeof(eocd), 1, file) != 1)
        fprintf(stderr, "Advertencia: archivo zip mal formado.\n");
    return eocd;
}

static czipio_entry *
czipio_extract_file(FILE *stream, central_directory_header *header)
{
    czipio_entry *file;
    char *name;
    if ((stream == NULL) || (header == NULL))
        return NULL;
    name = czipio_read_srting(stream, header->name_length);
    if (name == NULL)
        return NULL;
    file = czipio_entry_new(name);
    if (file != NULL) {
        uint8_t *content;
        int32_t size;

        fseek(stream, header->extra_field_length, SEEK_CUR);
        fseek(stream, header->comment_length, SEEK_CUR);

        free(name);

        content = czipio_read_content(stream, header, &size);
        if (content != NULL) {
            czipio_entry_set_content(file, content, size);
        } else {
            czipio_entry_set_content(file, NULL, 0);
        }
        free(content);
    }

    return file;
}

static czipio_file *
czipio_read_central_directory(FILE *stream)
{
    czipio_file *zip;
    end_central_directory eocd;
    central_directory_header cdh;
    local_file_header header;
    size_t length;

    fread(&header, sizeof(header), 1, stream);
    (void) header; // TODO: checkear integridad

    eocd = czipio_read_central_directory_end(stream);
    zip = malloc(sizeof(*zip));
    if (zip == NULL)
        return NULL;
    length = sizeof(cdh);

    zip->files = NULL;
    zip->mode = ReadOnly;
    zip->target = NULL;
    zip->root = NULL;
    zip->strip_from_path = 0;

    fseek(stream, eocd.central_directory_offset, SEEK_SET);
    while (fread(&cdh, length, 1, stream) == 1) {
        czipio_entry *file;
        file = czipio_extract_file(stream, &cdh);
        if (file == NULL)
            continue;
        zip->files = czipio_entry_append_file(zip->files, file);
    }
    return zip;
}

czipio_file *
czipio_open(const char *const path)
{
    czipio_file *zip;
    FILE *file;

    if (czipio_file_exists(path) == 0)
        return NULL;
    file = fopen(path, "r");
    if (file == NULL)
        return NULL;
    zip = czipio_read_central_directory(file);

    fclose(file);
    return zip;
}

const czipio_entry *
czipio_find(const czipio_file *const zip, const char *const which)
{
    czipio_entry *file;
    for (file = zip->files; file != NULL; file = czipio_entry_next(file)) {
        const char *name;
        name = czipio_entry_name(file);
        if (strcmp(name, which) != 0)
            continue;
        return file;
    }
    return NULL;
}

void
czipio_list(const czipio_file *const zip, int indent)
{
    czipio_entry *file;
    for (file = zip->files; file != NULL; file = czipio_entry_next(file)) {
        const char *name;
        name = czipio_entry_name(file);
        if (name == NULL)
            continue;
        fprintf(stderr, "%*s%s\n", indent, " ", name);
    }
}

static int
czipio_append_file_absolute_path(czipio_file *zip, const char *const path)
{
    FILE *file;
    czipio_entry *htifile;
    struct stat st;

    if (stat(path, &st) == -1)
        return -1;
    file = fopen(path, "r");
    if (file == NULL)
        return -1;
    htifile = czipio_entry_new(path + zip->strip_from_path + 1);
    if (htifile != NULL) {
        unsigned char *content;
        content = malloc(st.st_size);
        if (content == NULL)
            goto error;
        czipio_entry_set_size(htifile, st.st_size);
        if (fread(content, 1, st.st_size, file) == st.st_size)
            czipio_entry_set_content(htifile, content, st.st_size);
        else
            czipio_entry_set_content(htifile, NULL, st.st_size);
        zip->files = czipio_entry_append_file(zip->files, htifile);
        free(content);
    }
error:
    if (file != NULL)
        fclose(file);
    return 0;
}

static void
czipio_append_file_relative(czipio_file *zip, const char *const name)
{
    char *path;
    path = czipio_strdup_printf("%s/%s", zip->root, name);
    if (path == NULL)
        return;
    czipio_append_file_absolute_path(zip, path);
    free(path);
}

void
czipio_append_file(czipio_file *zip, const char *const name)
{
    czipio_append_file_relative(zip, name);
}

static int
czipio_creator_directory_visitor(const char *const directory,
    const char *const name, mode_t mode, void *data)
{
    char *path;
    if (S_ISDIR(mode) != 0)
        return 0;
    path = czipio_strdup_printf("%s/%s", directory, name);
    if (path == NULL)
        return -1;
    czipio_append_file_absolute_path(data, path);
    free(path);
    return 0;
}

void
czipio_append_directory(czipio_file *zip, const char *const root)
{
    char *path;
    path = czipio_strdup_printf("%s/%s", zip->root, root);
    if (path == NULL)
        return;
    czipio_directory_walk(path, czipio_creator_directory_visitor, zip);
    free(path);
}

static void
czipio_write_helper(const czipio_file *const zip)
{
    uint8_t *deflated;
    end_central_directory eocd;
    central_directory_header *cdhs;
    size_t count;
    czipio_entry *file;
    FILE *stream;
    int16_t method;

    stream = fopen(zip->target, "wb");
    if (stream == NULL)
        return;
    memset(&eocd, 0, sizeof(eocd));
    for (file = zip->files, count = 0; file != NULL; file = czipio_entry_next(file))
        count += 1;
    cdhs = malloc(count * sizeof(*cdhs));
    if (cdhs == NULL)
        goto failed;
    memset(&eocd, 0, sizeof(eocd));

    eocd.signature = END_CENTRAL_DIRECTORY_SIGNATURE;
    eocd.central_directory_number = 0;
    eocd.central_directory_offset = 0;
    eocd.central_directory_length = count * sizeof(*cdhs);
    eocd.central_directory_record_count = count;

    // TODO: deflate, no vale la pena por ahora.
    method = (int16_t) Stored;

    deflated = NULL;
    for (file = zip->files, count = 0; file != NULL; file = czipio_entry_next(file), ++count) {
        uint8_t *content;
        local_file_header header;
        int32_t uncompressed_size;
        int32_t compressed_size;
        int32_t name_length;
        uLong crc;
        const char *name;

        memset(&cdhs[count], 0, sizeof(*cdhs));
        memset(&header, 0, sizeof(header));

        content = czipio_entry_content(file);
        name = czipio_entry_name(file);
        uncompressed_size = czipio_entry_size(file);
        compressed_size = uncompressed_size;
        if (content == NULL)
            goto failed;
        deflated = malloc(compressed_size);//czipio_deflate_buffer(content, &compressed_size);
        if (deflated == NULL)
            goto failed;
        memcpy(deflated, content, compressed_size);
        if (name == NULL)
            goto failed;
        name_length = strlen(name);
        crc = crc32(0L, content, uncompressed_size);

        header.version = 0x10;
        header.signature = LOCAL_FILE_HEADER_SIGNATURE;
        header.compression_method = method;
        header.name_length = name_length;
        header.crc32 = (int32_t) crc;
        header.compressed_size = compressed_size;
        header.uncompressed_size = uncompressed_size;

        cdhs[count].version = 0x10;
        cdhs[count].signature = CENTRAL_DIRECTORY_HEADER_SIGNATURE;
        cdhs[count].compression_method = method;
        cdhs[count].name_length = name_length;
        cdhs[count].crc32 = (int32_t) crc;
        cdhs[count].compressed_size = compressed_size;
        cdhs[count].uncompressed_size = uncompressed_size;
        cdhs[count].local_file_header_offset = ftell(stream);

        eocd.central_directory_length += name_length;
        if (fwrite(&header, sizeof(header), 1, stream) != 1)
            goto failed;
        if (fwrite(name, 1, name_length, stream) != name_length)
            goto failed;
        if (fwrite(deflated, 1, compressed_size, stream) != compressed_size)
            goto failed;
        free(deflated);
    }
    eocd.central_directory_offset = ftell(stream);

    for (file = zip->files, count = 0; file != NULL; file = czipio_entry_next(file), ++count) {
        size_t length;
        central_directory_header *directory;
        const char *name;
        name = czipio_entry_name(file);
        if (name == NULL)
            goto failed;
        directory = &cdhs[count];
        if (fwrite(directory, sizeof(*directory), 1, stream) != 1)
            goto failed;
        length = directory->name_length;
        if (fwrite(name, 1, length, stream) != length)
            goto failed;
    }
    fwrite(&eocd, sizeof(eocd), 1, stream);
    fclose(stream);

    free(cdhs);
    return;
failed:
    fclose(stream);
    free(cdhs);

    unlink(zip->target);
    free(deflated);
}

void
czipio_close(czipio_file *zip)
{
    if (zip == NULL)
        return;

    if (zip->mode == WriteOnly)
        czipio_write_helper(zip);
    czipio_entry_free(zip->files);

    free(zip->target);
    free(zip->root);
    free(zip);
}

czipio_file *
czipio_create(const char *const root)
{
    char *target;
    czipio_file *zip;
    FILE *file;
    target = czipio_strdup_printf("%s.zip", root);
    if (target == NULL)
        return NULL;
    file = fopen(target, "w");
    if (file == NULL)
        goto error;
    zip = malloc(sizeof(*zip));
    if (zip == NULL)
        goto error;
    zip->files = NULL;
    zip->mode = WriteOnly;
    zip->target = target;
    zip->root = czipio_strdup(root);
    zip->strip_from_path = strlen(zip->root);

    fclose(file);
    return zip;
error:
    fprintf(stderr, "%d: %s\n", errno, strerror(errno));
    free(target);
    if (file != NULL) {
        fclose(file);
        unlink(root);
    }

    return NULL;
}
