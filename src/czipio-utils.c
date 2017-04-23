#include <czipio-utils.h>

#include <sys/stat.h>
#include <dirent.h>

#include <unistd.h>

#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <openssl/md5.h>

typedef struct czipio_dir
{
    char *root;
    struct dirent *entry;
    DIR *handle;
} czipio_dir;

typedef struct HTIDirStack
{
    czipio_dir **dirs;

    size_t size;
    size_t top;
} HTIDirStack;

char *
czipio_strdup(const char *const source)
{
    char *result;
    size_t length;
    length = strlen(source);
    result = malloc(length + 1);
    if (result == NULL)
        return NULL;
    memcpy(result, source, length + 1);
    return result;
}

static char *
czipio_strdup_vprintf(const char *const format, va_list args)
{
    char *result;
    size_t length;
    va_list copy;

    va_copy(copy, args);
    length = vsnprintf(NULL, 0, format, args);
    result = malloc(length + 1);
    if (result != NULL)
        vsprintf(result, format, copy);
    va_end(copy);
    return result;

}

char *
czipio_strdup_printf(const char *const format, ...)
{
    va_list args;
    char *result;
    va_start(args, format);
    result = czipio_strdup_vprintf(format, args);
    va_end(args);
    return result;
}

static czipio_dir *
czipio_opendir(const char *const path)
{
    czipio_dir *dir;
    dir = malloc(sizeof(*dir));
    if (dir == NULL)
        return NULL;
    dir->root = czipio_strdup(path);
    if (dir->root == NULL)
        goto error;
    dir->handle = opendir(path);
    if (dir->handle != NULL)
        return dir;
error:
    free(dir->root);
    free(dir);
    return NULL;
}

static HTIDirStack *
czipio_dirstack_new()
{
    HTIDirStack *stack;
    stack = malloc(sizeof(*stack));
    if (stack == NULL)
        return NULL;
    stack->dirs = malloc(0x100 * sizeof(*stack->dirs));
    if (stack->dirs != NULL)
        stack->size = 0x100;
    else
        stack->size = 0;
    stack->top = 0;
    return stack;
}

static int
czipio_dirstack_resize(HTIDirStack *stack)
{
    void *pointer;
    if (stack->size > stack->top + 1)
        return 0;
    pointer = realloc(stack->dirs, (stack->size + 0x100) * sizeof(*stack->dirs));
    if (pointer == NULL)
        return -1;
    stack->dirs = pointer;
    stack->size += 0x100;
    return 0;
}

static int
czipio_dirstack_push(HTIDirStack *stack, const char *const path)
{
    if (czipio_dirstack_resize(stack) == -1)
        return -1;
    stack->dirs[stack->top] = czipio_opendir(path);
    if (stack->dirs[stack->top] == NULL)
        return -1;
    stack->top += 1;
    return 0;
}

static void
czipio_dirstack_pop(HTIDirStack *stack)
{
    czipio_dir *dir;
    size_t index;

    index = stack->top - 1;
    dir = stack->dirs[stack->top - 1];
    if (dir == NULL)
        return;
    closedir(dir->handle);
    free(dir->root);
    free(dir);

    stack->dirs[index] = NULL;
    stack->top -= 1;
}

static bool
czipio_dirstack_is_empty(HTIDirStack *stack)
{
    return (stack->top == 0);
}

static void
czipio_dirstack_clear(HTIDirStack *stack)
{
    while (czipio_dirstack_is_empty(stack) == false)
        czipio_dirstack_pop(stack);
    free(stack->dirs);
    free(stack);
}

static czipio_dir *
czipio_dirstack_top(HTIDirStack *stack)
{
    if (stack->top == 0)
        return NULL;
    return stack->dirs[stack->top - 1];
}

static int
czipio_directory_walk_visit_directory(czipio_dir *dir, czipio_dir_visitor visit, void *data)
{
    int result;
    struct dirent *entry;
    const char *name;

    if (dir == NULL)
        return -1;

    entry = dir->entry;
    name = entry->d_name;
    result = visit(dir->root, name, S_IFDIR, data);

    return result;
}

int
czipio_directory_walk(const char *const path, czipio_dir_visitor visit, void *data)
{
    HTIDirStack *context;
    struct dirent *entry;
    context = czipio_dirstack_new();
    if (context == NULL)
        return -1;
    if (czipio_dirstack_push(context, path) == -1)
        goto error;
    while (czipio_dirstack_is_empty(context) == false)
    {
        czipio_dir *dir;
        int result;
        dir = czipio_dirstack_top(context);
        while (((entry = readdir(dir->handle)) != NULL) && (entry != NULL))
        {
            struct stat st;
            const char *name;
            char *childpath;

            dir->entry = entry;

            name = entry->d_name;
            if ((strcmp(name, ".") == 0) || (strcmp(name, "..") == 0))
                continue;
            childpath = czipio_strdup_printf("%s/%s", dir->root, name);
            if (childpath == NULL)
                continue; // Raro, habrá que notificarlo de alguna manera
            if (stat(childpath, &st) == -1)
                goto impossible;
            if (S_ISDIR(st.st_mode) != 0)
                czipio_dirstack_push(context, childpath);
            else
                result = visit(dir->root, name, st.st_mode, data);
            dir = czipio_dirstack_top(context);
        impossible:
            free(childpath);
            if (result == -1)
                goto error;
        }
        czipio_dirstack_pop(context);

        dir = czipio_dirstack_top(context);
        if (czipio_directory_walk_visit_directory(dir, visit, data) == -1)
            goto error;
    }
error:
    czipio_dirstack_clear(context);
    return 0;
}

const uint8_t *
czipio_sha256digest(const uint8_t *const entrada, size_t length)
{
    static uint8_t digest[SHA256_DIGEST_LENGTH];
    SHA256(entrada, length, digest);
    return digest;
}

uint8_t *
czipio_pbkdf2_hmac(const char *const password, const uint8_t *const salt, int iterations, int keylen)
{
    uint8_t *key;
    const char *digest;
    size_t saltlen;
    key = malloc(keylen);
    if (key == NULL)
        return NULL;
    digest = (const char *) czipio_sha256digest((const uint8_t *)
        password, strlen(password));
    saltlen = strlen((const char *) salt);
    PKCS5_PBKDF2_HMAC_SHA1(digest, SHA256_DIGEST_LENGTH,
        salt, saltlen, iterations, keylen, key);
    return key;
}

bool
czipio_file_exists(const char *const path)
{
    struct stat st;
    if (stat(path, &st) == -1)
        return 0;
    return S_ISREG(st.st_mode);
}

bool
czipio_directory_exists(const char *const path)
{
    struct stat st;
    if (stat(path, &st) == -1)
        return 0;
    return S_ISDIR(st.st_mode);
}

static int
czipio_remove_directory_visitor(const char *const path, const char *const name, mode_t mode, void *data)
{
    char *fullpath;

    fullpath = czipio_strdup_printf("%s/%s", path, name);
    if (fullpath == NULL)
        return -1;
    if (S_ISDIR(mode) == 0)
        unlink(fullpath);
    else
        rmdir(fullpath);
    free(fullpath);
    return 0;
}

void
czipio_remove_directory(const char *const path)
{
    if (czipio_directory_exists(path) == false)
        return;
    czipio_directory_walk(path, czipio_remove_directory_visitor, NULL);
    rmdir(path);
}

bool
czipio_check_md5_digest(const char *const md5sum, const uint8_t *const content, size_t length)
{
    uint8_t digest[MD5_DIGEST_LENGTH];
    MD5_CTX context;
    char string[2 * MD5_DIGEST_LENGTH + 1];

    MD5_Init(&context);
    MD5_Update(&context, content, length);
    MD5_Final(digest, &context);

    for (uint8_t i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        snprintf(&string[2 * i], 3, "%02x", digest[i]);
    }
    string[2 * MD5_DIGEST_LENGTH] = 0;

    return strcmp(md5sum, string) == 0;
}
