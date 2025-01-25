#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "sha256.h"

#define HASHMAP_INITIAL_CAPACITY 4

struct provider {
    int somedata;
};

struct provider *provider_new()
{
    struct provider *p = (struct provider *)malloc(sizeof(struct provider));
    if (p) {
        p->somedata = 123;
    }
    return p;
}

void provider_free(struct provider *provider) { free(provider); }

struct provider_hashmap {
    struct provider **arr;
    size_t capacity;
    size_t len;
};

struct provider_hashmap *hashmap_new()
{
    struct provider_hashmap *hashmap =
        (struct provider_hashmap *)malloc(sizeof(struct provider_hashmap));
    if (hashmap) {
        hashmap->arr = (struct provider **)malloc(sizeof(struct provider *) *
                                                  HASHMAP_INITIAL_CAPACITY);
        if (!hashmap->arr) {
            free(hashmap);
            return NULL;
        }
        hashmap->capacity = HASHMAP_INITIAL_CAPACITY;
        for (size_t i = 0; i < hashmap->capacity; i++)
            hashmap->arr[i] = NULL;
        hashmap->len = 0;
    }
    return hashmap;
}

void hashmap_free(struct provider_hashmap *hashmap)
{
    for (size_t i = 0; i < hashmap->capacity; i++) {
        if (hashmap->arr[i]) {
            printf("freeing %p\n", hashmap->arr[i]);
            provider_free(hashmap->arr[i]);
        }
    }
    free(hashmap->arr);
    free(hashmap);
}

int mod(unsigned char *hash, int divisor)
{
    int res = 0;
    for (size_t i = 0; i < SHA256_BLOCK_SIZE; i++)
        res = (res * 256 + hash[i]) % divisor;
    return res;
}

void sha256hash(unsigned char *token, unsigned char *hashed, size_t tokenlen)
{
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, (unsigned char *)token, tokenlen);
    sha256_final(&ctx, hashed);
}

int get_idx(struct provider_hashmap *hashmap, const char *token,
            size_t tokenlen)
{
    unsigned char hashed[SHA256_BLOCK_SIZE];
    sha256hash((unsigned char *)token, hashed, tokenlen);
    return mod(hashed, hashmap->capacity);
}

// hashmap takes ownership of provider ptr
void hashmap_insert(struct provider_hashmap *hashmap, struct provider *p,
                    const char *token, size_t tokenlen)
{
    if (hashmap->capacity == hashmap->len) {
        // handle reallocations
        printf("reallocating\n");
        size_t prev = hashmap->capacity;
        hashmap->capacity += HASHMAP_INITIAL_CAPACITY * 2;
        struct provider **newarr = (struct provider **)realloc(
            hashmap->arr, sizeof(struct provider *) * hashmap->capacity);
        for (size_t i = prev; i < hashmap->capacity; i++)
            newarr[i] = NULL;
        hashmap->arr = newarr;
    }

    int m = get_idx(hashmap, token, tokenlen);
    if (hashmap->arr[m]) {
        printf("collision occured at m %d\n", m);
        return;
    }

    printf("inserting %p at m: %d\n", p, m);
    hashmap->arr[m] = p;
    hashmap->len++;
}

void hashmap_del(struct provider_hashmap *hashmap, const char *token,
                 size_t tokenlen)
{
    int m = get_idx(hashmap, token, tokenlen);
    printf("deleting %p\n", hashmap->arr[m]);
    provider_free(hashmap->arr[m]);
    hashmap->arr[m] = NULL;
    hashmap->len--;
}

int main()
{
    struct provider_hashmap *hashmap = hashmap_new();
    hashmap_insert(hashmap, provider_new(), "test", 4);
    hashmap_insert(hashmap, provider_new(), "tes3", 4);
    hashmap_insert(hashmap, provider_new(), "abcd", 4);
    hashmap_insert(hashmap, provider_new(), "abce", 4);
    hashmap_insert(hashmap, provider_new(), "abca", 4);
    hashmap_insert(hashmap, provider_new(), "2bca", 4);
    hashmap_insert(hashmap, provider_new(), "7bca", 4);
    hashmap_insert(hashmap, provider_new(), "8bca", 4);
    hashmap_insert(hashmap, provider_new(), "9bca", 4);
    hashmap_free(hashmap);
    return 0;
}
