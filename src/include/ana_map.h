#ifndef ANA_MAP_OBJECT_H
#define ANA_MAP_OBJECT_H

typedef struct _ana_map_bucket 
{
  uint64_t          keyhash;
  char             *key;
  char             *value;
  uint64_t          keylen;
  uint64_t          valuelen;
  struct _ana_map_bucket *next;
} ana_map_bucket;

typedef struct _ana_map 
{
  ana_map_bucket **buckets;
  size_t   size;
  size_t   capacity;
} ana_map;

ana_map *ana_map_new(size_t size);

int ana_map_put(
  ana_map *map, 
  char *key, 
  char *value,
  uint64_t keylen,
  uint64_t valuelen
);

char *ana_map_get(ana_map *map, char *key, uint64_t keylen, uint64_t *outlen);

#endif
