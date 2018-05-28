#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "ana_server.h"

static inline uint64_t hashlen(unsigned char *str, size_t size)
{
  uint64_t hash = 5381;
  int c;
  size_t i = 0;

  while((c = *str++) && i++ < size) {
    hash = ((hash << 5) + hash) + c;
  }

  return hash;
}


static inline int do_resize(ana_map *map)
{
  size_t newcap = map->capacity * 2;
  ana_map_bucket **newbuckets = malloc(sizeof(ana_map_bucket *) * newcap);

  if(!newbuckets)
    return 1;

  size_t i;

  for(i = 0; i < newcap; i++)
    newbuckets[i] = NULL;
  
  for(i = 0; i < map->capacity; i++) 
  {
    ana_map_bucket *b = map->buckets[i];
    
    while(b)
    {
      ana_map_bucket *next = b->next;

      uint64_t newidx = hashlen((unsigned char *)b->key, b->keylen) % newcap;
      
      ana_map_bucket *bucket = malloc(sizeof(*bucket));

      if(!bucket)
        return 1;

      bucket->key = b->key;
      bucket->value = b->value;
      bucket->keylen = b->keylen;
      bucket->valuelen = b->valuelen;
      bucket->next = newbuckets[newidx];

      newbuckets[newidx] = bucket;

      free(b);
      b = next;
    }
  }

  free(map->buckets);
  map->buckets  = newbuckets;
  map->capacity = newcap;

  return 0;
}



ana_map *ana_map_new(size_t size)
{
  size_t i;
  ana_map *map = malloc(sizeof(*map));

  if(!map)
    return NULL;

  map->capacity = size;
  map->size = 0;

  map->buckets = malloc(sizeof(ana_map_bucket*) * size);

  if(!map->buckets)
    return NULL;

  for(i = 0; i < size; i++)
    map->buckets[i] = NULL;

  return map;
}

static inline ana_map_bucket *get_bucket(ana_map *map, char *key, size_t len, 
  size_t *idx)
{
  uint64_t hashed = hashlen((unsigned char *)key, len);
  uint64_t index  = hashed % map->capacity;
  ana_map_bucket *bucket = map->buckets[index];
  ana_map_bucket *retval = NULL;

  /* Check to see if this key already exists */
  while(bucket != NULL) 
  {
    ana_map_bucket *next = bucket->next;
    char *thiskey  = bucket->key;
    uint64_t thislen = bucket->keylen;

    if(thislen == len && memcmp(thiskey, key, len) == 0) 
    {
      retval = bucket;
      break;
    }

    bucket = next;
  }

  if(idx)
    *idx = index;

  return retval;
}

int ana_map_put(
  ana_map *map, 
  char *key, 
  char *value,
  uint64_t keylen,
  uint64_t valuelen
)
{
  if(map->size >= map->capacity)
  {
    if(do_resize(map) != 0)
      return 1;
  }

  uint64_t idx;
  ana_map_bucket *bucket = get_bucket(map, key, keylen, &idx);

  if(bucket) 
  {
    free(bucket->value);
    bucket->value = malloc(valuelen);
    memcpy(bucket->value, value, valuelen);
    bucket->valuelen = valuelen;
    goto done;
  }

  bucket = malloc(sizeof(*bucket));

  if(!bucket)
    return 1;

  bucket->key = malloc(keylen);
  memcpy(bucket->key, key, keylen);
  bucket->keylen = keylen;

  bucket->value = malloc(valuelen);
  memcpy(bucket->value, value, valuelen);
  bucket->valuelen = valuelen;

  bucket->next = map->buckets[idx];

  map->buckets[idx] = bucket;

  map->size++;

done:
  return 0;
}

char *ana_map_get(ana_map *map, char *key, uint64_t keylen, uint64_t *outlen)
{
  ana_map_bucket *bucket = get_bucket(map, key, keylen, NULL);

  if(bucket) 
  {
    *outlen = bucket->valuelen;
    return bucket->value;
  }

  return NULL;
}