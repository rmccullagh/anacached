#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>

char *ana_strdup(char *src)
{
  if(src == NULL || *src == '\0')
    return src;

  size_t len = strlen(src);
  char *buf;

  buf = malloc(len + 1);

  memcpy(buf, src, len);

  buf[len] = '\0';

  return buf;
}

char *ana_build_str(const char *fmt, ...)
{
  char *buffer = malloc(16);
  size_t size = 16;
  va_list ap;

  start:
    va_start(ap, fmt);
    int ret = vsnprintf(buffer, size, fmt, ap);
    va_end(ap);

  if(ret < 0) 
  {
    return NULL;
  }
  else if((size_t)ret < size)
  {
    goto done;
  }
  if((size_t)ret >= size)
  {
    size = size + ((size_t)ret - size ) + 1;
    buffer = realloc(buffer, size);
    goto start;
  }

done:
  return buffer;
}