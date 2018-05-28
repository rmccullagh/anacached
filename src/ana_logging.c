#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

#include "ana_server.h"

void __attribute__ ((noreturn)) ana_fatal(const char* format, ...)
{ 
  va_list args;

  fprintf(stderr, ANA_PROGRAM_NAME " \x1b[31mfatal:\x1b[0m ");  
  va_start (args, format);
    vfprintf (stderr, format, args);
  va_end (args);

  fputc('\n', stderr);

  fflush(stderr); 

  exit(1);
}

void ana_log(const char* format, ...)
{
  va_list args;

  fprintf(stderr, "\x1b[32m" ANA_PROGRAM_NAME ":\x1b[0m ");
  
  va_start (args, format);
    vfprintf (stderr, format, args);
  va_end (args);

  fputc('\n', stderr);

  fflush(stderr); 
}