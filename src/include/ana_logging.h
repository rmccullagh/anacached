#ifndef ANA_SERVER_LOGGING
#define ANA_SERVER_LOGGING

void __attribute__ ((noreturn)) ana_fatal(const char* format, ...);
void  ana_log(const char* format, ...);

#endif