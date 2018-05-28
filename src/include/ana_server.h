#ifndef ANA_SERVER_H
#define ANA_SERVER_H

#define _GNU_SOURCE

#include <time.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <sys/time.h>

#if !defined(ANA_PROGRAM_NAME)
#define ANA_PROGRAM_NAME "anaserver"
#endif

#include "ana_logging.h"
#include "ana_string.h"
#include "ana_message.h"
#include "ana_map.h"

#define ANA_UNUSED(x) (void)x
#define ANA_DEFAULT_LISTEN_BACKLOG 10
#define ANA_EPOLL_EVENT_SIZE 10
#define ANA_STATE_LISTEN 0
#define ANA_STATE_READ  1
#define ANA_STATE_WRITE 2
#define ANA_STATE_CLOSING 3
#define ANA_STATE_CLOSED 4
#define ANA_CONNECTION_BUFFER_SIZE 32
#define ANA_IDLE_CONNECTION_TIMEOUT 600L

typedef struct ana_connection_t {
  int fd;
  struct timeval start; /* the time we acceptz(2) this connection */
  struct timeval last_read; /* the last time we read data from this connection */
  struct timeval closed; /* when was this closed */
  int state;
  char *rbuffer;
  uint32_t read_sequence; /* how many reads did we do to get a valid a packet? */
  char *wbuffer;
  size_t read_bytes; /* how many bytes have we read on this fd? */
  size_t written_bytes; /* how many bytes have we written on this fd? */
  size_t total_write_bytes; /* how many bytes do we need to write? */
  size_t total_read_bytes; /* how many bytes do we need to read? */
  size_t rbuffer_size; /* total bytes allocated */
  size_t wbuffer_size; /* total bytes allocated */
  struct epoll_event *event;
  struct ana_connection_t *next;
} ana_connection_t;

typedef struct ana_settings {
  char *server_address;
  char *server_port;
  int   verbosity;
  int   listen_backlog;
  int   core_dumps_enabled;
  size_t connection_buffer_size;
  int idle_timeout;
  char **argv;
  int argc;
} ana_settings;

typedef struct ana_server_t {
  int fd;
  int epollfd;
  pid_t pid;
  time_t start;
  uint64_t connections;
  ana_settings *settings;
  ana_map *map;
  ana_connection_t *connection;
} ana_server_t;

typedef ana_server_t ana_client_t;
 
int ana_server_init(ana_server_t *server, ana_settings *settings);

#endif