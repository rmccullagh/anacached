#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/time.h>

#include "ana_server.h"

const char *shorthelpstr = "\
Usage: " ANA_PROGRAM_NAME " [option] ... [-l <address> -p <port>]";

const char *helpstr = "\
options and arguments:\n\
  -V, --verbose                 verbose messages to stdout\n\
  -h, --help                    show this help menu\n\
  -l, --listen-address          listening socket address (hostname or ip)\n\
  -p, --port                    port to bind to for the listening socket\n\
  -c  --enable-core-dumps       enable core dumps\n\
  -r  --connection-buffer-size  max connection buffer read size\n\
  -i  --idle-timeout            idle timeout for connnections in ms\n\
";

static struct option long_options[] = {
  { "verbose",                no_argument,       NULL, 'v'},
  { "help",                   no_argument,       NULL, 'h'},
  { "listen-address",         required_argument, NULL, 'l'},
  { "port",                   required_argument, NULL, 'p'},
  { "enable-core-dumps",      no_argument,       NULL, 'c'},
  { "connection-buffer-size", required_argument, NULL, 'r'},
  { "idle-timeout",           required_argument, NULL, 'i'},
  {0, 0, 0, 0}
};

static int __attribute__ ((noreturn))  usage(int status)
{
  if(status != 0) 
  {
    fprintf(stdout, "%s\n", shorthelpstr);
    fprintf(stdout, "Try " ANA_PROGRAM_NAME " --help' for more information\n");
  } 
  else { 
    fprintf(stdout, "%s\n", shorthelpstr);
    fprintf(stdout, "%s", helpstr);
  }
  
  exit(status);
}

static int ana_parse_argv(ana_settings *settings, int argc, char **argv)
{
  int c;
  int option_index = 0;
  int retval = 0;

  memset(settings, 0, sizeof(struct ana_settings));

  for(;;)
  {
    opterr = 1;

    c = getopt_long(argc, argv, "vhl:p:c", long_options, &option_index);

    if(c == -1)
      break;

    switch(c)
    { 
      case 0:
        break;
      case 'l':
        settings->server_address = ana_strdup(optarg);
        break;
      case 'p':
        settings->server_port = ana_strdup(optarg);
        break;
      case 'h':
        usage(0);
        break;
      case 'v':
        settings->verbosity = 1;
        break;
      case 'c':
        settings->core_dumps_enabled = 1;
        break;
      case 'r':
        errno = 0;
        settings->connection_buffer_size = strtoul(optarg, NULL, 10);

        if(settings->connection_buffer_size == ULONG_MAX && errno == ERANGE)
          ana_fatal("--connection-buffer-size: %s", strerror(errno));

        if(settings->connection_buffer_size >= 1000000)
          ana_log("warning: the configured --connection-buffer-size "
                  "may starve your system of memory");

        break;
      case 'i': 
      {
        errno = 0;
        long temp;
        temp = strtol(optarg, NULL, 10);

        if((temp == LONG_MIN || temp == LONG_MAX) && errno == ERANGE)
          ana_fatal("--idle-time-out: %s", strerror(errno));

        settings->idle_timeout = (int)temp;

        break;
      }
      case '?':
        retval = 1;
        goto exit;

      default:
        usage(1);
    }
  }

  if(settings->server_address == NULL ||
    settings->server_port == NULL)
  {
    retval = 1;
  }

exit:

  return retval;
}

static void ana_free_opts(ana_settings *opts)
{
  if(opts->server_address)
    free(opts->server_address);

  if(opts->server_port)
    free(opts->server_port);
}

static void ana_dump_settings(ana_server_t *server)
{
  ana_log("server settings");
  fprintf(stderr, "  server_address = %s\n", server->settings->server_address);
  fprintf(stderr, "  server_port = %s\n", server->settings->server_port);
  fprintf(stderr, "  verbosity = %d\n", server->settings->verbosity);
  fprintf(stderr, "  core_dumps_enabled = %d\n", 
    server->settings->core_dumps_enabled);
  fprintf(stderr, "  connection_buffer_size = %lu\n", 
    server->settings->connection_buffer_size);
  fprintf(stderr, "  listen_backlog = %d\n", 
    server->settings->listen_backlog);
  fprintf(stderr, "  idle_timeout = %d\n", server->settings->idle_timeout);
}

static void ana_dump_init_message(ana_server_t *server)
{
  char buffer[255];
  struct tm *tmp = localtime(&server->start);

  if(tmp == NULL)
    ana_fatal("localtime: %d: %s", errno, strerror(errno));

  /* May 25 17:24:24 */

  if(strftime(buffer, sizeof(buffer), "%b %d %I:%M:%S %p", tmp) == 0)
    ana_fatal("strftime: strftime returned 0");


  ana_log("%s # listen socket (%d) bound to %s:%s",
    buffer,
    server->fd, 
    server->settings->server_address, 
    server->settings->server_port);
}

int ana_server_init(ana_server_t *server, ana_settings *settings)
{
  server->fd = 0;
  server->epollfd = -1;
  server->pid = getpid();
  server->start = time(NULL);
  server->connections = 0;
  server->map = ana_map_new(16);
  server->settings = settings;
  server->connection = NULL;

  if(server->settings->listen_backlog == 0)
    server->settings->listen_backlog = ANA_DEFAULT_LISTEN_BACKLOG;

  if(server->settings->core_dumps_enabled)
  {
    struct rlimit new;
    new.rlim_cur = RLIM_INFINITY;
    new.rlim_max = RLIM_INFINITY;

    if(setrlimit(RLIMIT_CORE, &new) != 0)
    {
      ana_fatal("getrlimit: %d: %s", errno, strerror(errno));
    }
  }

  if(server->settings->idle_timeout == 0)
    server->settings->idle_timeout = ANA_IDLE_CONNECTION_TIMEOUT;

  if(server->settings->connection_buffer_size == 0)
    server->settings->connection_buffer_size = ANA_CONNECTION_BUFFER_SIZE;

  return 0;
}

char *ana_str_sockaddr(struct addrinfo *node, char *result)
{
  struct sockaddr_in *sockaddr_in;
  struct sockaddr_in6 *sockaddr_in6;

  if(node->ai_family == AF_INET)
  {
    sockaddr_in = (struct sockaddr_in *)node->ai_addr;
    inet_ntop(AF_INET, &(sockaddr_in->sin_addr), result, INET6_ADDRSTRLEN);
    return result;
  }
  else if(node->ai_family == AF_INET6)
  {
    sockaddr_in6 = (struct sockaddr_in6 *)node->ai_addr;
    inet_ntop(AF_INET6, &(sockaddr_in6->sin6_addr), result, INET6_ADDRSTRLEN);
    return result;
  }

/* Unreached */
  ana_log("node->ai_family was not correct");
  abort();
}

char *ana_str_sockaddr2(struct sockaddr *node, char *result)
{
  struct sockaddr_in *sockaddr_in;
  struct sockaddr_in6 *sockaddr_in6;

  if(node->sa_family == AF_INET)
  {
    sockaddr_in = (struct sockaddr_in *)node;
    inet_ntop(AF_INET, &(sockaddr_in->sin_addr), result, INET6_ADDRSTRLEN);
    return result;
  }
  else if(node->sa_family == AF_INET6)
  {
    sockaddr_in6 = (struct sockaddr_in6 *)node;
    inet_ntop(AF_INET6, &(sockaddr_in6->sin6_addr), result, INET6_ADDRSTRLEN);
    return result;
  }

/* Unreached */
  ana_log("node->ai_family was not correct");
  abort();
}


int ana_server_socket_init(ana_server_t *server)
{
  struct addrinfo hints, *res, *node;
  int ret;
  int flags;
  char result[INET6_ADDRSTRLEN];

  memset(&hints, 0, sizeof(struct addrinfo));

  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = 0;
  hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;

  ret = getaddrinfo(server->settings->server_address, 
    server->settings->server_port, &hints, &res);

  if(ret != 0)
  {
    ana_log("getaddrinfo returned nonzero: %s", gai_strerror(ret));
    goto exit;
  }

  for(node = res; node != NULL; node = node->ai_next)
  {
    if((server->fd = socket(node->ai_family, node->ai_socktype,
      node->ai_protocol)) == -1)
    {
      continue;
    }

    if((flags = fcntl(server->fd, F_GETFL, 0)) < 0)
    {
      close(server->fd);
      ana_log("fcntl: failed for F_GETFL on socket %d\n", server->fd);
      return 1;
    }

    if(fcntl(server->fd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
      close(server->fd);
      ana_log("fcntl: failed to call F_SETFL on socket %d\n", server->fd);
      return 1;
    }

    setsockopt(server->fd, SOL_SOCKET, SO_REUSEADDR, (void *)&flags, 
      sizeof(flags));

    if(bind(server->fd, node->ai_addr, node->ai_addrlen) == -1)
    {
      ana_log("bind: failed to bind to address to socket: %d: %s",
        errno, strerror(errno));
      
      close(server->fd);
      continue;   
    }

    if(listen(server->fd, server->settings->listen_backlog) == -1)
    {
      ana_log("listen: failed to listen on socket");
      close(server->fd);
      continue;
    }

    break;
  }

  if(node == NULL) {
    ana_log("failed to bind to socket");
    ret = 1;
  }
  else
  {
    if(server->settings->verbosity)
      ana_log("bind to %s success", ana_str_sockaddr(node, result));
  }

  freeaddrinfo(res);

exit:
  return ret;
}

static ana_connection_t *ana_new_connection(ana_server_t *server, int fd)
{
  ana_connection_t *connection = malloc(sizeof(*connection));

  connection->fd = fd;
  connection->state = ANA_STATE_READ;
  connection->read_sequence = 0;
  connection->rbuffer = malloc(server->settings->connection_buffer_size);
  connection->wbuffer = malloc(server->settings->connection_buffer_size);
  connection->read_bytes = 0; /* current position */
  connection->written_bytes = 0;
  connection->rbuffer_size = server->settings->connection_buffer_size;
  connection->wbuffer_size = server->settings->connection_buffer_size;
  connection->total_write_bytes = 0;
  connection->total_read_bytes = 0;
  connection->event = malloc(sizeof(struct epoll_event));
  connection->next = server->connection;
  
  gettimeofday(&connection->start, NULL);
  
  struct timeval defaulttimeval = {
    0, 0
  };

  connection->last_read = defaulttimeval;
  connection->closed = defaulttimeval;

  server->connection = connection;

  return connection;
}

static void handle_idle_connections(ana_server_t *server)
{
    /* idle connection timeout */

  ana_connection_t *root = server->connection;

  if(server->settings->verbosity)
    ana_log("running idle connection check for %lu connections",
      server->connections);

  while(root != NULL)
  {
    if(root->fd == server->fd)
      goto skip;

    if(root->state == ANA_STATE_CLOSED)
      goto skip;

    if(server->settings->verbosity)
      ana_log("checking connection %d", root->fd);

    if(root->last_read.tv_sec == 0)
    {
      struct timeval now;
      gettimeofday(&now, NULL);

      if(now.tv_sec - root->start.tv_sec >= ANA_IDLE_CONNECTION_TIMEOUT)
      {
        struct timeval diff;
        timersub(&now, &root->start, &diff); 

        ana_log("connection %d hasn't had first read event after %ld.%ld seconds, closing",
          root->fd, diff.tv_sec, diff.tv_usec / 1000);

        root->state = ANA_STATE_CLOSED;

        assert(server->connections != 0);
        server->connections--;

        close(root->fd);
      }
    } 
    else
    {
      struct timeval now;
      gettimeofday(&now, NULL);

      struct timeval diff;
      timersub(&now, &root->last_read, &diff); 

        if(diff.tv_sec >= ANA_IDLE_CONNECTION_TIMEOUT)
        { 
          ana_log("connection %d is idle after %ld.%ld seconds, closing", root->fd,
            diff.tv_sec, diff.tv_usec / 1000);
          
          if(epoll_ctl(server->epollfd, EPOLL_CTL_DEL, root->fd, 
              root->event) == -1)
          {
            ana_log("epoll_ctl: errno %d: %s", errno, strerror(errno));
          }

          root->state = ANA_STATE_CLOSED;

          assert(server->connections != 0);
          server->connections--;

          close(root->fd);
        }
        else
        {
          ana_log("connection %d last read was %ld.%ld ago", root->fd,
            diff.tv_sec, diff.tv_usec / 1000);
        }
      }

      skip:
      root = root->next;
    }

    if(server->settings->verbosity)
      ana_log("idle connection check complete");
}


int main(int argc, char **argv)
{
  ana_server_t server;
  ana_settings settings;
  char client_address_str[INET6_ADDRSTRLEN];

  if(ana_parse_argv(&settings, argc, argv) != 0)
    return usage(1);

  if(ana_server_init(&server, &settings) != 0)
    ana_fatal("failed to initialize ana_server_t struct");

  if(settings.verbosity)
    ana_dump_settings(&server);

  if(ana_server_socket_init(&server) != 0)
    ana_fatal("failed to initialize server socket");

  ana_dump_init_message(&server);

  signal(SIGPIPE, SIG_IGN);

  /* Init has been setup, server->fd is a nonblocking socket
     bound to the interface of settings->server_address and listening
     on port settings->port
   */
  struct epoll_event events[ANA_EPOLL_EVENT_SIZE];
  int fds, i;

  server.epollfd = epoll_create(ANA_EPOLL_EVENT_SIZE);

  if(server.epollfd == -1)
  {
    ana_fatal("epoll_create: %s", strerror(errno));
  }

  ana_connection_t *listening_connection =
    ana_new_connection(&server, server.fd);

  listening_connection->event->events = EPOLLIN;
  listening_connection->event->data.ptr = listening_connection;
  listening_connection->state = ANA_STATE_LISTEN;

  if(epoll_ctl(server.epollfd, EPOLL_CTL_ADD, server.fd, 
    listening_connection->event) == -1)
  {
    ana_fatal("epoll_ctl: %s", strerror(errno));
  }

  if(server.settings->verbosity)
    ana_log("ready to dispatch connections");

  for(;;)
  {
    /* accept connections, and dispatch the connection to a worker thread */

    fds = epoll_wait(server.epollfd, events, ANA_EPOLL_EVENT_SIZE, 
      server.settings->idle_timeout * 1000);

    if(fds == -1)
    {
      if(errno != EINTR)
        ana_fatal("epoll_wait: errno %d:%s", errno, strerror(errno));

      continue;
    }
    else if(fds == 0)
    {
      ana_log("epoll_wait: timed out after %ld seconds", settings.idle_timeout);
      
      if(server.connections > 0)
        handle_idle_connections(&server);
    }
    else
    {
      if(settings.verbosity)
        ana_log("epoll_wait: returned %d", fds);
    }

    for(i = 0; i < fds; i++)
    {
      ana_connection_t *connection = events[i].data.ptr;

      switch(connection->state)
      {
        case ANA_STATE_LISTEN:
        {
          if(settings.verbosity)
            ana_log("ANA_STATE_LISTEN: %d", connection->fd);

          struct sockaddr_in client_address;
          socklen_t client_address_len = sizeof(struct sockaddr_in);
          int client_fd;
          int flags;

          memset(&client_address, 0, sizeof(struct sockaddr_in));
          
          client_fd = accept(server.fd, (struct sockaddr *)&client_address, 
            &client_address_len);

          if(client_fd == -1)
          {
            ana_log("error, accept: %s", strerror(errno));
            continue;
          }

          if((flags = fcntl(client_fd, F_GETFL, 0)) < 0)
          {
            close(client_fd);
            ana_log("fcntl: failed for F_GETFL on client connection %d\n", 
              client_fd);
            continue;
          }

          if(fcntl(client_fd, F_SETFL, flags | O_NONBLOCK) < 0)
          {
            close(client_fd);
            ana_log("fcntl: failed to call F_SETFL on client connection %d\n", 
              client_fd);
            continue;
          }

          server.connections++;

          ana_log("accepted connection from %s (socket %d), connection #%lu", 
            ana_str_sockaddr2((struct sockaddr *)&client_address, 
              client_address_str), client_fd, server.connections);

          ana_connection_t *client_connection = 
            ana_new_connection(&server, client_fd);

          client_connection->event->events = EPOLLIN;
          client_connection->event->data.ptr = client_connection;


          if(epoll_ctl(server.epollfd, EPOLL_CTL_ADD, client_fd, 
            client_connection->event) == -1) 
          {

            ana_log("epoll_ctl: %s", strerror(errno));
            
            close(client_fd);
            
            client_connection->state = ANA_STATE_CLOSED;
          }

          break;
        }
        case ANA_STATE_READ:
        {
          ana_log("ANA_STATE_READ: %d", connection->fd);
          
          /* if connection->rbuffer_size - connection->read_bytes == 0
             that means we've exghausted this buffer 
           */
          if(connection->read_bytes >= connection->rbuffer_size)
          {
            if(settings.verbosity) 
            {
              ana_log("resizing buffer", connection->fd);
              ana_log("connection->rbuffer_size - connection->read_bytes="
                "%lu", connection->rbuffer_size - connection->read_bytes);
            }

            size_t old_size = connection->rbuffer_size;
            size_t new_size = old_size * 2;
            connection->rbuffer_size = new_size;

            if(settings.verbosity) 
            {
              ana_log("new buffer size is %lu, old size is %lu", 
                connection->rbuffer_size, old_size);
              ana_log("max read will now be %lu", 
                connection->rbuffer_size - connection->read_bytes);
            }

            connection->rbuffer = realloc(connection->rbuffer, new_size);

            if(connection->rbuffer == NULL)
            {
              ana_log("read: can't realloc to %lu bytes, dropping connection %d",
                new_size, connection->fd);

              connection->state = ANA_STATE_CLOSING;

              break;
            }
          }

          assert(connection->read_bytes < connection->rbuffer_size);

          /* max size to be passed to read is; 
             connection->rbuffer_size - connection->read_bytes
           */
          ssize_t nread = read(connection->fd, 
            connection->rbuffer + connection->read_bytes,
             connection->rbuffer_size - connection->read_bytes);

          gettimeofday(&connection->last_read , NULL);

          ana_log("ANA_STATE_READ: %d read returned %ld", connection->fd, 
            nread);

          if(nread == -1)
          {
            if(errno != EAGAIN && errno != EWOULDBLOCK)
            {
              ana_log("read(%d): %s", connection->fd, strerror(errno));
              
              connection->state = ANA_STATE_CLOSING;

              break;
            }
            else
            {
              connection->state = ANA_STATE_CLOSING;

              break;
            }
          }
          // End of file was reached
          else if(nread == 0)
          {
            if(settings.verbosity)
              ana_log("ANA_STATE_READ: read %zu bytes from %d", 
                  connection->read_bytes, connection->fd);
            
            connection->state = ANA_STATE_CLOSING;
          }
          else
          {
            connection->read_bytes += nread;

            ana_log("total bytes read now is %lu", connection->read_bytes);

            ana_message_t *msg = ana_message_try_parse(
              &connection->read_sequence, 
              connection->rbuffer,
              connection->read_bytes);

            if(msg != NULL)
            {

              /* TODO check for valid op types */
              ana_log("connection %d sent a %s request",
                connection->fd, 
                msg->opcode == ANA_MESSAGE_OP_GET ? "GET" : "SET");
              //
              // We've parsed a valid packet, now we can send a response
              //
              if(settings.verbosity)
                ana_log("ANA_STATE_READ: got valid packet from %d",
                  connection->fd);
              
              char *payload = (char *)msg + sizeof(ana_message_t);
              size_t i;

              ana_message_t *out_msg;
              size_t out_msg_len = 0;

              if(msg->opcode == ANA_MESSAGE_OP_GET)
              {
                char *key = payload;
                uint64_t keylen = msg->len;
                uint64_t outlen = 0;

                char *value = ana_map_get(server.map, key, keylen, &outlen);

                if(value)
                {
                  if(settings.verbosity)
                    ana_log("successfully retrieved value");

                  out_msg = ana_message_new(ANA_MESSAGE_OP_RES, value, outlen);
                  out_msg_len = sizeof(ana_message_t) + outlen;

                  if(settings.verbosity)
                      ana_log("out msg len will be %lu", out_msg_len);
                }
                else
                {
                    /* TODO, handle this gracefully */
                  out_msg = ana_message_new(ANA_MESSAGE_OP_RES,
                    "[Key Error]", sizeof("[Key Error]"));
                  out_msg_len = sizeof(ana_message_t) + sizeof("[Key Error]");
                }
              }
              else if(msg->opcode == ANA_MESSAGE_OP_SET)
              {
                char *key = payload;
                uint64_t keylen = msg->keylen;
                char *value = payload + msg->keylen;
                uint64_t valuelen = msg->len - msg->keylen;

                ana_map_put(server.map, key, value, keylen, valuelen);
                
                out_msg = ana_message_new(ANA_MESSAGE_OP_RES,
                    key, keylen);

                out_msg_len = sizeof(ana_message_t) + keylen;

                if(settings.verbosity)
                    ana_log("out msg len will be %lu", out_msg_len);
              }
              else
              {
                out_msg = ana_message_new(ANA_MESSAGE_OP_RES,
                    "Invalid Opcode", sizeof("Invalid Opcode"));

                out_msg_len = sizeof(ana_message_t) + sizeof("Invalid Opcode");
              }

              connection->event->events = EPOLLOUT;
              connection->state = ANA_STATE_WRITE;
              connection->total_write_bytes = out_msg_len;
              connection->written_bytes = 0;
              connection->read_bytes = 0;
              connection->total_read_bytes = 0;

              if(out_msg_len > connection->wbuffer_size)
              {
                connection->wbuffer = realloc(connection->wbuffer, out_msg_len);

                if(connection->rbuffer == NULL) 
                {
                  ana_log("realloc: can't allocate %lu bytes for write response. "
                    "Dropping connection", connection->fd, msg->len);

                  connection->state = ANA_STATE_CLOSING;
                  break;
                }

                connection->wbuffer_size = out_msg_len;
              }

              if(settings.verbosity)
                ana_log("total bytes to write is %lu", connection->total_write_bytes);

              char *out_msg_buffer = (char *)out_msg;

              for(i = 0; i < out_msg_len; i++)
              {
                assert(i < connection->wbuffer_size);

                connection->wbuffer[i] = out_msg_buffer[i];
              }

              if(settings.verbosity)
                ana_log("done writing response");

              if(epoll_ctl(server.epollfd, EPOLL_CTL_MOD, connection->fd,
                connection->event) == -1)
              {
                ana_log("warning: epoll_ctl: %d: %s", errno, strerror(errno));
                break;
              }
            }
            else
            {
              ana_log("ANA_STATE_READ: %d didn't get a valid packet, need to read more",
                connection->fd);
            }
          }

          break;
        }
        case ANA_STATE_CLOSING:
        {
          gettimeofday(&connection->closed , NULL);

          ana_log("ANA_STATE_CLOSING: %d", connection->fd);

          epoll_ctl(server.epollfd, EPOLL_CTL_DEL, connection->fd, 
            connection->event);

          struct timeval now;
          gettimeofday(&now, NULL);
          struct timeval diff;
          timersub(&now, &connection->start, &diff); 

          ana_log("%d was active for %ld.%ld seconds", connection->fd, 
            diff.tv_sec, diff.tv_usec);
          
          close(connection->fd);

          /* If we keep a doubly linked list, we can 
            remove it from the conn queue completely */
          connection->state = ANA_STATE_CLOSED;

          assert(server.connections != 0);

          server.connections--;

          break;
        }
        case ANA_STATE_WRITE:
        {
          ana_log("ANA_STATE_WRITE: %d", connection->fd);

          assert(connection->written_bytes < connection->total_write_bytes);

          ssize_t nwritten = write(connection->fd, 
            connection->wbuffer + connection->written_bytes, 
            connection->total_write_bytes - connection->written_bytes);

          ana_log("ANA_STATE_WRITE: write returned %ld", nwritten);

          // This may mean we've read the entire payload
          if(nwritten == -1)
          {
            if(errno != EAGAIN && errno != EWOULDBLOCK)
            {
              ana_log("read(%d): %s", connection->fd, strerror(errno));
              
              connection->state = ANA_STATE_CLOSING;

              break;
            }
            else
            {
              connection->event->events = EPOLLIN;

              if(epoll_ctl(server.epollfd, EPOLL_CTL_MOD, connection->fd, 
                connection->event) == -1) {

                ana_log("epoll_ctl: %s", strerror(errno));
              }

              connection->state = ANA_STATE_READ;

              break;
            }
          }
          // End of file was reached
          else if(nwritten == 0)
          {
            if(settings.verbosity)
              ana_log("ANA_STATE_READ: read %zu bytes from %d\n", 
                  connection->read_bytes, connection->fd);
            
            connection->state = ANA_STATE_CLOSING;
          }
          else
          {
            connection->written_bytes += nwritten;

            if(connection->written_bytes == connection->total_write_bytes)
            {              
              // We've written a full response
              // Now we can start reading again, for another packet
              //
              connection->event->events = EPOLLIN;

              if(epoll_ctl(server.epollfd, EPOLL_CTL_MOD, connection->fd, 
                connection->event) == -1) {

                ana_log("epoll_ctl: %s", strerror(errno));
              }

              /* This significes a complete message exchange,
                 now start over
               */
              connection->state = ANA_STATE_READ;
              connection->read_bytes = 0;
              connection->written_bytes = 0;
              connection->total_write_bytes = 0;
              connection->total_read_bytes = 0;
              connection->read_sequence = 0;
              break;
            }
          }
          
          break;
        }
      } 
    }
  }


  ana_free_opts(&settings);

  return 0;
}
