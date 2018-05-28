#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <setjmp.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <ana_server.h>
#include <sys/time.h>


#include "ana_server.h"

#undef ANA_PROGRAM_NAME
#define ANA_PROGRAM_NAME "anacli"

const char *shorthelpstr = "\
Usage: " ANA_PROGRAM_NAME " [option] ... [-a <address> -p <port>]";

const char *helpstr = "\
options and arguments:\n\
  -V, --verbose             verbose messages to stdout\n\
  -h, --help                show this help menu\n\
  -a, --server-address      server socket address (hostname or ip)\n\
  -p, --server-port         server port\n\
  -c  --enable-core-dumps   enable core dumps\n\
";

static struct option long_options[] = {
  { "verbose",           no_argument,       NULL, 'v'},
  { "help",              no_argument,       NULL, 'h'},
  { "server-address",    required_argument, NULL, 'l'},
  { "server-port",       required_argument, NULL, 'p'},
  { "enable-core-dumps", no_argument,       NULL, 'c'},
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

    c = getopt_long(argc, argv, "vha:p:c", long_options, &option_index);

    if(c == -1)
      break;

    switch(c)
    { 
      case 0:
        break;
      case 'a':
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

  if(optind < argc)
  {    
    settings->argc = argc - optind;
    settings->argv = argv + optind;        
  }

  return retval;
}

static void ana_free_opts(ana_settings *opts)
{
  if(opts->server_address)
    free(opts->server_address);

  if(opts->server_port)
    free(opts->server_port);
}

static ssize_t raw_input(const char* prompt, char* buffer, size_t buffer_size)
{
  ssize_t i = 0;
  int c;
  memset(buffer, '\0', buffer_size);
  printf("%s", prompt);
  
  while((c = fgetc(stdin)) != EOF) {
    if((size_t)i < buffer_size - 1) {
      if((char)c == '\n') {
        break;
      } else {
        buffer[i++] = (char)c;
      }
    } else {
      int cc;
      /* swallow the rest */
      while((cc = getchar()) != EOF && cc != '\n');
      break;
    }
  }

  buffer[i] = '\0';
  
  return c == EOF ? EOF : i + 1;
}

static int ana_client_init(ana_client_t *client, ana_settings *settings)
{
  int retval = 0;

  client->start = time(NULL);
  client->pid = getpid();
  client->fd = 0;
  client->settings = settings;
  client->connection = NULL;

  if(client->settings->listen_backlog == 0)
    client->settings->listen_backlog = ANA_DEFAULT_LISTEN_BACKLOG;

  if(client->settings->core_dumps_enabled)
  {
    struct rlimit new;
    new.rlim_cur = RLIM_INFINITY;
    new.rlim_max = RLIM_INFINITY;

    if(setrlimit(RLIMIT_CORE, &new) != 0)
    {
      ana_fatal("getrlimit: %d: %s", errno, strerror(errno));
    }
  }

  if(client->settings->idle_timeout == 0)
    client->settings->idle_timeout = ANA_IDLE_CONNECTION_TIMEOUT;

  return retval;
}


int ana_client_socket_init(ana_client_t *server)
{
  struct addrinfo hints, *res, *node;
  int ret, flags;

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
    errno = 0;

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

    // if(fcntl(server->fd, F_SETFL, flags | O_ASYNC | FIOSETOWN) < 0)
    if(fcntl(server->fd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
      close(server->fd);
      ana_log("fcntl: failed to call F_SETFL on socket %d\n", server->fd);
      return 1;
    }

    int status = connect(server->fd, node->ai_addr, node->ai_addrlen);

    if(status == -1 && errno == EINPROGRESS)
    {

      /*
       It is possible to select(2) or poll(2) for completion by selecting the  socket
       for writing.
       After select(2) indicates writability, use getsockopt(2) to read
       the SO_ERROR option at level SOL_SOCKET to determine  whether  connect()  com‐
       pleted  successfully  (SO_ERROR is zero) or unsuccessfully (SO_ERROR is one of
       the usual error codes listed here, explaining the reason for the failure).
       */
      break;
    }
    else
      close(server->fd);
  }

  if(node == NULL) {
    ana_log("connect: %s", strerror(errno));
    ret = 1;
  }

  struct pollfd pfds[1];

  pfds[0].fd = server->fd;
  pfds[0].events = POLLOUT;

  int nfds = poll(pfds, 1, 5);
  int i;

  if(nfds == -1)
  {
    ana_fatal("poll: %d: %s", errno, strerror(errno));
  }

  for(i = 0; i < nfds; i++)
  {   
    if(pfds[i].revents & POLLOUT)
    {
      int value = 0;
      socklen_t size = sizeof(value);
      getsockopt(server->fd, SOL_SOCKET, SO_ERROR, &value, 
        &size);

      if(value != 0)
      {
        ana_log("connect: %s", strerror(value));
        return 1;
      }
    }
  }

  freeaddrinfo(res);

exit:
  return ret;
}

/*
 fills  in  si_band  and  si_fd.
 The  si_band  event  is  a bit mask containing the same values as are filled in the
 revents field by poll(2).  The si_fd field indicates the file descriptor for  which
 the  I/O  event  occurred
*/
static void sigio_handler(int sig, siginfo_t *si, void *unused)
{
  printf("got SIGIO signal\n");

 // int fd = si->si_fd;
 // long band = si->si_band;

  printf("%ld\n", si->si_band);
  
  if(si->si_band & POLLERR)
  {
    printf("got POLLERR\n");
  }

  if(si->si_band & POLLHUP)
  {
    printf("got POLLHUP\n");
  }
}

int main(int argc, char **argv)
{
  ana_client_t client;
  ana_settings settings;

  if(ana_parse_argv(&settings, argc, argv) != 0)
    return usage(1);

  if(ana_client_init(&client, &settings) != 0)
    ana_fatal("failed to initialize client");

  if(ana_client_socket_init(&client) != 0)
    ana_fatal("failed to initialize client socket");
    
  //fcntl(client.fd, F_SETOWN, getpid());

  // struct sigaction sa;
  // sa.sa_flags = SA_SIGINFO;
  // sigemptyset(&sa.sa_mask);
  // sa.sa_sigaction = sigio_handler;
    
  // if(sigaction(SIGIO, &sa, NULL) == -1)
  //   ana_fatal("sigaction: could not install SIGIO handler");

  for(;;)
  {  
    struct pollfd pfds[1];

    pfds[0].fd = client.fd;
    pfds[0].events = POLLOUT;

    int nfds = poll(pfds, 1, -1);
    int i;

    if(nfds == -1)
    {
      ana_fatal("poll: %d: %s", errno, strerror(errno));
    }

    printf("main: poll returned %d\n", nfds);

    printf("after\n");

    for(i = 0; i < nfds; i++)
    {   
      if(pfds[i].revents & POLLHUP)
      {
        printf("GOT POLLHUP\n");
      }
    }

    char buffer[80];
    ssize_t bytes_read = raw_input("ana> ", buffer, sizeof(buffer));

    if(bytes_read == -1)
    {
      fputc('\n', stdout);
      break;
    }
    else if(bytes_read == 0) 
    {
      continue;
    }
    else
    {

    }
  }

  return 0;
}