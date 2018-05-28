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

static void dump_input_buffer(char *buffer, size_t len)
{
  ana_log("buffer dump:");
  printf("len: %lu\n", len);
  size_t i;
  for(i = 0; i < len; i++)
  {
    if(isprint(*(buffer + i)))
    {
      printf("%c", *(buffer + i));
    }
    else
    {
      fputc('.', stdout);
    }
  }

  fputc('\n', stdout);
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
    if((server->fd = socket(node->ai_family, node->ai_socktype,
      node->ai_protocol)) == -1)
    {
      continue;
    }

    // if((flags = fcntl(server->fd, F_GETFL, 0)) < 0)
    // {
    //   close(server->fd);
    //   ana_log("fcntl: failed for F_GETFL on socket %d\n", server->fd);
    //   return 1;
    // }

    // if(fcntl(server->fd, F_SETFL, flags | O_ASYNC | FIOSETOWN) < 0)
    // {
    //   close(server->fd);
    //   ana_log("fcntl: failed to call F_SETFL on socket %d\n", server->fd);
    //   return 1;
    // }

    if(connect(server->fd, node->ai_addr, node->ai_addrlen) != -1)
      break;
    else
      close(server->fd);
  }

  if(node == NULL) {
    ana_log("connect: %s", strerror(errno));
    ret = 1;
  }

  freeaddrinfo(res);

exit:
  return ret;
}

static volatile sig_atomic_t got_signal = 0;
static jmp_buf jmp_state;

/* remote has closed the connection */
static void sig_handler(int sig)
{
  signal(sig, SIG_IGN);
  got_signal = sig;
  longjmp(jmp_state, 1);
}

static ana_message_t *try_parse_command(
  char *key, 
  size_t *keylen, 
  char *value, 
  size_t *valuelen,
  char *buffer, 
  size_t bufferlen,
  size_t keylen_buffer_max)
{

  if(bufferlen < 3)
    return NULL;

  ana_message_t *msg = NULL;

  if(strncmp("SET", buffer, 3) == 0 || strncmp("set", buffer, 3) == 0)
  { 
    size_t i = 3;
    char *begin = buffer + 3;
    size_t klen = 0;
    size_t vlen = 0;

    if(*begin == '\0')
    {
      //ana_log("Invalid Syntax, try SET <key> <value>");
      return NULL;
    }

    while(i < bufferlen && *begin == ' ') 
    {
      i++;
      begin++;
    }

    while(*begin != ' ' && klen < keylen_buffer_max && i < bufferlen)
    {  
      key[klen++] = *begin++;
      i++;
    }

    assert(klen < keylen_buffer_max);


    if(key[klen - 1] != '\0') 
    {
      key[klen++] = '\0';
    }

    *keylen = klen;

    if(*begin == '\0')
    {
     // ana_log("Invalid Syntax, try SET <key> <value>");
      return NULL;
    }

    while(i < bufferlen && *begin == ' ') 
    {
      i++;
      begin++;
    }

    while(vlen < keylen_buffer_max && i < bufferlen)
    {
      value[vlen++] = *begin++; 
      i++;
    }

    assert(vlen < keylen_buffer_max);

    if(value[vlen - 1] != '\0') 
    {
      value[vlen++] = '\0';
    }

    *valuelen = vlen;

    msg = ana_message_set_request_new(key, *keylen, value, 
      *valuelen);

    return msg;
  }
  else if(strncmp("GET", buffer, 3) == 0 || strncmp("get", buffer, 3) == 0)
  {
    char *begin = buffer + 3;

    if(*begin == '\0')
    {
      //ana_log("Invalid Syntax, Try GET <key>");
      return NULL;
    }
    size_t klen = 0;
    size_t i = 3;

    while(*begin != '\0' && *begin == ' ')
    {
      i++;
      begin++;
    }

    while(*begin != ' ' && klen < keylen_buffer_max && i < bufferlen)
    {
      key[klen++] = *begin++;
      i++;
    }

    assert(klen < keylen_buffer_max);

    if(key[klen - 1] != '\0')
    {
      key[klen++] = '\0';
    }

    *keylen = klen;

    if(*keylen == 0) 
    {
      //ana_log("Invalid Syntax, Try GET <key>");
      return NULL;
    }

    if(*begin != '\0')
    {
      //ana_log("Invalid Syntax, Try GET <key>");
      return NULL;
    }

    msg = ana_message_new(ANA_MESSAGE_OP_GET,
              key, *keylen);

    return msg;
  }

  return NULL;
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

  if(si->si_code == POLL_ERR)
  {
    printf("got POLL_ERR\n");
  }
}

int main(int argc, char **argv)
{
  signal(SIGPIPE, sig_handler);

  ana_client_t client;
  ana_settings settings;
  char client_address_str[INET6_ADDRSTRLEN];

  if(ana_parse_argv(&settings, argc, argv) != 0)
    return usage(1);

  if(ana_client_init(&client, &settings) != 0)
    ana_fatal("failed to initialize client");

  if(ana_client_socket_init(&client) != 0)
    ana_fatal("failed to initialize client socket");

  /* install handler for async events, SIGIO via sigaction */
    
  struct sigaction sa;
  sa.sa_flags = SA_SIGINFO;
  sigemptyset(&sa.sa_mask);
  sa.sa_sigaction = sigio_handler;
    
  if(sigaction(SIGIO, &sa, NULL) == -1)
    ana_fatal("sigaction: could not install SIGIO handler");

  char buffer[255];
  struct tm *tmp = localtime(&client.start);

  if(tmp == NULL)
    ana_fatal("localtime: %d: %s", errno, strerror(errno));

  /* May 25 17:24:24 */

  if(strftime(buffer, sizeof(buffer), "%b %d %I:%M:%S %p", tmp) == 0)
    ana_fatal("strftime: strftime returned 0");

  ana_log("%s # connected to %s:%s, socket %d", 
    buffer, settings.server_address, settings.server_port, client.fd);


  if(setjmp(jmp_state))
  {
    ana_log("ECONNRESET: %s", strerror(ECONNRESET));
    
    close(client.fd);

    ana_free_opts(&settings);
  }
  else
  {
    for(;;)
    {
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
        if(settings.verbosity)
          dump_input_buffer(buffer, (size_t)bytes_read);
        
        char key[255];
        size_t keylen = 0;
        char value[255];
        size_t valuelen = 0;
        ana_message_t *message;
        size_t read_bytes = 0;

        if((message = try_parse_command(key, &keylen, value, &valuelen, buffer, bytes_read,
          255)) == NULL)
        {
          printf("Invalid command, try GET <key>, or SET <key> <value>\n");
          continue;
        }
        else
        {
          if(settings.verbosity) 
          {
            ana_log("key length is %lu", keylen);
            ana_log("value length is %lu", valuelen);
            ana_log("parsed command with success");   
            ana_log("payload length is %lu", ntohl((uint32_t)message->len));
          }
        }

        size_t total_write_bytes; 
        size_t total_bytes_written = 0;

        total_write_bytes = sizeof(ana_message_t) + ntohl((uint32_t)message->len);
        char *msg = (char *)message;

        if(settings.verbosity)
          ana_log("total bytes to write: %lu", total_write_bytes);

        while(total_bytes_written < total_write_bytes)
        {
          errno = 0;

          ssize_t nwritten = write(client.fd, 
            msg + total_bytes_written, total_write_bytes - total_bytes_written);

          if(settings.verbosity)
            ana_log("write: returned %ld", nwritten);

          if(nwritten == -1)
          {
            if(errno == EINTR) 
            {
              ana_log("warning: write was interupted: %s", strerror(errno));
              continue;
            }
            else
            {
              if(settings.verbosity)
                ana_log("write: %d: %s", errno, strerror(errno));
                
                goto exit;
              }
            }
            else if(nwritten == 0)
            {
              if(settings.verbosity)
                ana_log("write returned 0");
              
              break;
            }
            else
            {
              total_bytes_written += (size_t)nwritten;
            }
          }

          if(settings.verbosity)
            ana_log("wrote %lu bytes", total_bytes_written);

          char readbuffer[1024];
          size_t read_buffer_size = 1024;
          uint32_t seq = 0;

          while(1)
          {
            if(settings.verbosity)
              ana_log("trying to read %lu bytes", read_buffer_size - read_bytes);      

              assert(read_bytes < read_buffer_size);

              ssize_t nread = read(client.fd,
                readbuffer + read_bytes, read_buffer_size - read_bytes);

              if(nread == -1)
              {
                if(errno == EINTR)
                {
                  if(settings.verbosity)
                    ana_log("warning: read was interupted");
                  continue;
                }
                else
                {
                  if(settings.verbosity)
                  {
                    ana_fatal("read: %d: %s", errno, strerror(errno));
                  }
                }
              } 
              else if(nread == 0)
              {
                goto exit;
              }
              else
              {
                read_bytes += (size_t)nread;

                ana_message_t *msg = ana_message_try_parse(
                  &seq, 
                  readbuffer,
                  read_bytes);

                if(msg != NULL)
                {
                  char *res = (char *)msg + sizeof(ana_message_t);

                  uint64_t len = msg->len;
                  uint64_t i;
                  for(i = 0; i < len; i++)
                  {
                    if(isprint(res[i]))
                    {
                      printf("%c", res[i]);
                    }
                    else
                    {
                      fputc('.', stdout);
                    }
                  }

                  fputc('\n', stdout);

                  break;
                }
              }
          }


          exit:
          if(settings.verbosity)
            ana_log("read %lu bytes", read_bytes);

        }
    }
  }

  return 0;
}