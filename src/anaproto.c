#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>

#include "ana_server.h"

static void read_message_from_file(const char *file)
{
  ana_log("opening file write.bin for parsing");
  char buffer[1024];
  size_t nread = 0;
  size_t bytesread = 0;

  FILE *fp = fopen(file, "rb");

  if(!fp)
    ana_fatal("failed to open %s", file);
  
  /* read will be called exactly (file_size / 4 )+ (file_size % 4) */
  int totalreads = 0;
  ana_message_t *parsed_message = NULL;
  uint32_t parse_state = 0;

  while(1)
  {
    if(bytesread >= 1024) 
    {
      ana_fatal("Reached max buffer length, bytesread is %lu",
        bytesread);
    }

    nread = fread(buffer + bytesread, 1, 4, fp);
    totalreads++;
    bytesread += nread;

    if(nread != 4)
    {
      ana_log("reached EOF with read returning %lu", nread);
      break;
    }

    if((parsed_message = ana_message_try_parse(&parse_state, buffer, bytesread)) != NULL)
    {
      ana_log("read a complete message");
      break;
    } 
  }

  ana_log("read %lu bytes from file", bytesread);
  ana_log("total reads %d", totalreads);

  if((parsed_message = ana_message_try_parse(&parse_state, buffer, bytesread)) != NULL)
  {
    ana_log("parsed the message");
    ana_log("\tpayload size: %lu", parsed_message->len);
    char *payload = (char *)parsed_message + sizeof(struct ana_message_t);
    uint64_t i;
    for(i = 0; i < parsed_message->len; i++) 
    {
      if(isprint(*(payload + i)))
      {
        printf("%c", *(payload + i));
      }
      else
      {
        printf(".");
      }
    }
    printf("\n");
  }
  else
  {
    ana_log("Failed to parse message:");
    ana_log("writing buffer to output file: debug.bin");
    ana_write_message_to_file("debug.bin", buffer, bytesread);
  }

  fclose(fp);
}

static void test_set_request(char *key, size_t keylen, char *value, size_t valuelen)
{
  ana_log("test_set_request:");
  ana_log("\tkeylen %lu", keylen);
  ana_log("\tvaluelen %lu", valuelen);

  ana_message_t *msg = ana_message_set_request_new(key, keylen, value, valuelen);

  size_t msg_len = sizeof(ana_message_t) + keylen + valuelen;

  ana_log("\tmessage length %lu", msg_len);

  ana_log("writing file set.bin with message");

  ana_write_message_to_file("set.bin", (char *)msg, msg_len);

  read_message_from_file("set.bin");
}

int main(int argc, char **argv)
{
  if(argc < 2)
  {
    printf("Usage: anaproto <string>\n");
    return 1;
  }

  if(argc == 3)
  {
    test_set_request(argv[1], strlen(argv[1]) + 1, argv[2], strlen(argv[2]) + 1);

    return 0;
  }

  char *payload = argv[1];
  size_t payload_len = strlen(payload) + 1;
  char buffer[1024];
  size_t nread = 0;
  size_t bytesread = 0;

  ana_message_t *message = ana_message_new(ANA_MESSAGE_OP_GET,
    payload, payload_len);

  ana_log("payload_len is %lu", ntohl((uint32_t)message->len));
  assert( ntohl((uint32_t)message->len) == payload_len);

  size_t message_len = sizeof(ana_message_t) + payload_len;

  ana_log("message_len is %lu", message_len);

  ana_log("writing file write.bin with message");
  ana_write_message_to_file("write.bin", (char *)message, message_len);


  ana_log("opening file write.bin for parsing");

  FILE *fp = fopen("write.bin", "rb");

  if(!fp)
    ana_fatal("failed to open write.bin");
  
  /* read will be called exactly (file_size / 4 )+ (file_size % 4) */
  int totalreads = 0;
  ana_message_t *parsed_message = NULL;
  uint32_t parse_state = 0;

  while(1)
  {
    if(bytesread >= 1024) 
    {
      ana_fatal("Reached max buffer length, bytesread is %lu",
        bytesread);
    }

    nread = fread(buffer + bytesread, 1, 4, fp);
    totalreads++;
    bytesread += nread;

    if(nread != 4)
    {
      ana_log("reached EOF with read returning %lu", nread);
      break;
    }

    if((parsed_message = ana_message_try_parse(&parse_state, buffer, bytesread)) != NULL)
    {
      ana_log("read a complete message");
      break;
    } 
  }

  ana_log("read %lu bytes from file", bytesread);
  ana_log("total reads %d", totalreads);

  if((parsed_message = ana_message_try_parse(&parse_state, buffer, bytesread)) != NULL)
  {
    ana_log("parsed the message");
    ana_log("\tpayload size: %lu", parsed_message->len);
    char *payload = (char *)parsed_message + sizeof(struct ana_message_t);
    uint64_t i;
    for(i = 0; i < parsed_message->len; i++) 
    {
      if(isprint(*(payload + i)))
      {
        printf("%c", *(payload + i));
      }
      else
      {
        printf(".");
      }
    }
    printf("\n");
  }
  else
  {
    ana_log("Failed to parse message:");
    ana_log("writing buffer to output file: debug.bin");
    ana_write_message_to_file("debug.bin", buffer, bytesread);
  }


  fclose(fp);


  free(message);

  return 0;
}