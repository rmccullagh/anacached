#include <stdlib.h>
#include <inttypes.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>

#include "ana_server.h"

/*
 * payload len includes the terminting null byte
 */
ana_message_t *ana_message_new(uint8_t op, char *payload, uint64_t payloadlen)
{
  char *buffer = malloc(sizeof(ana_message_t) + payloadlen);
  ana_message_t *header = (ana_message_t *)buffer;
  char *payload_start = (char *)(buffer + sizeof(ana_message_t));
  size_t i = 0;

  header->magic = htonl(ANA_MESSAGE_MAGIC);
  header->opcode = op;
  header->padding1 = 0;
  header->padding2 = 0;
  header->padding3 = 0;
  header->keylen   = 0;
  header->len = htonl((uint32_t)payloadlen);

  while(i < payloadlen) 
  {
    *payload_start++ = *payload++;
    i++;
  }

  return header;
}

ana_message_t *ana_message_set_request_new(char *key, size_t keylen, char *value, 
  size_t valuelen)
{
  char *buffer = malloc(sizeof(ana_message_t) + keylen + valuelen);
  ana_message_t *header = (ana_message_t *)buffer;
  char *payload_start = (char *)(buffer + sizeof(ana_message_t));
  size_t i = 0;

  header->magic = htonl(ANA_MESSAGE_MAGIC);
  header->opcode = ANA_MESSAGE_OP_SET;
  header->padding1 = 0;
  header->padding2 = 0;
  header->padding3 = 0;
  header->keylen   = htonl((uint32_t)keylen);
  header->len = htonl((uint32_t)keylen + (uint32_t)valuelen);

  while(i < keylen)
  {
    *payload_start++ = *key++;
    i++;
  }

  i = 0;

  while(i < valuelen)
  {
    *payload_start++ = *value++;
    i++;
  }

  return header;
}



ana_message_t *ana_message_try_parse_header(char *buffer, size_t len)
{
  if(len < sizeof(struct ana_message_t)) 
  {
    return NULL;  
  }

  return (ana_message_t *)buffer;
}

ana_message_t *ana_message_try_parse(
  uint32_t *state, char *buffer, size_t len)
{
  if(len < sizeof(struct ana_message_t)) 
  {
    return NULL;  
  }

  ana_message_t *msg = (ana_message_t *)buffer; 

  /* Did we already convert the length to host order */
  if(*state == 0) 
  {
    msg->len = ntohl((uint32_t)msg->len);
    msg->keylen = ntohl((uint32_t)msg->keylen);
    *state = 1;
  }

  uint64_t payload_len = msg->len;

  /* here len is greater to be greater than the header */
  if(len - sizeof(struct ana_message_t) != payload_len) 
  {
    return NULL;
  }

  //ana_log("ana_message_try_parse: returning success");
  return msg;
}

void ana_write_message_to_file(const char *file, char *msg, size_t len)
{
  FILE *fp = fopen(file, "wb");
  size_t nwritten;

  if(!fp)
  {
    ana_fatal("failed to open proto.bin: %s\n", strerror(errno));
  }

  nwritten = fwrite(msg, len, 1, fp);  

  if(nwritten != 1)
    ana_log("warning: fwrite returned %lu, when we needed to write %lu\n",
      nwritten, len);

  fclose(fp);
}