#ifndef ANA_MESSAGE_H
#define ANA_MESSAGE_H

#define ANA_MESSAGE_MAGIC 0x3E2251
#define ANA_MESSAGE_OP_GET 0x01
#define ANA_MESSAGE_OP_SET 0x02
#define ANA_MESSAGE_OP_RES 0x03

typedef struct ana_message_t {
  uint32_t magic;
  uint8_t opcode;
  uint8_t padding1;
  uint8_t padding2;
  uint8_t padding3;
  uint32_t padding4;
  uint32_t keylen;
  uint64_t len;
} ana_message_t;

ana_message_t *ana_message_set_request_new(char *key, size_t keylen, char *value, 
  size_t valuelen);
ana_message_t *ana_message_new(uint8_t op, char *payload, uint64_t payloadlen);
ana_message_t *ana_message_try_parse(uint32_t *state, char *buffer, size_t len);
void ana_write_message_to_file(const char *file, char *msg, size_t len);

#endif