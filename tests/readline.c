#include <stdio.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <stdlib.h>

typedef struct ana_list_node ana_list_node;

typedef struct ana_list_t {
  ana_list_node *head;
  ana_list_node *tail;
} ana_list_t;

struct ana_list_node {
  ana_list_node *prev;
  ana_list_node *next;
  char *value;
};

static void ana_list_init(ana_list_t *list)
{
  list->head = NULL;
  list->tail = NULL;
}

static void ana_list_dump(ana_list_t *list)
{
  ana_list_node *head = list->tail;

  while(head != NULL)
  {
    printf("%s\n", head->value);
    head = head->prev;
  }
}

static ana_list_node *ana_list_node_new(char *value)
{
  ana_list_node *ret = malloc(sizeof(*ret));

  ret->prev = NULL;
  ret->next = NULL;

  ret->value = value;

  return ret;
}

static void ana_list_add(ana_list_t *list, char *value)
{
  ana_list_node *node = ana_list_node_new(value);

  if(list->tail == NULL)
  {
    list->head = node;
  }
  else
  {
    list->tail->next = node;
    node->prev = list->tail;
  }

  list->tail = node;
}

static void ana_list_delete(ana_list_t *list, char *value)
{
  ana_list_node *head = list->tail;

  while(head != NULL)
  {
    if(strlen(head->value) == strlen(value) &&
        memcmp(head->value, value, strlen(value) == 0))
    {
      head->prev->next = head->next;
      break;
    }
    head = head->prev;
  } 
}

int main(void)
{
  char *line;

//  using_history();

  ana_list_t list;

  ana_list_init(&list);

  while((line = readline("ana>")) != NULL)
  {
  //  printf("%s\n", line);

  //  add_history(line);

    ana_list_add(&list, line);
  }

  fputc('\n', stdout);
  ana_list_dump(&list);

  ana_list_delete(&list, "this");

  fputc('\n', stdout);
  ana_list_dump(&list);

  return 0;
}