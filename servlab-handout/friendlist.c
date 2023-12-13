/*
 * friendlist.c - [Starting code for] a web-based friend-graph manager.
 *
 * Based on:
 *  tiny.c - A simple, iterative HTTP/1.0 Web server that uses the 
 *      GET method to serve static and dynamic content.
 *   Tiny Web server
 *   Dave O'Hallaron
 *   Carnegie Mellon University
 */
#include "csapp.h"
#include "dictionary.h"
#include "more_string.h"

static void doit(int fd);
static dictionary_t *read_requesthdrs(rio_t *rp);
static void read_postquery(rio_t *rp, dictionary_t *headers, dictionary_t *d);
static void clienterror(int fd, char *cause, char *errnum, 
                        char *shortmsg, char *longmsg);
static void print_stringdictionary(dictionary_t *d);
static void serve_request(int fd, char *body);

//adding
static void handle_befriend(int fd, dictionary_t *query);
static void handle_unfriend(int fd, dictionary_t *query);
static void handle_friends(int fd, dictionary_t *query);
static void handle_introduce(int fd, dictionary_t *query);
static void add_friend(const char *user, const char *friend);
static void remove_friend(const char *user, const char *friend);

static dictionary_t *user_list;
//static char* create_request_body(dictionary_t *query);

int main(int argc, char **argv) {
  int listenfd, connfd;
  char hostname[MAXLINE], port[MAXLINE];
  socklen_t clientlen;
  struct sockaddr_storage clientaddr;

  // adding
  user_list = make_dictionary(COMPARE_CASE_SENS, free);

  /* Check command line args */
  if (argc != 2) {
    fprintf(stderr, "usage: %s <port>\n", argv[0]);
    exit(1);
  }

  listenfd = Open_listenfd(argv[1]);

  /* Don't kill the server if there's an error, because
     we want to survive errors due to a client. But we
     do want to report errors. */
  exit_on_error(0);

  /* Also, don't stop on broken connections: */
  Signal(SIGPIPE, SIG_IGN);

  while (1) {
    clientlen = sizeof(clientaddr);
    connfd = Accept(listenfd, (SA *)&clientaddr, &clientlen);
    if (connfd >= 0) {
      Getnameinfo((SA *) &clientaddr, clientlen, hostname, MAXLINE, 
                  port, MAXLINE, 0);
      printf("Accepted connection from (%s, %s)\n", hostname, port);
      doit(connfd);
      Close(connfd);
    }
  }

  //adding
  free_dictionary(user_list);
}

/*
 * doit - handle one HTTP request/response transaction
 */
void doit(int fd) {
  char buf[MAXLINE], *method, *uri, *version;
  rio_t rio;
  dictionary_t *headers, *query;

  /* Read request line and headers */
  Rio_readinitb(&rio, fd);
  printf("buf %s\n", buf);

  if (Rio_readlineb(&rio, buf, MAXLINE) <= 0)
    return;
  printf("buf %s\n", buf);
  printf("%s", buf);
  
  if (!parse_request_line(buf, &method, &uri, &version)) {
    clienterror(fd, method, "400", "Bad Request",
                "Friendlist did not recognize the request");
  } else {
    if (strcasecmp(version, "HTTP/1.0")
        && strcasecmp(version, "HTTP/1.1")) {
      clienterror(fd, version, "501", "Not Implemented",
                  "Friendlist does not implement that version");
    } else if (strcasecmp(method, "GET")
               && strcasecmp(method, "POST")) {
      clienterror(fd, method, "501", "Not Implemented",
                  "Friendlist does not implement that method");
    } else {
      headers = read_requesthdrs(&rio);
      /* Parse all query arguments into a dictionary */
      query = make_dictionary(COMPARE_CASE_SENS, free);
      parse_uriquery(uri, query);
      if (!strcasecmp(method, "POST"))
        read_postquery(&rio, headers, query);

      /* For debugging, print the dictionary */
      print_stringdictionary(query);

      /* You'll want to handle different queries here,
         but the intial implementation always returns
         nothing: */
      //adding
      dictionary_set(query, "uri", strdup(uri));

      printf("uri%s\n", uri);

      if(starts_with("/befriend",uri)){
          handle_befriend(fd, query);
      }else if(starts_with("/friends",uri)){
          handle_friends(fd, query);
      }else if(starts_with("/unfriend",uri)){
          handle_unfriend(fd, query);
      }else if(starts_with("/introduce",uri)){
          handle_introduce(fd, query);
      }

      //end
      //serve_request(fd, query);

      /* Clean up */
      free_dictionary(query);
      free_dictionary(headers);
    }

    /* Clean up status line */
    free(method);
    free(uri);
    free(version);
  }
}

/*
 * read_requesthdrs - read HTTP request headers
 */
dictionary_t *read_requesthdrs(rio_t *rp) {
  char buf[MAXLINE];
  dictionary_t *d = make_dictionary(COMPARE_CASE_INSENS, free);

  Rio_readlineb(rp, buf, MAXLINE);
  printf("%s", buf);
  while(strcmp(buf, "\r\n")) {
    Rio_readlineb(rp, buf, MAXLINE);
    printf("%s", buf);
    parse_header_line(buf, d);
  }
  
  return d;
}

void read_postquery(rio_t *rp, dictionary_t *headers, dictionary_t *dest) {
  char *len_str, *type, *buffer;
  int len;
  
  len_str = dictionary_get(headers, "Content-Length");
  len = (len_str ? atoi(len_str) : 0);

  type = dictionary_get(headers, "Content-Type");
  
  buffer = malloc(len+1);
  Rio_readnb(rp, buffer, len);
  buffer[len] = 0;

  if (!strcasecmp(type, "application/x-www-form-urlencoded")) {
    parse_query(buffer, dest);
  }

  free(buffer);
}

static char *ok_header(size_t len, const char *content_type) {
  char *len_str, *header;
  
  header = append_strings("HTTP/1.0 200 OK\r\n",
                          "Server: Friendlist Web Server\r\n",
                          "Connection: close\r\n",
                          "Content-length: ", len_str = to_string(len), "\r\n",
                          "Content-type: ", content_type, "\r\n\r\n",
                          NULL);
  free(len_str);

  return header;
}

/*
 * serve_request - example request handler
 */
static void serve_request(int fd, char *body) {
  size_t len;
  char *header;
  //adding
  len = strlen(body);

  /* Send response headers to client */
  header = ok_header(len, "text/html; charset=utf-8");
  Rio_writen(fd, header, strlen(header));
  printf("Response headers:\n");
  printf("%s", header);

  free(header);

  /* Send response body to client */
  Rio_writen(fd, body, len);

  //free(body);
}


/*
 * clienterror - returns an error message to the client
 */
void clienterror(int fd, char *cause, char *errnum, 
	char *shortmsg, char *longmsg) {
  size_t len;
  char *header, *body, *len_str;

  body = append_strings("<html><title>Friendlist Error</title>",
                        "<body bgcolor=""ffffff"">\r\n",
                        errnum, " ", shortmsg,
                        "<p>", longmsg, ": ", cause,
                        "<hr><em>Friendlist Server</em>\r\n",
                        NULL);
  len = strlen(body);

  /* Print the HTTP response */
  header = append_strings("HTTP/1.0 ", errnum, " ", shortmsg, "\r\n",
                          "Content-type: text/html; charset=utf-8\r\n",
                          "Content-length: ", len_str = to_string(len), "\r\n\r\n",
                          NULL);
  free(len_str);
  
  Rio_writen(fd, header, strlen(header));
  Rio_writen(fd, body, len);

  free(header);
  free(body);
}

static void print_stringdictionary(dictionary_t *d) {
  int i, count;

  count = dictionary_count(d);
  for (i = 0; i < count; i++) {
    printf("%s=%s\n",
           dictionary_key(d, i),
           (const char *)dictionary_value(d, i));
  }
  printf("\n");
}

/*
 *  request_body - create body and send to a client
 * 
*/
static char* create_request_body(dictionary_t *query) {
  char *body = NULL;
  char *uri = dictionary_get(query, "uri");

  if(starts_with("/befriend",uri) || starts_with("/friends",uri)
    || starts_with("/unfriend",uri)){
      char *user = dictionary_get(query, "user");
      dictionary_t *friend_list = dictionary_get(user_list, user);
      
      if(friend_list){
        const char **keys = dictionary_keys(friend_list);
        body = join_strings(keys, '\n');
        free(keys);
      }
  }
  return body;
}

void handle_befriend(int fd, dictionary_t *query) {

  char *user = dictionary_get(query, "user");
  char *friends = dictionary_get(query, "friends");
  char **friend_list = split_string(friends, '\n');

  for (int i = 0; friend_list[i] != NULL; i++) {
    add_friend(user, friend_list[i]);
    free(friend_list[i]);
  }
  free(friend_list);
  handle_friends(fd, query);
}

void handle_friends(int fd, dictionary_t *query) { 
   char *user = dictionary_get(query, "user");
    dictionary_t *user_friend_list = dictionary_get(user_list, user);

    char *body = NULL;
    if (user_friend_list) {
        const char **keys = dictionary_keys(user_friend_list);
        body = join_strings(keys, '\n');
        free(keys);
    } else {
        body = strdup("");
    }
    serve_request(fd, body);
    free(body);
}

void handle_unfriend(int fd, dictionary_t *query) { 
  char *user = dictionary_get(query, "user");
  char *friends = dictionary_get(query, "friends");
  char **friend_list = split_string(friends, '\n');

  for (int i = 0; friend_list[i] != NULL; i++) {
    remove_friend(user, friend_list[i]);
    free(friend_list[i]);
  }
  free(friend_list);
  handle_friends(fd, query);
}

void handle_introduce(int fd, dictionary_t *query) { 
  char *user = dictionary_get(query, "user");
  char *friend = dictionary_get(query, "friend");
  char *host = dictionary_get(query, "host");
  char *port = dictionary_get(query, "port");

  int clientfd, status_code;
  rio_t rio;
  char buf[MAXLINE], *status_line, *version, *status, *desc;

  // connect to server
  clientfd = Open_clientfd(host, port);
  if (clientfd < 0) {
    fprintf(stderr, "Connection to server failed.\n");
    return;
  }
  rio_readinitb(&rio, clientfd);
  printf("clientfd %d\n", clientfd);

  // send GET request to server
  sprintf(buf, "GET /friends?user=%s HTTP/1.1\r\n\r\n", friend);
  Rio_writen(clientfd, buf, strlen(buf));
  printf("hoge1\n");
  // read status line
  Rio_readlineb(&rio, buf, MAXLINE);
  status_line = strdup(buf);
  printf("hoge2\n");
  // parse status line
  if (!parse_status_line(status_line, &version, &status, &desc)) {
    fprintf(stderr, "Failed to parse status line.\n");
    Close(clientfd);
    free(status_line);
    return;
  }

  status_code = atoi(status);
  free(version);
  free(status);
  free(desc);
  free(status_line);

  if (status_code != 200) {
    fprintf(stderr, "Server responded with status code %d.\n", status_code);
    Close(clientfd);
    return;
  }

  // skip headder
  do {
    Rio_readlineb(&rio, buf, MAXLINE);
  } while (strcmp(buf, "\r\n"));

  // read friend list and parse
  while (Rio_readlineb(&rio, buf, MAXLINE) > 0) {
    buf[strcspn(buf, "\r\n")] = 0; // remove new line
    char **friends = split_string(buf, '\n');
    for (int i = 0; friends[i] != NULL; i++) {
        add_friend(user, friends[i]);
        free(friends[i]);
    }
    free(friends);
  }

  //serve_request(clientfd, query);
  Close(clientfd);
}

void add_friend(const char *user, const char *friend) {
    dictionary_t *user_friend_list = dictionary_get(user_list, user);
    dictionary_t *friend_friend_list = dictionary_get(user_list, friend);

    if (!user_friend_list) {
        user_friend_list = make_dictionary(COMPARE_CASE_SENS, free);
        dictionary_set(user_list, user, user_friend_list);
    }

    if (!friend_friend_list) {
        friend_friend_list = make_dictionary(COMPARE_CASE_SENS, free);
        dictionary_set(user_list, friend, friend_friend_list);
    }

    if (!dictionary_get(user_friend_list, friend)) {
        dictionary_set(user_friend_list, friend, NULL);
    }

    if (!dictionary_get(friend_friend_list, user)) {
        dictionary_set(friend_friend_list, user, NULL);
    }
}

void remove_friend(const char *user, const char *friend) {
    dictionary_t *user_friend_list = dictionary_get(user_list, user);
    dictionary_t *friend_friend_list = dictionary_get(user_list, friend);

    if (user_friend_list) {
        dictionary_remove(user_friend_list, friend);
    }
    if (friend_friend_list) {
        dictionary_remove(friend_friend_list, friend);
    }
}

