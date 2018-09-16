/*
Copyright (C) 2018 Jorge Matricali <jorgematricali@gmail.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h> /* va_list, va_start, va_end */
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#define BUFSIZE 8096
#define MAX_CHILDS 10
#define LISTEN_BACKLOG 500
#define PROTOCOL "HTCPCP/1.0"

enum log_level {
    LOG_NONE,
    LOG_FATAL,
    LOG_ERROR,
    LOG_WARNING,
    LOG_NOTICE,
    LOG_INFO,
    LOG_DEBUG,
    LOG_NEVER
};

/* Coffee Pot */
typedef enum pot_status {
    POT_STATUS_ERROR = 0,
    POT_STATUS_READY = 1,
    POT_STATUS_BREWING = 2
} pot_status_t;

typedef struct {
    pot_status_t status;
    int served;
    time_t start_time;
    time_t end_time;
    pthread_mutex_t mutex;
} pot_t;

/* HTTP */
typedef struct {
    char *field_name;
    char *field_value;
} http_header_t;

typedef struct {
    http_header_t **headers;
    int length;
} http_header_list_t;

typedef struct {
    char method[100];
    char path[2084];
    char protocol[100];
    http_header_list_t *headers;
    int content_length;
    char body[2084];
} http_request_t;

typedef struct {
    int code;
    const char *message;
    const char *headers;
    const char *body;
} http_response_t;

http_response_t RESPONSE_OK = {200, "OK", NULL, NULL};
http_response_t RESPONSE_BAD_REQUEST = {400, "Bad Request", NULL, NULL};
http_response_t RESPONSE_POT_BUSY = {510, "Pot Busy", "Content-Type: message/coffepot\n", "Pot busy"};
http_response_t RESPONSE_POT_READY = {200, "OK", "Content-Type: message/coffepot\n", "Pot ready to brew"};
http_response_t RESPONSE_POT_NOT_FOUND = {404, "Pot Not Found", NULL, NULL};
http_response_t RESPONSE_URI_TOO_LONG = {414, "Request-URI Too Long", NULL, NULL};
http_response_t RESPONSE_UNSUPPORTED_MEDIA_TYPE = {415, "Unsupported Media Type", NULL, NULL};
http_response_t RESPONSE_I_AM_A_TEAPOT = {418, "I'm a teapot", "Content-Type: text/plain\n", "I'm a teapot"};
http_response_t RESPONSE_VERSION_NOT_SUPPORTED = {505, "HTTP Version Not Supported", NULL, NULL};

FILE *log_file = NULL;
int g_verbose = 0;
static pot_t *POT = NULL;

void logger(enum log_level level, const char *format, ...) {
    if (level == LOG_NEVER || level == LOG_NONE) {
        return;
    }
    if (level == LOG_DEBUG && g_verbose == 0) {
        return;
    }

    FILE *stream = stderr;

    if (level == LOG_INFO || level == LOG_NOTICE || level == LOG_DEBUG) {
        stream = stdout;
    }

    va_list args;
    va_start(args, format);
    vfprintf(stream, format, args);
    va_end (args);
}

void access_log(const char *host, const char *ident, const char *authuser,
    struct tm* tm_info, const char *request_method, const char *request_path,
    const char *request_protocol, int status, int bytes)
{
    char datetime[27];
    strftime(datetime, 27, "%d/%b/%Y:%H:%M:%S %z", tm_info);

    logger(LOG_INFO, "%s %s %s [%s] \"%s %s %s\" %d %d\n",
        host, "-", "-", datetime, request_method, request_path,
        request_protocol, status, bytes);

    if (log_file > 0) {
        fprintf(log_file, "%s %s %s [%s] \"%s %s %s\" %d %d\n",
            host, "-", "-", datetime, request_method, request_path,
            request_protocol, status, bytes);
        fflush(log_file);
    }
}

/* Coffee pot */
void pot_init(pot_t *pot)
{
    pot->status = POT_STATUS_READY;
    pot->served = 0;
    pot->start_time = 0;
    pot->end_time = 0;
}

void pot_refresh(pot_t *pot)
{
    pthread_mutex_lock(&pot->mutex);
    if (pot->status == POT_STATUS_BREWING) {
        time_t cur_time = time(NULL);
        if (cur_time > pot->end_time) {
            pot->status = POT_STATUS_READY;
            ++pot->served;
        }
    }
    pthread_mutex_unlock(&pot->mutex);
}

void pot_brew(pot_t *pot)
{
    pthread_mutex_lock(&pot->mutex);
    if (pot->status != POT_STATUS_READY) {
        pthread_mutex_unlock(&pot->mutex);
        logger(LOG_DEBUG, "POT isnt READY\n");
        return;
    }
    pot->start_time = time(NULL);
    pot->end_time = pot->start_time + 30;
    pot->status = POT_STATUS_BREWING;
    pthread_mutex_unlock(&pot->mutex);
}

void pot_destroy(pot_t *pot)
{
    free(pot);
    pot = NULL;
}

/* HTTP */
void http_header_list_append(http_header_list_t *list, const char *name,
    const char *value)
{
    if (list->headers == NULL) {
        list->headers = malloc((list->length+1) * sizeof(*list->headers));
    } else {
        list->headers = realloc(list->headers,
            (list->length+1) * sizeof(*list->headers));
    }

    http_header_t *header = malloc(sizeof *header);

    header->field_name = malloc(strlen(name)+1);
    strcpy(header->field_name, name);

    header->field_value = malloc(strlen(value)+1);
    strcpy(header->field_value, value);

    list->headers[list->length] = header;
    ++list->length;
}

const char *http_header_list_find(http_header_list_t *list, const char *name)
{
    if (list == NULL) {
        return NULL;
    }
    for (int i = 0; i < list->length; ++i) {
        if (strcasecmp(list->headers[i]->field_name, name) == 0) {
            return list->headers[i]->field_value;
        }
    }
    return NULL;
}

void http_header_list_destroy(http_header_list_t *list)
{
    if (list != NULL) {
        if (list->headers != NULL) {
            for (int p = 0; p < list->length; p++) {
                if (list->headers[p] != NULL) {
                    free(list->headers[p]->field_name);
                    free(list->headers[p]->field_value);
                    free(list->headers[p]);
                    list->headers[p] = NULL;
                }
            }
            free(list->headers);
            list->headers = NULL;
        }
        free(list);
        list = NULL;
    }
}

int http_build_response(char *buffer, http_response_t response)
{
    int len = 0;

    if (response.body != NULL) {
        len = strlen(response.body);
    }

    return sprintf(
        buffer,
        "%s %d %s\n%sServer: %s\nContent-Length: %d\nConnection: close\n\n%s",
        PROTOCOL,
        response.code,
        response.message,
        (response.headers != NULL ? response.headers : ""),
        "jorge-matricali/htcpcp",
        len,
        (response.body != NULL ? response.body : "")
    );
}

void process_request(int socket_fd, const char *source)
{
    long len;
    static char buffer[BUFSIZE + 1];
    time_t timer;
    struct tm* tm_info;

    /* Request time */
    time(&timer);
    tm_info = localtime(&timer);

    /* Parsear cabeceras */
    http_request_t request = {{0}};
    http_response_t response = {0};

    /* Read buffer */
    len = read(socket_fd, buffer, BUFSIZE);

    if (len == 0 || len == -1) {
        goto cleanup;
    }

    if (len > 0 && len < BUFSIZE) {
        /* Cerrar buffer */
        buffer[len] = 0;
    } else {
        buffer[0] = 0;
    }

    /*
    Parsing request-line
    https://tools.ietf.org/html/rfc2616#section-5.1
    */
    int i;
    int t;

    /* 5.1.1 Method */
    for (t = 0, i = 0; ; ++i, ++t) {
        if (i >= len || buffer[i] == 0) {
            /* We expect a SP as a token separator */
            goto parse_error;
        }
        if (buffer[i] == ' ') {
            request.method[t] = 0;
            break;
        }
        request.method[t] = buffer[i];
    }
    /* 5.1.2 Request-URI */
    for (t = 0, ++i; ; ++i, ++t) {
        if (i >= len || buffer[i] == 0) {
            /* We expect a SP as a token separator */
            goto parse_error;
        }
        if (t >= 2083) {
            response = RESPONSE_URI_TOO_LONG;
            goto send;
        }
        if (buffer[i] == ' ') {
            request.path[t] = 0;
            break;
        }
        request.path[t] = buffer[i];
    }
    /* Request protocol version */
    for (t = 0, ++i; ; ++i, ++t) {
        if (i >= len || buffer[i] == 0 || buffer[i] == ' ') {
            /* We expect a CRLF */
            goto parse_error;
        }
        if (buffer[i] == '\r' && buffer[i+1] == '\n') {
            request.protocol[t] = 0;
            ++i;
            break;
        }
        request.protocol[t] = buffer[i];
    }

    if (strncmp(PROTOCOL, request.protocol, 1+strlen(PROTOCOL)) != 0) {
        /* Unsupported protocol */
        response = RESPONSE_VERSION_NOT_SUPPORTED;
        goto send;
    }

    if (strncmp("/pot-1", request.path, 1+strlen("/pot-1")) != 0) {
        /* Not Found */
        response = RESPONSE_POT_NOT_FOUND;
        goto send;
    }

    /* 4.2 Message Headers */
    char header_name[2048] = {0};
    char header_value[2048] = {0};
    request.headers = malloc(sizeof *request.headers);
    request.headers->length = 0;
    request.headers->headers = NULL;

    while (++i) {
        if (i >= len || buffer[i] == 0) {
            /* We expect a CRLF */
            goto parse_error;
        }
        if (buffer[i] == '\r' && buffer[i+1] == '\n') {
            ++i;
            break;
        }
        /* Nombre */
        while (i < len && buffer[i] == ' ') {
            ++i;
        }
        for (t = 0; ; ++i, ++t) {
            if (i >= len || buffer[i] == 0) {
                /* We expect ':' as a separator */
                goto parse_error;
            }
            if (buffer[i] == ':') {
                header_name[t] = 0;
                break;
            }
            if (buffer[i] == '\r' && buffer[i+1] == '\n') {
                header_name[t] = 0;
                --i; /* Parse again as an empty header value */
                break;
            }
            header_name[t] = buffer[i];
        }
        /* Leading whitespaces */
        while (++i < len && buffer[i] == ' ') {}
        /* Valor */
        for (t = 0; ; ++i, ++t) {
            if (i >= len || buffer[i] == 0) {
                /* We expect a CRLF */
                goto parse_error;
            }
            if (buffer[i] == '\r' && buffer[i+1] == '\n') {
                header_value[t] = 0;
                ++i;
                break;
            }
            header_value[t] = buffer[i];
        }

        http_header_list_append(request.headers, header_name, header_value);
    }

    /* 14.13 Content-Length */
    request.content_length = 0;
    const char *content_length_str = http_header_list_find(request.headers,
        "Content-Length");

    if (content_length_str != NULL) {
        request.content_length = atoi(content_length_str);
    }

    if (request.content_length < 0) {
        /* 10.4.1 400 Bad Request */
        goto parse_error;
    }

    /* 4.3 Message Body */
    for (t = 0; t < request.content_length && (++i < len); ++t) {
        request.body[t] = buffer[i];
    }
    request.body[t] = 0;

    if (strncmp("BREW", request.method, 5) == 0
        || strncmp("POST", request.method, 5) == 0) {
        // @TODO: Add response header "Safe: no"
        // @TODO: Parse "Accept-Additions" headers
        // @TODO: 406 Not Acceptable
        const char *content_type = http_header_list_find(request.headers, "Content-Type");

        if (content_type == NULL ||
            strcasecmp(content_type, "application/coffee-pot-command") != 0) {
            /* 10.4.16 415 Unsupported Media Type */
            response = RESPONSE_UNSUPPORTED_MEDIA_TYPE;
            goto send;
        }

        pot_refresh(POT);

        if (strcmp(request.body, "start") == 0) {
            if (POT->status == POT_STATUS_BREWING) {
                response = RESPONSE_POT_BUSY;
                goto send;
            }

            pot_brew(POT);

            response = RESPONSE_OK;
            goto send;
        }

        if (strcmp(request.body, "stop") == 0) {
            /* It is not yet implemented :D */
        }

        /* I'm not sure what return code should we use in this case */
        response = RESPONSE_BAD_REQUEST;
        goto send;
    }

    if (strncmp("GET", request.method, 4) == 0) {
        response = RESPONSE_OK;
        goto send;
    }

    if (strncmp("PROPFIND", request.method, 9) == 0) {
        pot_refresh(POT);

        if (POT->status != POT_STATUS_READY) {
            response = RESPONSE_POT_BUSY;
            goto send;
        }

        response = RESPONSE_POT_READY;
        goto send;
    }

    if (strncmp("WHEN", request.method, 5) == 0) {
        response.code = 406;
        response.message = "Not Acceptable";
        response.headers = "Additions-List: MILK\n";
        response.body = NULL;
        goto send;
    }

    /* I'm a teapot :D */
    response = RESPONSE_I_AM_A_TEAPOT;
    goto send;

parse_error:
    response = RESPONSE_BAD_REQUEST;

send:
    http_build_response(buffer, response);
    write(socket_fd, buffer, strlen(buffer));
    access_log(source, "-", "-", tm_info, request.method, request.path,
        request.protocol, response.code, strlen(buffer));

cleanup:
    logger(LOG_DEBUG, "Closing connection.\n");
    shutdown(socket_fd, SHUT_RDWR);
    close(socket_fd);
    http_header_list_destroy(request.headers);
}

void usage(const char *p)
{
    printf("\nusage: %s [-h] [-v] [-p <port>]\n\n", p);
}

int main(int argc, char *argv[])
{
    int port = 8888;
    int listenfd;
    int socketfd;
    int pid;
    pid_t children[MAX_CHILDS];
    int option = 1;
    int opt;

    static struct sockaddr_in serv_addr;
    static struct sockaddr_in cli_addr;
    socklen_t len = 0;

    while ((opt = getopt(argc, argv, "p:vh")) != -1) {
        switch (opt) {
            case 'p':
                port = atoi(optarg);
                break;
            case 'v':
                g_verbose = 1;
                break;
            case 'h':
                usage(argv[0]);
                printf("  -h                This help\n"
                        "  -v                Verbose mode\n"
                        "  -p <port>         Port number\n");
                exit(EXIT_SUCCESS);
            default:
                usage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    /* Access log */
    log_file = fopen("access.log", "a");
    if (log_file < 0) {
        logger(LOG_ERROR, "Error opening log file.\n");
    }

    logger(LOG_INFO, "Starting htcpcp-server on port %d...\n", port);

    /* Place POT in shared memory */
    int prot = PROT_READ | PROT_WRITE;
    int flags = MAP_SHARED | MAP_ANONYMOUS;
    POT = mmap(NULL, sizeof(pot_t), prot, flags, -1, 0);
    if (POT == MAP_FAILED) {
        logger(LOG_FATAL, "Cannot allocate shared memory.\n");
        exit(EXIT_FAILURE);
    }

    pot_init(POT);

    /* Initialise mutex so it works properly in shared memory */
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
    pthread_mutex_init(&POT->mutex, &attr);

    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd < 0) {
        logger(LOG_FATAL, "Error opening listen socket.\n");
        return EXIT_FAILURE;
    }

    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (char*) &option,
        sizeof(option));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(port);

    if (bind(listenfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
        logger(LOG_FATAL, "Cannot bind port\n");
        return EXIT_FAILURE;
    }

    if (listen(listenfd, LISTEN_BACKLOG) < 0) {
        logger(LOG_FATAL, "Cannot listen on port\n");
        return EXIT_FAILURE;
    }

    for (int i = 0; i < MAX_CHILDS; ++i) {
        pid = fork();

        if (pid < 0) {
            logger(LOG_FATAL, "Cannot fork!\n");
            break;
        }

        if (pid) {
            children[i] = pid;
        }

        if (pid == 0) {
            /* Child process */
            for (;;) {
                len = sizeof(cli_addr);

                socketfd = accept(listenfd, (struct sockaddr *) &cli_addr, &len);

                char client_address[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(cli_addr.sin_addr), client_address, INET_ADDRSTRLEN);

                if (socketfd < 0) {
                    logger(LOG_FATAL, "Cannot accept incoming connection from %s\n", client_address);
                    close(socketfd);
                    continue;
                }

                logger(LOG_DEBUG, "Incoming connection from: %s\n", client_address);
                process_request(socketfd, client_address);
            }
        }
    }

    for (int i = 0; i < MAX_CHILDS; ++i) {
        waitpid(children[i], NULL, 0);
    }

    pot_destroy(POT);

    /* Access log */
    if (log_file != NULL) {
        fclose(log_file);
    }
}
