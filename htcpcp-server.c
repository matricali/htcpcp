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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>

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

typedef struct {
    char *field_name;
    char *field_value;
} http_header_t;

typedef struct {
    http_header_t **headers;
    int length;
} http_header_list_t;

FILE *log_file = NULL;
int g_verbose = 0;

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

void http_header_list_append(http_header_list_t *list, const char *name,
    const char *value)
{
    if (list->headers == NULL) {
        list->headers = malloc((list->length+1) * sizeof(*list->headers));
    } else {
        list->headers = realloc(list->headers,
            (list->length+1) * sizeof(*list->headers));
    }

    list->headers[list->length] = malloc(sizeof *list->headers[list->length]);

    list->headers[list->length]->field_name = malloc(strlen(name)+1);
    strcpy(list->headers[list->length]->field_name, name);

    list->headers[list->length]->field_value = malloc(strlen(value)+1);
    strcpy(list->headers[list->length]->field_value, value);

    list->length++;
}

int build_response(char *buffer, int status, const char *headers,
    const char *body)
{
    int len = 0;
    char status_line[50] = "Unknown";

    if (status == 503) {
        strncpy(status_line, "Service Unavailable", 50);
    }
    if (status == 505) {
        strncpy(status_line, "HTTP Version Not Supported", 50);
    }
    if (status == 400) {
        strncpy(status_line, "Bad Request", 50);
    }
    if (status == 406) {
        strncpy(status_line, "Not Acceptable", 50);
    }
    if (status == 418) {
        strncpy(status_line, "I'm a teapot", 50);
    }
    if (status == 414) {
        strncpy(status_line, "Request-URI Too Long", 50);
    }
    if (status == 200) {
        strncpy(status_line, "OK", 50);
    }
    if (body != NULL) {
        len = strlen(body);
    }

    return sprintf(
        buffer,
        "%s %d %s\n%sServer: %s\nContent-Length: %d\nConnection: close\n\n%s",
        PROTOCOL,
        status,
        status_line,
        (headers != NULL ? headers : ""),
        "jorge-matricali/htcpcp",
        len,
        (body != NULL ? body : "")
    );
}

void process_request(int socket_fd, const char *source)
{
    long ret;
    static char buffer[BUFSIZE + 1];
    int status_code = 200;
    time_t timer;
    struct tm* tm_info;

    /* Request time */
    time(&timer);
    tm_info = localtime(&timer);

    /* Parsear cabeceras */
    char request_method[100] = "";
    char request_path[2084] = "";
    char request_protocol[100] = "";
    http_header_list_t *headers = NULL;

    /* Read buffer */
    ret = read(socket_fd, buffer, BUFSIZE);

    if (ret == 0 || ret == -1) {
        goto cleanup;
    }

    if (ret > 0 && ret < BUFSIZE) {
        /* Cerrar buffer */
        buffer[ret] = 0;
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
    for (i = 0; i < ret; i++) {
        if (buffer[i] == 0 || buffer[i] == ' ') {
            request_method[i] = 0;
            break;
        }
        request_method[i] = buffer[i];
    }
    /* 5.1.2 Request-URI */
    for (t = 0, i++; i < ret; i++) {
        if (buffer[i] == 0 || buffer[i] == ' ') {
            request_path[t] = 0;
            break;
        }
        if (t >= 2083) {
            status_code = 414;
            build_response(buffer, status_code, NULL, NULL);
            goto send;
        }
        request_path[t] = buffer[i];
        t++;
    }
    /* Request protocol version */
    for (t = 0, i++; i < ret - 1; i++) {
        if (buffer[i] == 0 || buffer[i] == ' '
        || (buffer[i] == '\r' && buffer[i+1] == '\n')) {
            request_protocol[t] = 0;
            i++;
            break;
        }
        request_protocol[t] = buffer[i];
        t++;
    }
    if (strncmp(PROTOCOL, request_protocol, 1+strlen(PROTOCOL)) != 0) {
        /* Unsupported protocol */
        status_code = 505;
        build_response(buffer, status_code, NULL, NULL);
        goto send;
    }

    /* 4.2 Message Headers */
    char header_name[2048] = {0};
    char header_value[2048] = {0};
    headers = malloc(sizeof *headers);
    headers->length = 0;
    headers->headers = NULL;

    while (i++ < ret - 1) {
        if (buffer[i] == '\r' && buffer[i+1] == '\n') {
            break;
        }
        /* Nombre */
        char f = 0;
        for (t = 0; i < ret - 1; i++) {
            if (f == 0 && buffer[i] == ' ') {
                continue;
            }
            f = 1;
            if (buffer[i] == 0 || buffer[i] == ':') {
                header_name[t] = 0;
                break;
            }
            if (buffer[i] == '\r' && buffer[i+1] == '\n') {
                header_name[t] = 0;
                i++;
                break;
            }
            header_name[t] = buffer[i];
            t++;
        }
        /* Valor */
        f = 0;
        for (t = 0, i++; i < ret - 1; i++) {
            if (f == 0 && buffer[i] == ' ') {
                continue;
            }
            f = 1;
            if (buffer[i] == 0
            || (buffer[i] == '\r' && buffer[i+1] == '\n')) {
                header_value[t] = 0;
                if (buffer[i] == '\r' && buffer[i+1] == '\n') {
                    i++;
                }
                break;
            }
            header_value[t] = buffer[i];
            t++;
        }

        http_header_list_append(headers, header_value, header_name);
    }

    // @TODO: Validate resource

    if (strncmp("BREW", request_method, 5) == 0
        || strncmp("POST", request_method, 5) == 0) {
        // @TODO: Content-Type MUST be "application/coffee-pot-command"
        // @TODO: Add response header "Safe: no"
        // @TODO: Parse "Accept-Additions" headers
        // @TODO: 406 Not Acceptable
        // @TODO: Parse body. coffee-message-body = "start" | "stop"
        status_code = 200;
        build_response(buffer, status_code, NULL, NULL);
        goto send;
    }

    if (strncmp("GET", request_method, 4) == 0) {
        status_code = 200;
        build_response(buffer, status_code, NULL, "<h1>GET received</h1>\n:)");
        goto send;
    }

    if (strncmp("PROPFIND", request_method, 9) == 0) {
        status_code = 200;
        build_response(buffer, status_code, "Content-Type: message/coffepot\n",
            "Pot ready to brew");
        goto send;
    }

    if (strncmp("WHEN", request_method, 5) == 0) {
        status_code = 406;
        build_response(buffer, status_code, "Additions-List: MILK\n", NULL);
        goto send;
    }

    /* I'm a teapot :D */
    status_code = 418;
    build_response(buffer, status_code, NULL, NULL);

send:
    write(socket_fd, buffer, strlen(buffer));
    access_log(source, "-", "-", tm_info, request_method, request_path,
        request_protocol, status_code, strlen(buffer));

cleanup:
    logger(LOG_DEBUG, "Closing connection.\n");
    shutdown(socket_fd, SHUT_RDWR);
    close(socket_fd);

    if (headers != NULL) {
        if (headers->headers != NULL) {
            for (int p = 0; p < headers->length; p++) {
                free(headers->headers[p]->field_name);
                free(headers->headers[p]->field_value);
                free(headers->headers[p]);
            }
            free(headers->headers);
        }
        free(headers);
    }
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

    for (int i = 0; i < MAX_CHILDS; i++) {
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

    for (int i = 0; i < MAX_CHILDS; i++) {
        waitpid(children[i], NULL, 0);
    }

    /* Access log */
    if (log_file != NULL) {
        fclose(log_file);
    }
}
