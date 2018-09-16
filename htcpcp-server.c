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
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#include "http/headers.h"
#include "http/request.h"
#include "http/response.h"
#include "http/access_log.h"
#include "logger.h"
#include "pot.h"

#define MAX_CHILDS 10
#define LISTEN_BACKLOG 500
#define PROTOCOL "HTCPCP/1.0"

int g_verbose = 0;
static pot_t *POT = NULL;

static http_response_t RESPONSE_POT_BUSY = {510, "Pot Busy", "Content-Type: message/coffepot\n", "Pot busy"};
static http_response_t RESPONSE_POT_READY = {200, "OK", "Content-Type: message/coffepot\n", "Pot ready to brew"};
static http_response_t RESPONSE_POT_NOT_FOUND = {404, "Pot Not Found", NULL, NULL};

http_response_t htcpcp_handle_brew(http_request_t request)
{
    // @TODO: Add response header "Safe: no"
    // @TODO: Parse "Accept-Additions" headers
    // @TODO: 406 Not Acceptable
    const char *content_type = http_header_list_find(request.headers, "Content-Type");

    if (content_type == NULL ||
        strcasecmp(content_type, "application/coffee-pot-command") != 0) {
        /* 10.4.16 415 Unsupported Media Type */
        return RESPONSE_UNSUPPORTED_MEDIA_TYPE;
    }

    pot_refresh(POT);

    if (strcmp(request.body, "start") == 0) {
        if (POT->status == POT_STATUS_BREWING) {
            return RESPONSE_POT_BUSY;
        }

        pot_brew(POT);

        return RESPONSE_OK;
    }

    if (strcmp(request.body, "stop") == 0) {
        /* It is not yet implemented :D */
    }

    /* I'm not sure what return code should we use in this case */
    return RESPONSE_BAD_REQUEST;
}

http_response_t htcpcp_handle_get(http_request_t request)
{
    return RESPONSE_OK;
}

http_response_t htcpcp_handle_propfind(http_request_t request)
{
    pot_refresh(POT);

    if (POT->status != POT_STATUS_READY) {
        return RESPONSE_POT_BUSY;
    }

    return RESPONSE_POT_READY;
}

http_response_t htcpcp_handle_when(http_request_t request)
{
    return (http_response_t) {
        .code = 406,
        .message = "Not Acceptable",
        .headers = "Additions-List: MILK\n",
        .body = NULL
    };
}

http_response_t htcpcp_request_handle(http_request_t request)
{
    if (strncmp(PROTOCOL, request.protocol, 1+strlen(PROTOCOL)) != 0) {
        /* Unsupported protocol */
        return RESPONSE_VERSION_NOT_SUPPORTED;
    }

    if (strncmp("/pot-1", request.path, 1+strlen("/pot-1")) != 0) {
        /* Not Found */
        return RESPONSE_POT_NOT_FOUND;
    }

    if (strncmp("BREW", request.method, 5) == 0
        || strncmp("POST", request.method, 5) == 0) {
        return htcpcp_handle_brew(request);
    }

    if (strncmp("GET", request.method, 4) == 0) {
        return htcpcp_handle_get(request);
    }

    if (strncmp("PROPFIND", request.method, 9) == 0) {
        return htcpcp_handle_propfind(request);
    }

    if (strncmp("WHEN", request.method, 5) == 0) {
        return htcpcp_handle_when(request);
    }

    return RESPONSE_BAD_REQUEST;
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
    access_log_open("access.log");

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
                http_request_read(socketfd, client_address, PROTOCOL, &htcpcp_request_handle);
            }
        }
    }

    for (int i = 0; i < MAX_CHILDS; ++i) {
        waitpid(children[i], NULL, 0);
    }

    pot_destroy(POT);

    /* Access log */
    access_log_close();
}
