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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#define BUFSIZE 8096

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

void logger(enum log_level level, const char *format, ...) {
    if (level == LOG_NEVER || level == LOG_NONE) {
        return;
    }
    va_list args;
    va_start(args, format);
    vfprintf(stdout, format, args);
    va_end (args);
}

void process_request(int socket_fd, const char *source)
{
    printf("> %s\n", source);

    long ret;
    static char buffer[BUFSIZE + 1];

    ret = read(socket_fd, buffer, BUFSIZE);

    if (ret == 0 || ret == -1) {
        write(socket_fd, "HTTP/1.1 403 Forbidden\r\n\r\n", 26);
        logger(LOG_ERROR, "403 Forbidden\tFailed to read browser request.\n");
        goto cleanup;
    }

    if (ret > 0 && ret < BUFSIZE) {
        /* Cerrar buffer */
        buffer[ret] = 0;
    } else {
        buffer[0] = 0;
    }

    /* Parsear cabeceras */
    char request_method[100];
    char request_path[255];
    char request_protocol[100];

    int i;
    int t;

    logger(LOG_DEBUG, "---BUFFER---\n%s\n---------", buffer);

    /* Request method */
    for (i = 0; i < ret; i++) {
        if (buffer[i] == 0 || buffer[i] == ' ') {
            request_method[i] = 0;
            break;
        }
        request_method[i] = buffer[i];
    }
    i++;
    /* Request path */
    for (t = 0; i < ret; i++) {
        if (buffer[i] == 0 || buffer[i] == ' ') {
            request_path[t] = 0;
            break;
        }
        request_path[t] = buffer[i];
        t++;
    }
    i++;
    /* Request protocol */
    for (t = 0; i < ret - 1; i++) {
        if (buffer[i] == 0 || (buffer[i] == '\r' && buffer[i+1] == '\n')) {
            request_protocol[t] = 0;
            break;
        }
        request_protocol[t] = buffer[i];
        t++;
    }
    logger(LOG_DEBUG, "method=<%s> path=<%s> protocol=<%s>",
        request_method, request_path, request_protocol);

    /* -------- */

    sprintf(
        buffer,
        "HTTP/1.1 405 Method Not Allowed\nServer: %s\nContent-Length: 0\nConnection: close\n\n",
        "jorge-matricali/htcpcp"
    );

    write(socket_fd, buffer, strlen(buffer));
    sleep(1);

cleanup:
    logger(LOG_DEBUG, "Closing connection.\n");
    close(socket_fd);
    exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[])
{
    int port = 8888;
    int listenfd;
    int socketfd;
    int pid;
    int option = 1;

    static struct sockaddr_in serv_addr;
    static struct sockaddr_in cli_addr;
    socklen_t len = 0;

    printf("Starting htcpcp-server on port %d...\n", port);

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

    if (listen(listenfd, 64) < 0) {
        logger(LOG_FATAL, "Cannot listen on port\n");
        return EXIT_FAILURE;
    }

    for (;;) {
        len = sizeof(cli_addr);

        socketfd = accept(listenfd, (struct sockaddr *) &cli_addr, &len);

        char client_address[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(cli_addr.sin_addr), client_address, INET_ADDRSTRLEN);

        if (socketfd < 0) {
            logger(LOG_FATAL, "Cannot accept incoming connection from %s\n", client_address);
            (void) close(socketfd);
            return EXIT_FAILURE;
        }

        logger(LOG_INFO, "Incoming connection from %s\n", client_address);

        pid = fork();
        if (pid < 0) {
            logger(LOG_FATAL, "Cannot fork!\n");
            return EXIT_FAILURE;
        }

        if (pid == 0) {
            (void) close(listenfd);
            process_request(socketfd, client_address);
            exit(EXIT_SUCCESS);
        } else {
            (void) close(socketfd);
        }
    }
}
