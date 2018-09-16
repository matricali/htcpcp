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

#ifndef HTTP_RESPONSE_H
#define HTTP_RESPONSE_H

#include <stdlib.h>

typedef struct {
    int code;
    const char *message;
    const char *headers;
    const char *body;
} http_response_t;

int http_response_build(char *buffer, const char *protocol,
    http_response_t response);

/* HTCPCP */
static http_response_t RESPONSE_OK = {200, "OK", NULL, NULL};
static http_response_t RESPONSE_BAD_REQUEST = {400, "Bad Request", NULL, NULL};
static http_response_t RESPONSE_URI_TOO_LONG = {414, "Request-URI Too Long", NULL, NULL};
static http_response_t RESPONSE_UNSUPPORTED_MEDIA_TYPE = {415, "Unsupported Media Type", NULL, NULL};
static http_response_t RESPONSE_I_AM_A_TEAPOT = {418, "I'm a teapot", "Content-Type: text/plain\n", "I'm a teapot"};
static http_response_t RESPONSE_VERSION_NOT_SUPPORTED = {505, "HTTP Version Not Supported", NULL, NULL};

#endif /* HTTP_RESPONSE_H */
