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

#ifndef HTTP_REQUEST_H
#define HTTP_REQUEST_H

#include "headers.h"

typedef struct {
    char method[100];
    char path[2084];
    char protocol[100];
    http_header_list_t *headers;
    int content_length;
    char body[2084];
} http_request_t;

int http_request_parse(http_request_t *request, const char *buffer, size_t len);

#endif /* HTTP_REQUEST_H */
