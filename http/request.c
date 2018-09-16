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
#include <stdlib.h> /* malloc */

#include "request.h"
#include "headers.h"

/**
 * Parse HTTP request from buffer into http_request_t struct
 * @author Jorge Matricali <jorgematricali@gmail.com>
 * @param  request Destination
 * @param  buffer  Buffer to be read
 * @param  len     Buffer size
 * @return         1 = BAD_REQUEST, 2 = URI_TOO_LONG
 */
int http_request_parse(http_request_t *request, const char *buffer, size_t len)
{
    int i;
    int t;

    /*
    Parsing request-line
    https://tools.ietf.org/html/rfc2616#section-5.1
    */

    /* 5.1.1 Method */
    for (t = 0, i = 0; ; ++i, ++t) {
        if (i >= len || buffer[i] == 0) {
            /* We expect a SP as a token separator */
            goto parse_error;
        }
        if (buffer[i] == ' ') {
            request->method[t] = 0;
            break;
        }
        request->method[t] = buffer[i];
    }
    /* 5.1.2 Request-URI */
    for (t = 0, ++i; ; ++i, ++t) {
        if (i >= len || buffer[i] == 0) {
            /* We expect a SP as a token separator */
            goto parse_error;
        }
        if (t >= 2083) {
            return 2; /* Request-URI too long */
        }
        if (buffer[i] == ' ') {
            request->path[t] = 0;
            break;
        }
        request->path[t] = buffer[i];
    }
    /* Request protocol version */
    for (t = 0, ++i; ; ++i, ++t) {
        if (i >= len || buffer[i] == 0 || buffer[i] == ' ') {
            /* We expect a CRLF */
            goto parse_error;
        }
        if (buffer[i] == '\r' && buffer[i+1] == '\n') {
            request->protocol[t] = 0;
            ++i;
            break;
        }
        request->protocol[t] = buffer[i];
    }

    /* 4.2 Message Headers */
    char header_name[2048] = {0};
    char header_value[2048] = {0};
    request->headers = malloc(sizeof *request->headers);
    request->headers->length = 0;
    request->headers->headers = NULL;

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

        http_header_list_append(request->headers, header_name, header_value);
    }

    /* 14.13 Content-Length */
    request->content_length = 0;
    const char *content_length_str = http_header_list_find(request->headers,
        "Content-Length");

    if (content_length_str != NULL) {
        request->content_length = atoi(content_length_str);
    }

    if (request->content_length < 0) {
        /* 10.4.1 400 Bad Request */
        goto parse_error;
    }

    /* 4.3 Message Body */
    for (t = 0; t < request->content_length && (++i < len); ++t) {
        request->body[t] = buffer[i];
    }
    request->body[t] = 0;
    return 0;

parse_error:
    return 1; /* Bad Request */
}
