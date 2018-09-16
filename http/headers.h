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

#ifndef HTTP_HEADERS_H
#define HTTP_HEADERS_H

typedef struct {
    char *field_name;
    char *field_value;
} http_header_t;

typedef struct {
    http_header_t **headers;
    int length;
} http_header_list_t;

void http_header_list_append(http_header_list_t *list, const char *name,
    const char *value);

const char *http_header_list_find(http_header_list_t *list, const char *name);

void http_header_list_destroy(http_header_list_t *list);

#endif /* HTTP_HEADERS_H */
