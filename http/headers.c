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
#include <stdlib.h>
#include <string.h>

#include "headers.h"

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
