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
#include <string.h>

#include "response.h"

int http_response_build(char *buffer, const char *protocol,
    http_response_t response)
{
    int len = 0;

    if (response.body != NULL) {
        len = strlen(response.body);
    }

    return sprintf(
        buffer,
        "%s %d %s\n%sServer: %s\nContent-Length: %d\nConnection: close\n\n%s",
        protocol,
        response.code,
        response.message,
        (response.headers != NULL ? response.headers : ""),
        "jorge-matricali/htcpcp",
        len,
        (response.body != NULL ? response.body : "")
    );
}
