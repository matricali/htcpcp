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
#include <stdarg.h> /* va_list, va_start, va_end */

#include "logger.h"

void logger(enum log_level level, const char *format, ...)
{
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
