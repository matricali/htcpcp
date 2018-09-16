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

#ifndef LOGGER_H
#define LOGGER_H

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

extern int g_verbose;

void logger(enum log_level level, const char *format, ...);

#endif /* LOGGER_H */
