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

#ifndef POT_H
#define POT_H

/* Coffee Pot */
typedef enum pot_status {
    POT_STATUS_ERROR = 0,
    POT_STATUS_READY = 1,
    POT_STATUS_BREWING = 2
} pot_status_t;

typedef struct {
    pot_status_t status;
    int served;
    time_t start_time;
    time_t end_time;
    pthread_mutex_t mutex;
} pot_t;

void pot_brew(pot_t *pot);
void pot_destroy(pot_t *pot);
void pot_init(pot_t *pot);
void pot_refresh(pot_t *pot);

#endif /* POT_H */
