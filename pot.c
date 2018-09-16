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
#include <time.h>
#include <pthread.h>

#include "pot.h"
#include "logger.h"

/* Coffee pot */
void pot_init(pot_t *pot)
{
    pot->status = POT_STATUS_READY;
    pot->served = 0;
    pot->start_time = 0;
    pot->end_time = 0;
}

void pot_refresh(pot_t *pot)
{
    pthread_mutex_lock(&pot->mutex);
    if (pot->status == POT_STATUS_BREWING) {
        time_t cur_time = time(NULL);
        if (cur_time > pot->end_time) {
            pot->status = POT_STATUS_READY;
            ++pot->served;
        }
    }
    pthread_mutex_unlock(&pot->mutex);
}

void pot_brew(pot_t *pot)
{
    pthread_mutex_lock(&pot->mutex);
    if (pot->status != POT_STATUS_READY) {
        pthread_mutex_unlock(&pot->mutex);
        logger(LOG_DEBUG, "POT isnt READY\n");
        return;
    }
    pot->start_time = time(NULL);
    pot->end_time = pot->start_time + 30;
    pot->status = POT_STATUS_BREWING;
    pthread_mutex_unlock(&pot->mutex);
}

void pot_destroy(pot_t *pot)
{
    free(pot);
    pot = NULL;
}
