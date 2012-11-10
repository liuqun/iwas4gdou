/*	This is a file of iwas4gdou. (2010-09-10)

    Copyright (C) 2010 Imma. <474445006@QQ.com>

    iwas4gdou is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
 
 
#define IWAS4G_HWADDR_LEN		6

#define IWAS4G_WATCH_EAPOL_KEY			1
#define IWAS4G_WATCH_EAP_FAILURE		2
#define IWAS4G_WATCH_TIMEOUT				0
#define IWAS4G_WATCH_ERROR					-1

typedef struct {
	char *if_name;
	unsigned char hw_addr[IWAS4G_HWADDR_LEN];
	int to_ms;
	int to_retry;
} iwas4g_env;


int 
iwas4g_begin_session (iwas4g_env *env);


void
iwas4g_end_session (void);


int
iwas4g_auth (char *usr, char *psw);


int
iwas4g_watch (void);


int
iwas4g_reauth (void);


int
iwas4g_deauth (void);


char *
iwas4g_get_error (void);

