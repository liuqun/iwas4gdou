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


static unsigned char s[256];
static unsigned int i, j;
static unsigned char temp;


/* KSA */
void 
rc4_init (unsigned char *key, unsigned int key_length)
{

    for (i = 0; i < 256; i++)
        s[i] = i;

    for (i = j = 0; i < 256; i++) {
        j = (j + key[i % key_length] + s[i]) & 255;
        temp = s[i];
        s[i] = s[j];
        s[j] = temp;
    }

    i = j = 0;
}


/* PRGA */
unsigned char 
rc4_output (void) 
{
    i = (i + 1) & 255;
    j = (j + s[i]) & 255;

    temp = s[i];
    s[i] = s[j];
    s[j] = temp;

    return s[(s[i] + s[j]) & 255];
}

