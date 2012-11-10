/*
    pidfile.c - interact with pidfiles
    Copyright (c) 1995  Martin Schulze <Martin.Schulze@Linux.DE>

    This file is part of the sysklogd package, a kernel and system log daemon.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111, USA
*/

/*
 * Sat Aug 19 13:24:33 MET DST 1995: Martin Schulze
 *  First version (v0.2) released
 */
 
/*
 * Edited by Imma.
 * July 14, 2010 
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

/* read_pid
 *
 * Reads the specified pidfile and returns the read pid.
 * 0 is returned if either there's no pidfile, it's empty
 * or no pid can be read.
 */
int read_pid (char *pid_file)
{
  FILE *f;
  int pid;


  if (!(f = fopen(pid_file, "r"))) {
    /*perror(pid_file);*/
    return 0;
  }
  fscanf(f, "%d", &pid);
  fclose(f);
  return pid;
}


/* check_pid
 *
 * Reads the pid using read_pid and looks up the pid in the process
 * table (using /proc) to determine if the process already exists. If
 * so 1 is returned, otherwise 0.
 */
int check_pid (char *pid_file)
{
  int pid = read_pid(pid_file);

  /* Amazing ! _I_ am already holding the pid file... */
  if ((!pid) || (pid == getpid ()))
    return 0;

  /*
   * The 'standard' method of doing this is to try and do a 'fake' kill
   * of the process.  If an ESRCH error is returned the process cannot
   * be found -- GW
   */
  /* But... errno is usually changed only on error.. */
  if (kill(pid, 0) && errno == ESRCH)
    return(0);

  return pid;
}


/* write_pid
 *
 * Writes the pid to the specified file. If that fails 0 is
 * returned, otherwise the pid.
 */
int write_pid (char *pid_file)
{
  FILE *f;
  int fd;
  int pid;

  if ( ((fd = open(pid_file, O_RDWR|O_CREAT|O_TRUNC, 0644)) == -1)
       || ((f = fdopen(fd, "r+")) == NULL) ) {
      /* fprintf(stderr, "Can't open or create %s.\n", pid_file); */
      perror(pid_file);
      return 0;
  }

  if (flock(fd, LOCK_EX|LOCK_NB) == -1) {
      fscanf(f, "%d", &pid);
      fclose(f);
      /* printf("Can't lock, lock is held by pid %d.\n", pid); */
      return 0;
  }

  pid = getpid();
  if (!fprintf(f,"%d\n", pid)) {
      /* printf("Can't write pid , %s.\n", strerror(errno)); */
      close(fd);
      return 0;
  }
  fflush(f);

  if (flock(fd, LOCK_UN) == -1) {
      /* printf("Can't unlock pidfile %s, %s.\n", pid_file, strerror(errno)); */
      close(fd);
      return 0;
  }
  close(fd);

  return pid;
}


/* remove_pid
 *
 * Remove the the specified file. The result from unlink(2)
 * is returned
 */
int remove_pid (char *pid_file)
{
  return unlink (pid_file);
}

