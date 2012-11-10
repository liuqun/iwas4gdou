/*  iwas4gdou  0.2 release (2010-09-10)
         -- IEEE802.1x Wired Authentication Supplicant for GDOU 


    Copyright (C) 2010 Imma. <474445006@QQ.com>

    This program is free software: you can redistribute it and/or modify
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


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <time.h>
#include <getopt.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include "pidfile.h"
#include "iwas4g.h"

#define PSW_MAX      128
#define USR_MAX      64
#define PSW_PROMPT  "Please enter your password:"
#define PID_FILE    "/var/run/iwas4gdou-%s.pid"
#define OUT_FILE    "/tmp/iwas4gdou-%s"

int auth_mode = 0, 
    deauth_mode = 0, 
    help_mode = 0,
    need_reauth = 0,
    need_daemon = 1, 
    need_compatibility = 0,
    interval = 190;

char *if_name, *usr, *psw;
char pid_file[PATH_MAX];

static int get_opt (int argc, char **argv);
static int bind_device (void);
static void free_device (void);
static void termination (int sig);
static int reauth (void);
static int reauth_c (void);
static int daemonize (void);
static void usage (void);


int main (int argc, char **argv)
{
  int old_pid;

  if (get_opt(argc, argv)) {
    return (-1);
  }

  sprintf(pid_file, PID_FILE, if_name);
  if (check_pid(pid_file)) {
    old_pid = read_pid(pid_file);
    if (deauth_mode) {
      kill(old_pid, SIGTERM);
      printf("De-authenticate.\n");
    } else {
      fprintf(stderr, "iwas4gdou (%d) was already run on `%s'.\n",
              old_pid, if_name);
      return (-1);
    }
  } else {
    remove_pid(pid_file);
  }

  if (auth_mode) {
    if (bind_device()) {
      return (-1);
    }

    if (!iwas4g_auth(usr, psw)) {
      printf("Authentication succeeds.\n");
      if (need_reauth) {
        if (need_daemon) {
          if (!daemonize()) {
            printf("Daemonizing succeeds.\n");
          } else {
            fprintf(stderr, "Deamonizing fails.\n");
          }
        }
        write_pid(pid_file);
        signal(SIGTERM, termination);

        if (need_compatibility) {
          reauth_c();
        } else {
          reauth();
        }
      }
    } else {
      fprintf(stderr, "Authentication fails: %s\n", iwas4g_get_error());
    }
    free_device();
    return (-1);
  }
  return (0);
}



static int 
get_opt (int argc, char **argv)
{
  int opt;
  struct option long_opts[] = {
    {"help",          0,  NULL,  'h'},
    {"deauth",        0,  NULL,  'd'},
    {"auth",          0,  NULL,  'a'},
    {"interface",    	1,  NULL,  'i'},
    {"user",          1,  NULL,  'u'},
    {"password",      1,  NULL,  'p'},
    {"interval",      1,  NULL,  't'},
    {"reauth",        0,  NULL,  'r'},
    {"foreground",    0,  NULL,  'f'},
    {"compatibility", 0,  NULL,  'c'},
    {0, 0, 0, 0}
  };

  while ((opt = getopt_long(argc, argv, "hdai:u:p:rfc", long_opts, NULL)) 
         != -1) {
    switch (opt) {
      case '?':
      case 'h':
        usage();
        return (-1);

      case 'd':
        deauth_mode = 1;
        break;

      case 'a':
        auth_mode = 1;
        break;

      case 'i':
        if_name = optarg;
        break;

      case 'u':
        usr = optarg;
        if (strlen(usr) > USR_MAX) {
          fprintf(
            stderr, 
            "User name is too long (limited to %d characters).\n",
            USR_MAX);
          return (-1);
        }
        break;

      case 'p':
        psw = optarg;
        if (strlen(psw) > PSW_MAX) {
          fprintf(
            stderr, 
            "Password is too long (limited to %d characters).\n",
            PSW_MAX);
          return (-1);
        }
        break;

      case 'r':
        need_reauth = 1;
        break;

      case 'f':
        need_daemon = 0;
        break;

      case 'c':
        need_compatibility = 1;
        break;
    }
  }

  if (!auth_mode && !deauth_mode) {
    usage();
    return (-1);
  }
  
  if (auth_mode && (if_name == NULL || usr == NULL)) {
    usage();
    return (-1);
  }
  
  if (auth_mode && psw == NULL) {
    psw = getpass(PSW_PROMPT);
    if (psw == NULL) {
      return (-1);
    } else {
      return (0);
    }
  }
  
  if (deauth_mode && if_name == NULL) {
    usage();
    return (-1);
  }
  return (0);
}


static int 
bind_device (void)
{
  iwas4g_env env;
  struct ifreq req;
  int errno, sinet;


  sinet = socket(AF_INET, SOCK_DGRAM, 0);
  strcpy(req.ifr_name, if_name);
  errno = ioctl(sinet, SIOCGIFHWADDR, &req);
  close(sinet);

  if (errno != -1) {
    env.if_name = if_name;
    memcpy(env.hw_addr, req.ifr_hwaddr.sa_data, ETH_ALEN);
    env.to_ms = 128;
    env.to_retry = 8;
    if (iwas4g_begin_session(&env)) {
      fprintf(stderr, 
              "Binding device `%s' fails: %s\n", 
              if_name, iwas4g_get_error());
      return (-1);
    } else {
      printf("Binding device `%s' succeeds.\n", if_name);
      return (0);
    }
  } else {
    perror("Binding device fails");
    return (-1);
  }
}


static void 
free_device (void)
{
  iwas4g_end_session();
}


static void 
termination (int sig)
{
  iwas4g_deauth();
  remove_pid(pid_file);
  free_device();
  exit(0);
  /* signal(sig, SIG_DFL); */
}


static int 
reauth (void)
{
  /* time_t last; */
  int rtnval;

  /* last = time(NULL); */
  printf("Perform re-authentication.\n");
  while ((rtnval = iwas4g_watch()) != IWAS4G_WATCH_ERROR) {
    switch (rtnval) {
      case IWAS4G_WATCH_EAPOL_KEY:
        printf("%s\n", iwas4g_get_error());
        if (iwas4g_reauth()) {
          fprintf(stderr, "Re-authentication fails: %s\n", iwas4g_get_error());
          return (-1);
        } else {
          /* last = time(NULL); */
          fprintf(stdout, "%s\n", iwas4g_get_error());
        }
        break;

   /* case IWAS4G_WATCH_TIMEOUT: 
        if (difftime(time(NULL), last) > interval + 5) {
          fprintf(stderr, "Re-authentication fails: Lost communication "  
                  "with authenticator over %d seconds.\n", interval);  
          return (-1);  
        }  
        break; */
        
      case IWAS4G_WATCH_EAP_FAILURE:
        fprintf(stderr, "Re-authentication fails: %s\n", iwas4g_get_error());
        return (-1);
        break;
    }
  }
  fprintf(stderr, "Re-authentication fails: %s\n", iwas4g_get_error());
  return (-1);
}


static int 
reauth_c (void)
{
  /* time_t last; */
  int rtnval;

  /* last = time(NULL); */
  printf("Perform re-authentication (compatible mode).\n");
  while ((rtnval = iwas4g_watch()) != IWAS4G_WATCH_ERROR) {
    if (rtnval == IWAS4G_WATCH_EAPOL_KEY 
        || rtnval == IWAS4G_WATCH_EAP_FAILURE
        /* || difftime(time(NULL), last) > interval + 5 */) {
      if (iwas4g_auth(usr, psw)) {
        fprintf(stderr, "Authentication fails: %s\n", iwas4g_get_error());
        return (-1);
      } else {
        /* last = time(NULL); */
        printf("Authentication succeeds.%s\n", iwas4g_get_error());
      }
    } 
  }
  fprintf(stderr, "Performing re-authentication (compatible mode) fails: %s\n",
          iwas4g_get_error());
  return (-1);
}


static int 
daemonize(void)
{
  char out_file[PATH_MAX];
  int pid;

  pid = fork();
  if (pid == -1) {
    return (-1);
  } else if (pid != 0) {
    exit(0);
  }
  setsid();

  pid = fork();
  if (pid == -1) {
    return (-1);
  } else if (pid != 0) {
    exit(0);
  }

  signal(SIGTTOU, SIG_IGN);
  signal(SIGTTIN, SIG_IGN);
  signal(SIGTSTP, SIG_IGN);
  signal(SIGHUP, SIG_IGN);
  signal(SIGCHLD, SIG_IGN);

  close(0);
  close(1);
  close(2);

  open("/dev/null", O_RDWR);
  sprintf(out_file, OUT_FILE, if_name);
  open(out_file, O_WRONLY|O_CREAT|O_TRUNC, 0600);
  open(out_file, O_WRONLY|O_CREAT|O_TRUNC, 0600);
  chdir("/");
  umask(0);
  return (0);
}


static void
usage (void)
{
#define USAGE "\
Usage: \n\
  iwas4gdou <-a> <-i interface> <-u user> [-p password] [-options]\n\n\
  iwas4gdou <-d> <-i interface>\n\n\
Examples: \n\
  # De-authenticate first if necessary, then authenticate and perform re-authenticate\n\
  iwas4gdou -ar -i eth0 -u zjlanhb302000 -p 02302000\n\n\
  # De-authenticate\n\
  iwas4gdou -d -i eth0\n\n\
Try `man iwas4gdou' to get more information.\n\n"
  
  printf(USAGE);
}
