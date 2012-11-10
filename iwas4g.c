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
 
 
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include "pcap.h"
#include "global.h"
#include "md5.h"
#include "rc4.h"
#include "hmac_md5.h"


#define ETHERNET_TYPE        0x88, 0x8E
#define EAE_GROUP_ADDRESS    0x01, 0x80, 0xC2, 0x00, 0x00, 0x03

#define PACKET_LEN          128
#define ERRBUF_LEN          PCAP_ERRBUF_SIZE + 128

#define IWAS4G_HWADDR_LEN    6

#define IWAS4G_WATCH_EAPOL_KEY      1
#define IWAS4G_WATCH_EAP_FAILURE    2
#define IWAS4G_WATCH_TIMEOUT        0
#define IWAS4G_WATCH_ERROR          -1


typedef struct {
  char *if_name;
  unsigned char hw_addr[IWAS4G_HWADDR_LEN];
  int to_ms;
  int to_retry;
} iwas4g_env;

typedef struct {
  struct {
    unsigned char dst[IWAS4G_HWADDR_LEN];
    unsigned char src[IWAS4G_HWADDR_LEN];
    unsigned char type[2];
  } eth;
  struct {
    unsigned char version;
    unsigned char type;
    unsigned char length[2];
  } eapol;
} pkt_eapol_start, pkt_eapol_logoff;

typedef struct {
  struct {
    unsigned char dst[IWAS4G_HWADDR_LEN];
    unsigned char src[IWAS4G_HWADDR_LEN];
    unsigned char type[2];
  } eth;
  struct {
    unsigned char version;
    unsigned char type;
    unsigned char length[2];
  } eapol;
  struct {
    unsigned char type;
    unsigned char key_length[2];
    unsigned char reply_counter[8];
    unsigned char key_iv[16];
    unsigned char key_index;
    unsigned char key_signature[16];
    unsigned char key[16];
  } keydes;
} pkt_eapol_key;

typedef struct {
  struct {
    unsigned char dst[IWAS4G_HWADDR_LEN];
    unsigned char src[IWAS4G_HWADDR_LEN];
    unsigned char type[2];
  } eth;
  struct {
    unsigned char version;
    unsigned char type;
    unsigned char length[2];
  } eapol;
  struct {
    unsigned char code;
    unsigned char id;
    unsigned char length[2];
    unsigned char type;
  } eap;
  unsigned char identity[PACKET_LEN - 23];
} pkt_eap_id;

typedef struct {
  struct {
    unsigned char dst[IWAS4G_HWADDR_LEN];
    unsigned char src[IWAS4G_HWADDR_LEN];
    unsigned char type[2];
  } eth;
  struct {
    unsigned char version;
    unsigned char type;
    unsigned char length[2];
  } eapol;
  struct {
    unsigned char code;
    unsigned char id;
    unsigned char length[2];
    unsigned char type;
  } eap;
  unsigned char value_size;
  unsigned char value[16];
  unsigned char identity[PACKET_LEN - 40];
} pkt_eap_md5ch;

typedef struct {
  struct {
    unsigned char dst[IWAS4G_HWADDR_LEN];
    unsigned char src[IWAS4G_HWADDR_LEN];
    unsigned char type[2];
  } eth;
  struct {
    unsigned char version;
    unsigned char type;
    unsigned char length[2];
  } eapol;
  struct {
    unsigned char code;
    unsigned char id;
    unsigned char length[2];
    unsigned char type;
  } eap;
} pkt_eap_success, pkt_eap_failure;


pcap_t *sid = NULL;
unsigned char hw_addr[IWAS4G_HWADDR_LEN];
unsigned char reply_counter[8], key_iv[16], key_index;
char error_buf[ERRBUF_LEN];
int max_retry;


static char * put_error (const char *fmt_str, ...);
static int is_eap_failure (const unsigned char *pkt, const char *prefix);

static int send_eapol_start (void);
static int rece_eap_id_request (unsigned char *id);
static int send_eap_id_respond (char *usr, unsigned char id);
static int rece_eap_md5ch_request (unsigned char *id, unsigned char chall[16]);
static int send_eap_md5ch_respond
           (char *usr, char *psw, unsigned char id, unsigned char chall[16]);
static int rece_eap_success (void);
static void send_eapol_logoff (void);
static int send_eapol_key (void);


int 
iwas4g_begin_session (iwas4g_env *env)
{
#ifdef WINPCAP
# define IF_NAME  "rpcap://\\Device\\NPF_%s"
#else
# define IF_NAME  "%s"
#endif

#define FILTER \
    "ether proto 0X888E && ether dst %02X:%02X:%02X:%02X:%02X:%02X"

  struct bpf_program fp;
  char errbuf[PCAP_ERRBUF_SIZE], filter[62], *if_name;

  if (!env->if_name) {
    put_error("Iterface name shoud not be NULL.");
    return (-1);
  }
  if (env->to_ms < 0) {
    put_error("Reading packet timeout shoud not be less than 0.");
    return (-1);
  }
  if ((max_retry = env->to_retry) < 0) {
    put_error("Retry times should not be less than 0.");
    return (-1);
  }

  /* Save hardware address */
  memcpy(hw_addr, env->hw_addr, IWAS4G_HWADDR_LEN);

  /* Open interface by device name */
  if_name = (char *) malloc((strlen(IF_NAME) + strlen(env->if_name))
                             * sizeof(char));
  sprintf(if_name, IF_NAME, env->if_name);
  sid = pcap_open_live(if_name, PACKET_LEN, 0, env->to_ms, errbuf);
  if (!sid) {
    put_error(errbuf);
    return (-1);
  }
  free(if_name);

  /* Set capture filter */
  sprintf(filter, FILTER, hw_addr[0], hw_addr[1], hw_addr[2], 
          hw_addr[3], hw_addr[4], hw_addr[5]);
  if (!pcap_compile(sid, &fp, filter, 1, 0)) {
    if (!pcap_setfilter(sid, &fp)) {
      return (0);
    }
  }

  put_error(pcap_geterr(sid));
  return (-1);
}


void
iwas4g_end_session (void)
{
  if (sid != NULL) {
    pcap_close(sid);
  }
}


int
iwas4g_auth (char *usr, char *psw)
{

  struct pcap_pkthdr *pkt_header;
  unsigned char id, chall[16];
  const unsigned char *rmt_pkt;
  

  if (sid == NULL) {
    put_error("No any seesion.");
    return -1;
  }
  if (usr == NULL) {
    put_error("User name should not be NULL.");
    return -1;
  }
  if (psw == NULL) {
    put_error("Password should not be NULL.");
    return -1;
  }

  /* There may be some packets that were captured without handled,
   * they remains in packet queue, now we shall drop it.  */
  while (pcap_next_ex(sid, &pkt_header, &rmt_pkt) == 1);

  if (!send_eapol_start()) {
    if (!rece_eap_id_request(&id)) {
      if (!send_eap_id_respond(usr, id)) {
        if (!rece_eap_md5ch_request(&id, chall)) {
          if (!send_eap_md5ch_respond(usr, psw, id, chall)) {
            if (!rece_eap_success()) {
              return 0;
            }
          }
        }
      }
    }
  }
  return -1;
}


int
iwas4g_watch (void)
{
  struct pcap_pkthdr *pkt_header;
  const unsigned char *pkt;
  const pkt_eapol_key *eapol_key;
  int try_times, rtnval;


  if (sid == NULL) {
    put_error("No any seesion.");
    return (IWAS4G_WATCH_ERROR);
  }

  /* Try to get an packet (filtered) */
  for (try_times = 0; ; try_times++) {
    rtnval = pcap_next_ex(sid, &pkt_header, &pkt);
    if (rtnval > 0) {
      eapol_key = (const pkt_eapol_key *) pkt;
      if (eapol_key->eapol.type == 3 && eapol_key->keydes.type == 1)
      {
        memcpy(reply_counter, eapol_key->keydes.reply_counter, 8);
        memcpy(key_iv, eapol_key->keydes.key_iv, 16);
        key_index = eapol_key->keydes.key_index;
        put_error("[EAPOL-KEY] from: %02X:%02X:%02X:%02X:%02X:%02X.",
                  eapol_key->eth.src[0], eapol_key->eth.src[1], 
                  eapol_key->eth.src[2], eapol_key->eth.src[3], 
                  eapol_key->eth.src[4], eapol_key->eth.src[5]);
        return (IWAS4G_WATCH_EAPOL_KEY);
      } else if (is_eap_failure(pkt, NULL)) {
        put_error("[EAP-FAILURE] from: %02X:%02X:%02X:%02X:%02X:%02X.",
                  eapol_key->eth.src[0], eapol_key->eth.src[1], 
                  eapol_key->eth.src[2], eapol_key->eth.src[3], 
                  eapol_key->eth.src[4], eapol_key->eth.src[5]);
        return (IWAS4G_WATCH_EAP_FAILURE);
      }
    } else if (rtnval == 0) {
      if (try_times > max_retry) {
        return (IWAS4G_WATCH_TIMEOUT);
      }
    } else {
      put_error(pcap_geterr(sid));
      return (IWAS4G_WATCH_ERROR);
    }
  }
  put_error("Unknow error.");
  return (IWAS4G_WATCH_ERROR);
}


int
iwas4g_reauth (void)
{
  if (sid == NULL) {
    put_error("No any seesion.");
    return (-1);
  }

  if (!send_eapol_key ()) {
    return (0);
  } else {
    return (-1);
  }
}


int
iwas4g_deauth (void)
{
  if (sid == NULL) {
    put_error("No any seesion.");
    return (-1);
  }

  send_eapol_logoff ();
  return (0);
}


char *
iwas4g_get_error (void)
{
  return error_buf;
}


static int 
send_eapol_start (void)
{
  unsigned char pkt[PACKET_LEN] = {
    EAE_GROUP_ADDRESS,    /* eth.dst        */
    0, 0, 0, 0, 0, 0,     /* eth.src        */
    ETHERNET_TYPE,        /* eth.type       */
    0x01,                 /* eapol.version  */
    0x01,                 /* eapol.type     */
    0x00, 0x00            /* eapol.length   */
  };
  pkt_eapol_start *eapol_start = (pkt_eapol_start *) &pkt;

  /* Send [EAPOL-START] */
  memcpy(eapol_start->eth.src, hw_addr, IWAS4G_HWADDR_LEN);
  if (pcap_sendpacket(sid, pkt, 18) == -1) {
    put_error(pcap_geterr(sid));
    return (-1);
  }
  return (0);
}


static int
rece_eap_id_request(unsigned char *id)
{
  struct pcap_pkthdr *pkt_header;
  const unsigned char *pkt;
  const pkt_eap_id *eap_id_request;
  int try_times, rtnval;


  /* Try to get an [EAP-IDENTITY-REQUEST] from authenticator */
  for (try_times = 0; ; try_times++) {
    rtnval = pcap_next_ex(sid, &pkt_header, &pkt);
    if (rtnval > 0) {
      eap_id_request = (const pkt_eap_id *) pkt;
      if (eap_id_request->eapol.type == 0
          && eap_id_request->eap.code == 1
          && eap_id_request->eap.type == 1) {
        *id = eap_id_request->eap.id;
        return 0;
      } else if (is_eap_failure(pkt, 
                                "When receiving [EAP-IDENTIFY-REQUEST], ")) {
        return (-1);
      } else {
        put_error("There are too many EAPOL packets, you may be attacked,"
                  "you can check that by sniffing and analysing packets.");
        return (-1);
      }
    } else if (rtnval == 0) {
      if (try_times > max_retry) {
        put_error("Receiving [EAP-IDENTIFY-REQUEST] timeout.");
        return (-1);
      }
    } else {
      put_error("Receiving [EAP-IDENTIFY-REQUEST] fails: %s", 
                pcap_geterr(sid));
      return (-1);
    }
  }
  put_error("Receiving [EAP-IDENTIFY-REQUEST] fails: Unknow error.");
  return (-1);
}


static int
send_eap_id_respond (char *usr, unsigned char id)
{
  unsigned char pkt[PACKET_LEN] = {
    EAE_GROUP_ADDRESS,    /* eth.dst        */
    0, 0, 0, 0, 0, 0,     /* eth.src        */
    ETHERNET_TYPE,        /* eth.type       */
    0x01,                 /* eapol.version  */
    0x00,                 /* eapol.type     */
    0, 0,                 /* eapol.length   */
    0x02,                 /* eap.code       */
    0,                    /* eap.id         */
    0, 0,                 /* eap.length     */
    0x01,                 /* eap.type       */
    0                     /* eap.identity   */
  };
  pkt_eap_id *eap_id_respond = (pkt_eap_id *) &pkt;
  unsigned char usrlen = strlen(usr);


  /* Send [EAP-IDENTIFY-RESPOND] */
  memcpy(eap_id_respond->eth.src, hw_addr, IWAS4G_HWADDR_LEN);
  eap_id_respond->eapol.length[0] = (usrlen + 5) >> 8;
  eap_id_respond->eapol.length[1] = (usrlen + 5);
  eap_id_respond->eap.id = id;
  eap_id_respond->eap.length[0] = eap_id_respond->eapol.length[0];
  eap_id_respond->eap.length[1] = eap_id_respond->eapol.length[1];
  memcpy(eap_id_respond->identity, usr, usrlen);
  if (pcap_sendpacket(sid, pkt, 23 + usrlen) == -1) {
    put_error("Sending [EAP-IDENTIFY-RESPOND] fails: %s", pcap_geterr(sid));
    return (-1);
  }
  return (0);
}


static int
rece_eap_md5ch_request(unsigned char *id, unsigned char chall[16])
{
  struct pcap_pkthdr *pkt_header;
  const unsigned char *pkt;
  const pkt_eap_md5ch *eap_md5ch_request;
  int try_times, rtnval;


  /* Try to get an [EAP-MAD5-CHALLENGE-REQUEST] from authenticator */
  for (try_times = 0; ; try_times++) {
    rtnval = pcap_next_ex(sid, &pkt_header, &pkt);
    if (rtnval > 0) {
      eap_md5ch_request = (pkt_eap_md5ch *) pkt;
      if (eap_md5ch_request->eapol.type == 0
          && eap_md5ch_request->eap.code == 1
          && eap_md5ch_request->eap.type == 4) {
        *id = eap_md5ch_request->eap.id;
        memcpy(chall, eap_md5ch_request->value, 16);
        return (0);
      } else if (is_eap_failure(pkt, 
                  "When receiving [EAP-MAD5-CHALLENGE-REQUEST], ")) {
        return (-1);
      } else {
        put_error("There are too many EAPOL packets,you may be attacked,"
                  "you can check that by sniffing and analysing packets.");
        return (-1);
      }
    } else if (rtnval == 0) {
      if (try_times > max_retry) {
        put_error("Receiving [EAP-MAD5-CHALLENGE-REQUEST] timeout.");
        return (-1);
      }
    } else {
      put_error("Receiving [EAP-MAD5-CHALLENGE-REQUEST] fails: %s",
                pcap_geterr(sid));
      return (-1);
    }
  }
  put_error("Receiving [EAP-MAD5-CHALLENGE-REQUEST] fails: Unknow error.");
  return (-1);
}


static int
send_eap_md5ch_respond (char *usr,
                        char *psw,
                        unsigned char id,
                        unsigned char chall[16]) {
  unsigned char pkt[PACKET_LEN] = {
    EAE_GROUP_ADDRESS,      /* eth.dst        */
    0, 0, 0, 0, 0, 0,       /* eth.src        */
    ETHERNET_TYPE,          /* eth.type       */
    0x01,                   /* eapol.version  */
    0x00,                   /* eapol.type     */
    0, 0,                   /* eapol.length   */
    0x02,                   /* eap.code       */
    0,                      /* eap.id         */
    0, 0,                   /* eap.length     */
    0x04,                   /* eap.type       */
    0x10,                   /* eap.value-size           */
    0, 0, 0, 0, 0, 0, 0, 0, /* eap.value(hi-8byte)      */
    0, 0, 0, 0, 0, 0, 0, 0, /* eap.value(lo-8byte)      */
    0                       /* eap.extradata(identity)  */
  };
  pkt_eap_md5ch *eap_md5ch_respond = (pkt_eap_md5ch *) &pkt;
  unsigned char usrlen = strlen(usr);
  unsigned char pswlen = strlen(psw);
  MD5_CTX context;
  char *srctext;
  unsigned char digest[16];


  /* Generate `MD5-CHALLENGE` by concatenating: id, psw and challenge */
  srctext = (char *) malloc(17 + pswlen);
  srctext[0] = id;
  memcpy(srctext + 1, psw, pswlen);
  memcpy(srctext + 1 + pswlen, chall, 16);
  MD5Init(&context);
  MD5Update(&context, (unsigned char *) srctext, 17 + pswlen);
  MD5Final(digest, &context);
  free(srctext);

  /* Send [EAP-MAD5-CHALLENGE-RESPOND] */
  memcpy(eap_md5ch_respond->eth.src, hw_addr, IWAS4G_HWADDR_LEN);
  eap_md5ch_respond->eapol.length[0] = (usrlen + 22) >> 8;
  eap_md5ch_respond->eapol.length[1] = (usrlen + 22);
  eap_md5ch_respond->eap.id = id;
  eap_md5ch_respond->eap.length[0] = eap_md5ch_respond->eapol.length[0];
  eap_md5ch_respond->eap.length[1] = eap_md5ch_respond->eapol.length[1];
  memcpy(eap_md5ch_respond->value, digest, 16);
  memcpy(eap_md5ch_respond->identity, usr, usrlen);

  if (pcap_sendpacket(sid, pkt, usrlen + 40) == -1) {
    put_error("Sending [EAP-MD5-CHALLENGE-RESPOND] fails: %s",pcap_geterr(sid));
    return (-1);
  }
  return (0);
}


static int
rece_eap_success()
{
  struct pcap_pkthdr *pkt_header;
  const unsigned char *pkt;
  const pkt_eap_success *eap_success;
  int try_times, rtnval;

  for (try_times = 0; ; try_times++)
  {
    rtnval = pcap_next_ex(sid, &pkt_header, &pkt);
    if (rtnval > 0)
    {
      eap_success = (const pkt_eap_success *) pkt;
      if (eap_success->eapol.type == 0 && eap_success->eap.code == 3) {
        return (0);
      } else if (is_eap_failure(pkt, "When receiving [EAP-SUCCESS], ")) {
        return (-1);
      } else {
        put_error("There are too many eapol packets,you may be attacked,"
                  "you can check that by sniffing and analysing packets.");
      }
    } else if (rtnval == 0) {
      if (try_times > max_retry) {
        put_error("Receiving [EAP-SUCCESS] timeout");
        return (-1);
      }
    } else {
      put_error("Receiving [EAP-SUCCESS] fails: %s", pcap_geterr(sid));
      return (-1);
    }
  }
  put_error("Receiving [EAP-SUCCESS] fails: Unknow error.");
  return (-1);
}


static void
send_eapol_logoff (void)
{
  unsigned char pkt[PACKET_LEN] = {
    EAE_GROUP_ADDRESS,    /* eth.dst        */
    0, 0, 0, 0, 0, 0,     /* eth.src        */
    ETHERNET_TYPE,        /* eth.type       */
    0x01,                 /* eapol.version  */
    0x02,                 /* eapol.type     */
    0x00, 0x00,           /* eapol.length   */
  };
  pkt_eapol_logoff *eapol_logoff = (pkt_eapol_logoff *) &pkt;
  if(sid) {
    memcpy(eapol_logoff->eth.src, hw_addr, 6);
    pcap_sendpacket(sid, pkt, 18);
  }
}



static int
send_eapol_key ()
{
#define SESSION_KEY1    0x02, 0x0E, 0x05, 0x04, 0x66, 0x40, 0x19, 0x75,\
                        0x06, 0x06, 0x00, 0x16, 0xD3, 0xF3, 0xAC, 0x02
#define SESSION_KEY2    0x02, 0x02, 0x14, 0x00

  unsigned char pkt1[PACKET_LEN] = {
    EAE_GROUP_ADDRESS,      /* eth.dst        */
    0, 0, 0, 0, 0, 0,       /* eth.src        */
    ETHERNET_TYPE,          /* eth.type       */
    0x01,                   /* eapol.version  */
    0x03,                   /* eapol.type     */
    0x00, 0x3C,             /* eapol.length   */
    0x01,                                             /* keydes.type          */
    0x00, 0x10,                                       /* keydes.key_length    */
    0, 0, 0, 0, 0, 0, 0, 0,                           /* keydes.reply_counter */
    0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0,  /* keydes.key_iv        */
    0,                                                /* keydes.key_index     */
    0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0,  /* keydes.key_signature */
    0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0   /* keydes.key           */
  };
  unsigned char pkt2[PACKET_LEN] = {
    EAE_GROUP_ADDRESS,      /* eth.dst        */
    0, 0, 0, 0, 0, 0,       /* eth.src        */
    ETHERNET_TYPE,          /* eth.type       */
    0x01,                   /* eapol.version  */
    0x03,                   /* eapol.type     */
    0x00, 0x30,             /* eapol.length   */
    0x01,                                             /* keydes.type          */
    0x00, 0x04,                                       /* keydes.key_length    */
    0, 0, 0, 0, 0, 0, 0, 0,                           /* keydes.reply_counter */
    0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0,  /* keydes.key_iv        */
    0,                                                /* keydes.key_index     */
    0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0,  /* keydes.key_signature */
    0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0   /* keydes.key           */
  };
  pkt_eapol_key *eapol_key1 = (pkt_eapol_key *) &pkt1;
  pkt_eapol_key *eapol_key2 = (pkt_eapol_key *) &pkt2;
  unsigned char new_key_iv[20];
  unsigned char session_key1[16] = { SESSION_KEY1 };
  unsigned char session_key2[4]  = { SESSION_KEY2 };
  unsigned char rc4_sub_key[16];
  unsigned char i;


  /* Generate a `new key iv' by concatenating:
   * received `key iv' and its `lower-4bytes' */
  memcpy(new_key_iv, key_iv, 16);
  memcpy(new_key_iv + 16, new_key_iv + 12, 4);

  /* Generate RC4 crypt stream and 1st/2nd session key */
  rc4_init(new_key_iv, 20);
  for (i = 0; i < 16; i ++) {
    rc4_sub_key[i] = rc4_output();
    session_key1[i] = (session_key1[i] ^ rc4_sub_key[i]);
  }
  for (i = 0; i < 4; i ++) {
    session_key2[i] = (session_key2[i] ^ rc4_sub_key[i]);
  }

  /* Fill 1st/2nd [EAPOL-KEY] */
  memcpy(eapol_key1->eth.src, hw_addr, 6);
  memcpy(eapol_key1->keydes.reply_counter, reply_counter, 8);
  memcpy(eapol_key1->keydes.key_iv, key_iv, 16);
  eapol_key1->keydes.key_index = key_index;
  memcpy(eapol_key1->keydes.key, session_key1, 16);
  hmac_md5(
    &eapol_key1->eapol.version, 64, 
    &eapol_key1->keydes.key_index, 1, 
    eapol_key1->keydes.key_signature);  
  memcpy(eapol_key2->eth.src, hw_addr, 6);
  memcpy(eapol_key2->keydes.reply_counter, reply_counter, 8);
  memcpy(eapol_key2->keydes.key_iv, key_iv, 16);
  eapol_key2->keydes.key_index = key_index;
  memcpy(eapol_key2->keydes.key, session_key2, 4);
  hmac_md5(
    &eapol_key2->eapol.version, 52, 
    &eapol_key2->keydes.key_index, 1, 
    eapol_key2->keydes.key_signature);

  /* send 1st [EAPOL-KEY] */
  if (pcap_sendpacket(sid, pkt1, 78) != -1)
  {
    /* send 2nd [EAPOL-KEY] */
    if (pcap_sendpacket(sid, pkt2, 66) != -1)
    {
      put_error("Send a couple of [EAPOL-KEY].");
      return (0);
    }
  }
  put_error("Re-authentication fails: Sending [eapol-KEY] fails: %s",
            pcap_geterr(sid));
  return (-1);
}


static int
is_eap_failure (const unsigned char *pkt, const char *prefix)
{
  const pkt_eap_failure *eap_failure;
  char errbuf[ERRBUF_LEN];
  unsigned short eap_length;
  int i;
  
  
  if (pkt == NULL) {
    return 0;
  } else {
    eap_failure = (const pkt_eap_failure *) pkt;
  }
  
  if (eap_failure->eapol.type == 0 
      && eap_failure->eap.code == 4) {
    eap_length = (((unsigned short)eap_failure->eap.length[0]) << 8)
                 + eap_failure->eap.length[1];
    if (eap_length > 6) {
      /* In GDOU, when `EAP LENGTH' is greater than 6, there will be an 
       * error message (CodePage:GBK) attached to the tail of [EAP-Failure].
       * The length of this message  is [`EAP LENGTH' - 6] */
      sprintf(errbuf, "%s%s", prefix, 
              "Received [EAP-FAILURE] with message(GBK): [");
      i = strlen(errbuf);
      if ((i + eap_length - 6 + 3) <= ERRBUF_LEN) {
        memcpy(errbuf + i, pkt + 24, eap_length - 6);
        errbuf[(i + eap_length - 6)] = ']';
        errbuf[(++i + eap_length - 6)] = '.';
        errbuf[(++i + eap_length - 6)] = '\0';
      } else {
        strcat(errbuf, "...].");
      }
    } else {
      sprintf(errbuf, "%s%s", prefix, "Received [EAP-FAILURE].");
    }
    put_error(errbuf);
    return (1);
  } else {
    put_error(errbuf);
    return (0);
  }
}


static char *
put_error (const char *fmt_str, ...)
{
  va_list args;

  va_start(args, fmt_str);
  vsprintf(error_buf, fmt_str, args);
  va_end(args);
  return error_buf;
}

