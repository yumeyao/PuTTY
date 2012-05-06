/*
 * "Raw" backend.
 */

#include <stdio.h>
#include <stdlib.h>

#include "raw.h"

typedef struct adb_backend_data {
    struct raw_backend_data;
    int state;
} *Adb;

/* member functions in Backend */
static const char *
    adb_init(void *, void **, Config *, char *, int, char **, int, int);
#define adb_free                raw_free
#define adb_reconfig            raw_reconfig
#define adb_send                raw_send
#define adb_sendbuffer          raw_sendbuffer
#define adb_size                raw_size
#define adb_special             raw_special
#define adb_get_specials        raw_get_specials
#define adb_connected           raw_connected
#define adb_exitcode            raw_exitcode
#define adb_sendok              raw_sendok
#define adb_ldisc               ((int (*)(void *, int))raw_stub_false)
#define adb_provide_ldisc       raw_provide_ldisc
#define adb_provide_logctx      raw_provide_logctx
#define adb_unthrottle          raw_unthrottle
#define adb_cfg_info            raw_cfg_info

/* member functions in plug function table */
#define adb_log                 raw_log
#define adb_closing             raw_closing
static int adb_receive(Plug, int, char *, int);
#define adb_sent                raw_sent

static int adb_receive(Plug plug, int urgent, char *data, int len)
{
    Adb adb = (Adb) plug;
    if (adb->state==1) {
        if (data[0]=='O') { // OKAY
            sk_write(adb->s,"0006shell:",10);
            adb->state=2; // wait for shell start response
        } else {
            if (data[0]=='F') {
                char* d = (char*)smalloc(len+1);
                memcpy(d,data,len);
                d[len]='\0';
                connection_fatal(adb->frontend, "%s", d+8);
                sfree(d);
            } else {
                connection_fatal(adb->frontend, "Bad response");
            }
            return 0;
        }
    } else if (adb->state==2) {
        if (data[0]=='O') { //OKAY
            adb->state=3; // shell started, switch to terminal mode
        } else {
            if (data[0]=='F') {
                char* d = (char*)smalloc(len+1);
                memcpy(d,data,len);
                d[len]='\0';
                connection_fatal(adb->frontend, "%s", d+8);
                sfree(d);
            } else {
                connection_fatal(adb->frontend, "Bad response");
            }
            return 0;
        }
    } else {
        c_write((Raw)adb, data, len);
    }
    return 1;
}

/*
 * Called to set up the adb connection.
 * 
 * Returns an error message, or NULL on success.
 *
 * Also places the canonical host name into `realhost'. It must be
 * freed by the caller.
 */
static const char *adb_init(void *frontend_handle, void **backend_handle,
                            Config *cfg,
                            char *host, int port, char **realhost, int nodelay,
                            int keepalive)
{
    static const struct plug_function_table fn_table = {
        adb_log,
        adb_closing,
        adb_receive,
        adb_sent
    };
    SockAddr addr;
    const char *err;
    Adb adb;

    adb = snew(struct adb_backend_data);
    adb->fn = &fn_table;
    adb->s = NULL;
    adb->state = 0;
    *backend_handle = adb;

    adb->frontend = frontend_handle;

    /*
     * Try to find host.
     */
    {
        char *buf;
        buf = dupprintf("Looking up host \"%s\"%s", "localhost",
                    (cfg->addressfamily == ADDRTYPE_IPV4 ? " (IPv4)" :
                    (cfg->addressfamily == ADDRTYPE_IPV6 ? " (IPv6)" :
                    "")));
    logevent(adb->frontend, buf);
    sfree(buf);
    }
    addr = name_lookup("localhost", port, realhost, cfg, cfg->addressfamily);
    if ((err = sk_addr_error(addr)) != NULL) {
        sk_addr_free(addr);
        return err;
    }

    if (port < 0)
        port = 5037;               /* default adb port */

    /*
     * Open socket.
     */
    adb->s = new_connection(addr, *realhost, port, 0, 1, nodelay, keepalive,
                            (Plug) adb, cfg);
    if ((err = sk_socket_error(adb->s)) != NULL)
        return err;

    if (*cfg->loghost) {
        char *colon;

        sfree(*realhost);
        *realhost = dupstr(cfg->loghost);
        colon = strrchr(*realhost, ':');
        if (colon) {
            /*
             * FIXME: if we ever update this aspect of ssh.c for
             * IPv6 literal management, this should change in line
             * with it.
             */
            *colon++ = '\0';
        }
    }

    /* send initial data to adb server */
#define ADB_SHELL_DEFAULT_STR "0012" "host:transport-usb"
#define ADB_SHELL_DEFAULT_STR_LEN (sizeof(ADB_SHELL_DEFAULT_STR)-1)
#define ADB_SHELL_SERIAL_PREFIX "host:transport:"
#define ADB_SHELL_SERIAL_PREFIX_LEN (sizeof(ADB_SHELL_SERIAL_PREFIX)-1)
    do {
        size_t len = strlen(host);
        if (len == 0) {
            sk_write(adb->s, ADB_SHELL_DEFAULT_STR, ADB_SHELL_DEFAULT_STR_LEN);
        } else {
            char sendbuf[512];
#define ADB_SHELL_HOST_MAX_LEN \
        (sizeof(sendbuf)-4-ADB_SHELL_SERIAL_PREFIX_LEN-1)
            if (len > ADB_SHELL_HOST_MAX_LEN)
                len = ADB_SHELL_HOST_MAX_LEN;
            sprintf(sendbuf,"%04x" ADB_SHELL_SERIAL_PREFIX,
                len+ADB_SHELL_SERIAL_PREFIX_LEN);
            memcpy(sendbuf+4+ADB_SHELL_SERIAL_PREFIX_LEN, host, len);
            sk_write(adb->s,sendbuf,len+4+ADB_SHELL_SERIAL_PREFIX_LEN);
        }
    } while (0);

    sk_flush(adb->s);
    adb->state = 1;
    return NULL;
}

Backend adb_backend = {
    adb_init,
    adb_free,
    adb_reconfig,
    adb_send,
    adb_sendbuffer,
    adb_size,
    adb_special,
    adb_get_specials,
    adb_connected,
    adb_exitcode,
    adb_sendok,
    adb_ldisc,
    adb_provide_ldisc,
    adb_provide_logctx,
    adb_unthrottle,
    adb_cfg_info,
    "adb",
    PROT_ADB,
    5037
};