/*
 * "Raw" backend.
 */

#include <stdio.h>
#include <stdlib.h>

#include "raw.h"

void c_write(Raw raw, char *buf, int len)
{
    int backlog = from_backend(raw->frontend, 0, buf, len);
    sk_set_frozen(raw->s, backlog > RAW_MAX_BACKLOG);
}

void raw_log(Plug plug, int type, SockAddr addr, int port,
             const char *error_msg, int error_code)
{
    Raw raw = (Raw) plug;
    char addrbuf[256], *msg;

    sk_getaddr(addr, addrbuf, lenof(addrbuf));

    if (type == 0)
        msg = dupprintf("Connecting to %s port %d", addrbuf, port);
    else
        msg = dupprintf("Failed to connect to %s: %s", addrbuf, error_msg);

    logevent(raw->frontend, msg);
}

int raw_closing(Plug plug, const char *error_msg, int error_code,
                int calling_back)
{
    Raw raw = (Raw) plug;

    if (raw->s) {
        sk_close(raw->s);
        raw->s = NULL;
        notify_remote_exit(raw->frontend);
    }
    if (error_msg) {
        /* A socket error has occurred. */
        logevent(raw->frontend, error_msg);
        connection_fatal(raw->frontend, "%s", error_msg);
    } /* Otherwise, the remote side closed the connection normally. */
    return 0;
}

int raw_receive(Plug plug, int urgent, char *data, int len)
{
    Raw raw = (Raw) plug;
    c_write(raw, data, len);
    return 1;
}

void raw_sent(Plug plug, int bufsize)
{
    Raw raw = (Raw) plug;
    raw->bufsize = bufsize;
}

/*
 * Called to set up the raw connection.
 * 
 * Returns an error message, or NULL on success.
 *
 * Also places the canonical host name into `realhost'. It must be
 * freed by the caller.
 */
static const char *raw_init(void *frontend_handle, void **backend_handle,
                            Config *cfg,
                            char *host, int port, char **realhost, int nodelay,
                            int keepalive)
{
    static const struct plug_function_table fn_table = {
        raw_log,
        raw_closing,
        raw_receive,
        raw_sent
    };
    SockAddr addr;
    const char *err;
    Raw raw;

    raw = snew(struct raw_backend_data);
    raw->fn = &fn_table;
    raw->s = NULL;
    *backend_handle = raw;

    raw->frontend = frontend_handle;

    /*
     * Try to find host.
     */
    {
        char *buf;
        buf = dupprintf("Looking up host \"%s\"%s", host,
                    (cfg->addressfamily == ADDRTYPE_IPV4 ? " (IPv4)" :
                    (cfg->addressfamily == ADDRTYPE_IPV6 ? " (IPv6)" :
                    "")));
        logevent(raw->frontend, buf);
        sfree(buf);
    }
    addr = name_lookup(host, port, realhost, cfg, cfg->addressfamily);
    if ((err = sk_addr_error(addr)) != NULL) {
        sk_addr_free(addr);
        return err;
    }

    if (port < 0)
        port = 23;                       /* default telnet port */

    /*
     * Open socket.
     */
    raw->s = new_connection(addr, *realhost, port, 0, 1, nodelay, keepalive,
                            (Plug) raw, cfg);
    if ((err = sk_socket_error(raw->s)) != NULL)
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

    return NULL;
}

void raw_free(void *handle)
{
    Raw raw = (Raw) handle;

    if (raw->s)
        sk_close(raw->s);
    sfree(raw);
}

/*
 * Stub routines
 */
void raw_stub_void(){return;}
int raw_stub_false(){return 0;}
int raw_stub_true(){return 1;}

/*
 * Called to send data down the raw connection.
 */
int raw_send(void *handle, char *buf, int len)
{
    Raw raw = (Raw) handle;

    if (raw->s == NULL)
        return 0;

    raw->bufsize = sk_write(raw->s, buf, len);

    return raw->bufsize;
}

/*
 * Called to query the current socket sendability status.
 */
int raw_sendbuffer(void *handle)
{
    Raw raw = (Raw) handle;
    return raw->bufsize;
}

int raw_connected(void *handle)
{
    Raw raw = (Raw) handle;
    return raw->s != NULL;
}

void raw_unthrottle(void *handle, int backlog)
{
    Raw raw = (Raw) handle;
    sk_set_frozen(raw->s, backlog > RAW_MAX_BACKLOG);
}

int raw_ldisc(void *handle, int option)
{
    if (option == LD_EDIT || option == LD_ECHO)
        return 1;
    return 0;
}

int raw_exitcode(void *handle)
{
    Raw raw = (Raw) handle;
    if (raw->s != NULL)
        return -1;                     /* still connected */
    else
        /* Exit codes are a meaningless concept in the Raw protocol */
        return 0;
}

Backend raw_backend = {
    raw_init,
    raw_free,
    raw_reconfig,
    raw_send,
    raw_sendbuffer,
    raw_size,
    raw_special,
    raw_get_specials,
    raw_connected,
    raw_exitcode,
    raw_sendok,
    raw_ldisc,
    raw_provide_ldisc,
    raw_provide_logctx,
    raw_unthrottle,
    raw_cfg_info,
    "raw",
    PROT_RAW,
    0
};

/* Other friend function implementions */
int raw_connected_checks(void *handle)
{
    Raw raw = (Raw) handle;
    return raw->s != NULL;
}