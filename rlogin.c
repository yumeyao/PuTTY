/*
 * Rlogin backend.
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include "raw.h"

typedef struct rlogin_tag {
    struct raw_backend_data;
    int firstbyte;
    int cansize;
    int term_width, term_height;

    Config cfg;

    /* In case we need to read a username from the terminal before starting */
    prompts_t *prompt;
} *Rlogin;

#define RLOGIN_MAX_BACKLOG 4096

/* member functions in Backend */
static const char *
    rlogin_init(void *, void **, Config *, char *, int, char **, int, int);
static void rlogin_free(void *);
#define rlogin_reconfig         raw_reconfig
static int rlogin_send(void *, char *, int);
#define rlogin_sendbuffer       raw_sendbuffer
void rlogin_size(void *, int, int);
#define rlogin_special          raw_special
#define rlogin_get_specials     raw_get_specials
#define rlogin_connected        raw_connected_checks
/* If we ever implement RSH, we'll probably need to do this properly */
#define rlogin_exitcode         raw_exitcode
#define rlogin_sendok           raw_sendok
#define rlogin_ldisc            ((int (*)(void *, int))raw_stub_false)
#define rlogin_provide_ldisc    raw_provide_ldisc
#define rlogin_provide_logctx   raw_provide_logctx
#if (RLOGIN_MAX_BACKLOG==RAW_MAX_BACKLOG)
#define rlogin_unthrottle raw_unthrottle
#else
static void rlogin_unthrottle(void *handle, int backlog)
{
    Rlogin rlogin = (Rlogin) handle;
    sk_set_frozen(rlogin->s, backlog > RLOGIN_MAX_BACKLOG);
}
#endif
#define rlogin_cfg_info         raw_cfg_info

/* member functions in plug function table */
#define rlogin_log              raw_log
#define rlogin_closing          raw_closing
static int rlogin_receive(Plug, int, char *, int);
#define rlogin_sent             raw_sent

#if (RLOGIN_MAX_BACKLOG==RAW_MAX_BACKLOG)
#define c_write_rlogin(rlogin, buf, len) c_write((Raw)rlogin, buf, len)
#else
static void c_write_rlogin(Rlogin rlogin, char *buf, int len)
{
    int backlog = from_backend(rlogin->frontend, 0, buf, len);
    sk_set_frozen(rlogin->s, backlog > RLOGIN_MAX_BACKLOG);
}
#endif

static int rlogin_receive(Plug plug, int urgent, char *data, int len)
{
    Rlogin rlogin = (Rlogin) plug;
    if (urgent == 2) {
        char c;

        c = *data++;
        len--;
        if (c == '\x80') {
            rlogin->cansize = 1;
            rlogin_size(rlogin, rlogin->term_width, rlogin->term_height);
        }
        /*
         * We should flush everything (aka Telnet SYNCH) if we see
         * 0x02, and we should turn off and on _local_ flow control
         * on 0x10 and 0x20 respectively. I'm not convinced it's
         * worth it...
         */
    } else {
        /*
         * Main rlogin protocol. This is really simple: the first
         * byte is expected to be NULL and is ignored, and the rest
         * is printed.
         */
        if (rlogin->firstbyte) {
            if (data[0] == '\0') {
                data++;
                len--;
            }
            rlogin->firstbyte = 0;
        }
        if (len > 0)
            c_write_rlogin(rlogin, data, len);
    }
    return 1;
}

static void rlogin_startup(Rlogin rlogin, const char *ruser)
{
    char z = 0;
    char *p;
    sk_write(rlogin->s, &z, 1);
    sk_write(rlogin->s, rlogin->cfg.localusername,
             strlen(rlogin->cfg.localusername));
    sk_write(rlogin->s, &z, 1);
    sk_write(rlogin->s, ruser,
             strlen(ruser));
    sk_write(rlogin->s, &z, 1);
    sk_write(rlogin->s, rlogin->cfg.termtype,
             strlen(rlogin->cfg.termtype));
    sk_write(rlogin->s, "/", 1);
    for (p = rlogin->cfg.termspeed; isdigit((unsigned char)*p); p++) continue;
    sk_write(rlogin->s, rlogin->cfg.termspeed, p - rlogin->cfg.termspeed);
    rlogin->bufsize = sk_write(rlogin->s, &z, 1);

    rlogin->prompt = NULL;
}

/*
 * Called to set up the rlogin connection.
 * 
 * Returns an error message, or NULL on success.
 *
 * Also places the canonical host name into `realhost'. It must be
 * freed by the caller.
 */
static const char *rlogin_init(void *frontend_handle, void **backend_handle,
                               Config *cfg,
                               char *host, int port, char **realhost,
                               int nodelay, int keepalive)
{
    static const struct plug_function_table fn_table = {
        rlogin_log,
        rlogin_closing,
        rlogin_receive,
        raw_sent
    };
    SockAddr addr;
    const char *err;
    Rlogin rlogin;
    char ruser[sizeof(cfg->username)];

    rlogin = snew(struct rlogin_tag);
    rlogin->fn = &fn_table;
    rlogin->s = NULL;
    rlogin->frontend = frontend_handle;
    rlogin->term_width = cfg->width;
    rlogin->term_height = cfg->height;
    rlogin->firstbyte = 1;
    rlogin->cansize = 0;
    rlogin->prompt = NULL;
    rlogin->cfg = *cfg;                /* STRUCTURE COPY */
    *backend_handle = rlogin;

    /*
     * Try to find host.
     */
    {
        char *buf;
        buf = dupprintf("Looking up host \"%s\"%s", host,
                        (cfg->addressfamily == ADDRTYPE_IPV4 ? " (IPv4)" :
                         (cfg->addressfamily == ADDRTYPE_IPV6 ? " (IPv6)" :
                          "")));
        logevent(rlogin->frontend, buf);
        sfree(buf);
    }
    addr = name_lookup(host, port, realhost, cfg, cfg->addressfamily);
    if ((err = sk_addr_error(addr)) != NULL) {
        sk_addr_free(addr);
        return err;
    }

    if (port < 0)
        port = 513;                       /* default rlogin port */

    /*
     * Open socket.
     */
    rlogin->s = new_connection(addr, *realhost, port, 1, 0,
                               nodelay, keepalive, (Plug) rlogin, cfg);
    if ((err = sk_socket_error(rlogin->s)) != NULL)
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

    /*
     * Send local username, remote username, terminal type and
     * terminal speed - unless we don't have the remote username yet,
     * in which case we prompt for it and may end up deferring doing
     * anything else until the local prompt mechanism returns.
     */
    if (get_remote_username(cfg, ruser, sizeof(ruser))) {
        rlogin_startup(rlogin, ruser);
    } else {
        int ret;

        rlogin->prompt = new_prompts(rlogin->frontend);
        rlogin->prompt->to_server = TRUE;
        rlogin->prompt->name = dupstr("Rlogin login name");
        add_prompt(rlogin->prompt, dupstr("rlogin username: "), TRUE,
                   sizeof(cfg->username)); 
        ret = get_userpass_input(rlogin->prompt, NULL, 0);
        if (ret >= 0) {
            rlogin_startup(rlogin, rlogin->prompt->prompts[0]->result);
        }
    }

    return NULL;
}

static void rlogin_free(void *handle)
{
    Rlogin rlogin = (Rlogin) handle;

    if (rlogin->prompt)
        free_prompts(rlogin->prompt);
    if (rlogin->s)
        sk_close(rlogin->s);
    sfree(rlogin);
}

/*
 * Called to send data down the rlogin connection.
 */
static int rlogin_send(void *handle, char *buf, int len)
{
    Rlogin rlogin = (Rlogin) handle;

    if (rlogin->s == NULL)
        return 0;

    if (rlogin->prompt) {
        /*
         * We're still prompting for a username, and aren't talking
         * directly to the network connection yet.
         */
        int ret = get_userpass_input(rlogin->prompt,
                                     (unsigned char *)buf, len);
        if (ret >= 0) {
            rlogin_startup(rlogin, rlogin->prompt->prompts[0]->result);
            /* that nulls out rlogin->prompt, so then we'll start sending
             * data down the wire in the obvious way */
        }
    } else {
        rlogin->bufsize = sk_write(rlogin->s, buf, len);
    }

    return rlogin->bufsize;
}

/*
 * Called to set the size of the window
 */
static void rlogin_size(void *handle, int width, int height)
{
    Rlogin rlogin = (Rlogin) handle;
    char b[12] = { '\xFF', '\xFF', 0x73, 0x73, 0, 0, 0, 0, 0, 0, 0, 0 };

    rlogin->term_width = width;
    rlogin->term_height = height;

    if (rlogin->s == NULL || !rlogin->cansize)
        return;

    b[6] = rlogin->term_width >> 8;
    b[7] = rlogin->term_width & 0xFF;
    b[4] = rlogin->term_height >> 8;
    b[5] = rlogin->term_height & 0xFF;
    rlogin->bufsize = sk_write(rlogin->s, b, 12);
    return;
}

Backend rlogin_backend = {
    rlogin_init,
    rlogin_free,
    rlogin_reconfig,
    rlogin_send,
    rlogin_sendbuffer,
    rlogin_size,
    rlogin_special,
    rlogin_get_specials,
    rlogin_connected,
    rlogin_exitcode,
    rlogin_sendok,
    rlogin_ldisc,
    rlogin_provide_ldisc,
    rlogin_provide_logctx,
    rlogin_unthrottle,
    rlogin_cfg_info,
    "rlogin",
    PROT_RLOGIN,
    513
};
