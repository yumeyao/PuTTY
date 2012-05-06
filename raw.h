#ifndef PUTTY_RAW_H
#define PUTTY_RAW_H

#include "putty.h"

#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE 1
#endif

#define RAW_MAX_BACKLOG 4096

typedef struct raw_backend_data {
    const struct plug_function_table *fn;
    /* the above field _must_ be first in the structure */

    Socket s;
    int bufsize;
    void *frontend;
} *Raw;

/* stub functions for common using */
extern void raw_stub_void();
extern int raw_stub_false();
extern int raw_stub_true();
#define raw_stub_null raw_stub_false


/* member functions in Backend */
extern void raw_free(void *);
#define raw_reconfig ((void (*)(void *, Config *))raw_stub_void)
extern int raw_send(void *, char *, int);
extern int raw_sendbuffer(void *);
#define raw_size ((void (*)(void *, int, int))raw_stub_void)
#define raw_special ((void (*)(void *, Telnet_Special))raw_stub_void)
#define raw_get_specials ((const struct telnet_special *(*)(void *))raw_stub_null)
extern int raw_connected(void *);
extern int raw_exitcode(void *);
#define raw_sendok ((int (*)(void *))raw_stub_true)
extern int raw_ldisc(void *, int);
#define raw_provide_ldisc ((void (*)(void *, void *))raw_stub_void)
#define raw_provide_logctx ((void (*)(void *, void *))raw_stub_void)
extern void raw_unthrottle(void *, int);
#define raw_cfg_info ((int (*)(void *))raw_stub_false)


/* member functions in plug function table */
extern void raw_log(Plug, int, SockAddr, int, const char *, int);
extern int raw_closing(Plug, const char *, int, int);
extern int raw_receive(Plug, int, char *, int);
extern void raw_sent(Plug, int);


/* so-called "friend" functions */
void c_write(Raw, char *, int);
int raw_connected_checks(void *);

#endif