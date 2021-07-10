/***********************************************************************
 *          C_YCOMMAND.C
 *          YCommand GClass.
 *
 *          Yuneta Statistics
 *
 *          Copyright (c) 2016 Niyamaka.
 *          All Rights Reserved.
 ***********************************************************************/
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <pty.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include "c_ycommand.h"

/***************************************************************************
 *              Constants
 ***************************************************************************/
enum {
    CTRL_A = 1,
    CTRL_B = 2,
    CTRL_C = 3,
    CTRL_D = 4,
    CTRL_E = 5,
    CTRL_F = 6,
    CTRL_H = 8,
    BACKSPACE =  127,
    TAB = 9,
    CTRL_K = 11,
    ENTER = 13,
    CTRL_N = 14,
    CTRL_P = 16,
    CTRL_T = 20,
    CTRL_U = 21,
    CTRL_W = 23,
    CTRL_Y = 25,
    ESCAPE = 27,

    MKEY_START =         0x485B1B, // .[H
    MKEY_PREV_PAGE =     0x7E355B1B, // .[5~
    MKEY_NEXT_PAGE =     0x7E365B1B, // .[6~
    MKEY_END =           0x465B1B, // .[F
    MKEY_UP =            0x415B1B, // .[A
    MKEY_DOWN =          0x425B1B, // .[B
    MKEY_LEFT =          0x445B1B, // .[D
    MKEY_RIGHT =         0x435B1B, // .[C

    MKEY_START2 =        0x484F1B, // .[H
    MKEY_END2 =          0x464F1B, // .[F
    MKEY_UP2 =           0x414F1B, // .OA
    MKEY_DOWN2 =         0x424F1B, // .OB
    MKEY_LEFT2 =         0x444F1B, // .OD
    MKEY_RIGHT2 =        0x434F1B, // .OC

    MKEY_INS =           0x7E325B1B, // .[2~
    MKEY_DEL =           0x7E335B1B, // .[3~
    MKEY_ALT_START =     0x48333B315B1B, // .[1;3H
    MKEY_ALT_PREV_PAGE = 0x7E333B355B1B, // .[5;3~
    MKEY_ALT_NEXT_PAGE = 0x7E333B365B1B, // .[6;3~
    MKEY_ALT_END =       0x46333B315B1B, // .[1;3F
};

/***************************************************************************
 *              Structures
 ***************************************************************************/

/***************************************************************************
 *              Prototypes
 ***************************************************************************/
PRIVATE void on_alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf);
PRIVATE void on_read_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
PRIVATE void on_close_cb(uv_handle_t* handle);
PRIVATE void do_close(hgobj gobj);
PRIVATE int cmd_connect(hgobj gobj);
PRIVATE int do_command(hgobj gobj, const char *command);
PRIVATE int clear_input_line(hgobj gobj);
PRIVATE char *get_history_file(char *bf, int bfsize);

/***************************************************************************
 *          Data: config, public data, private data
 ***************************************************************************/
volatile struct winsize winsz;

struct keytable_s {
    const char *dst_gobj;
    const char *event;
    unsigned long long key;
} keytable[] = {
{"editline",    "EV_EDITLINE_MOVE_START",       CTRL_A},
{"editline",    "EV_EDITLINE_MOVE_START",       MKEY_START},
{"editline",    "EV_EDITLINE_MOVE_START",       MKEY_START2},
{"editline",    "EV_EDITLINE_MOVE_END",         CTRL_E},
{"editline",    "EV_EDITLINE_MOVE_END",         MKEY_END},
{"editline",    "EV_EDITLINE_MOVE_END",         MKEY_END2},
{"editline",    "EV_EDITLINE_MOVE_LEFT",        CTRL_B},
{"editline",    "EV_EDITLINE_MOVE_LEFT",        MKEY_LEFT},
{"editline",    "EV_EDITLINE_MOVE_LEFT",        MKEY_LEFT2},
{"editline",    "EV_EDITLINE_MOVE_RIGHT",       CTRL_F},
{"editline",    "EV_EDITLINE_MOVE_RIGHT",       MKEY_RIGHT},
{"editline",    "EV_EDITLINE_MOVE_RIGHT",       MKEY_RIGHT2},
{"editline",    "EV_EDITLINE_DEL_CHAR",         CTRL_D},
{"editline",    "EV_EDITLINE_DEL_CHAR",         MKEY_DEL},
{"editline",    "EV_EDITLINE_BACKSPACE",        CTRL_H},
{"editline",    "EV_EDITLINE_BACKSPACE",        BACKSPACE},
{"editline",    "EV_EDITLINE_COMPLETE_LINE",    TAB},
{"editline",    "EV_EDITLINE_ENTER",            ENTER},
{"editline",    "EV_EDITLINE_PREV_HIST",        MKEY_UP},
{"editline",    "EV_EDITLINE_PREV_HIST",        MKEY_UP2},
{"editline",    "EV_EDITLINE_NEXT_HIST",        MKEY_DOWN},
{"editline",    "EV_EDITLINE_NEXT_HIST",        MKEY_DOWN2},
{"editline",    "EV_EDITLINE_SWAP_CHAR",        CTRL_T},
{"editline",    "EV_EDITLINE_DEL_LINE",         CTRL_U},
{"editline",    "EV_EDITLINE_DEL_LINE",         CTRL_Y},
{"editline",    "EV_EDITLINE_DEL_PREV_WORD",    CTRL_W},

{"screen",      "EV_CLRSCR",                    CTRL_K},

{"screen",      "EV_SCROLL_PAGE_UP",            MKEY_PREV_PAGE},
{"screen",      "EV_SCROLL_PAGE_DOWN",          MKEY_NEXT_PAGE},

{"screen",      "EV_SCROLL_LINE_UP",            MKEY_ALT_PREV_PAGE},
{"screen",      "EV_SCROLL_LINE_DOWN",          MKEY_ALT_NEXT_PAGE},
{"screen",      "EV_SCROLL_TOP",                MKEY_ALT_START},
{"screen",      "EV_SCROLL_BOTTOM",             MKEY_ALT_END},

{0}
};


/*---------------------------------------------*
 *      Attributes - order affect to oid's
 *---------------------------------------------*/
PRIVATE sdata_desc_t tattr_desc[] = {
/*-ATTR-type------------name----------------flag--------default---------description---------- */
SDATA (ASN_BOOLEAN,     "verbose",          0,          1,              "Verbose mode."),
SDATA (ASN_BOOLEAN,     "interactive",      0,          0,              "Interactive."),
SDATA (ASN_OCTET_STR,   "command",          0,          "",             "Command."),
SDATA (ASN_OCTET_STR,   "url",              0,          "ws://127.0.0.1:1991",  "Url to get Statistics. Can be a ip/hostname or a full url"),
SDATA (ASN_OCTET_STR,   "yuno_name",        0,          "",             "Yuno name"),
SDATA (ASN_OCTET_STR,   "yuno_role",        0,          "yuneta_agent", "Yuno role"),
SDATA (ASN_OCTET_STR,   "yuno_service",     0,          "agent",        "Yuno service"),
SDATA (ASN_POINTER,     "gobj_connector",   0,          0,              "connection gobj"),
SDATA (ASN_OCTET_STR,   "display_mode",     SDF_WR|SDF_PERSIST,"table", "Display mode: table or form"),
SDATA (ASN_OCTET_STR,   "editor",           SDF_WR|SDF_PERSIST,"vim",   "Editor"),
SDATA (ASN_POINTER,     "user_data",        0,          0,              "user data"),
SDATA (ASN_POINTER,     "user_data2",       0,          0,              "more user data"),
SDATA_END()
};

/*---------------------------------------------*
 *      GClass trace levels
 *---------------------------------------------*/
enum {
    TRACE_MESSAGES = 0x0001,
};
PRIVATE const trace_level_t s_user_trace_level[16] = {
{"messages",        "Trace messages"},
{0, 0},
};


/*---------------------------------------------*
 *              Private data
 *---------------------------------------------*/
typedef struct _PRIVATE_DATA {
    int32_t verbose;
    int32_t interactive;
    uv_tty_t uv_tty;
    char uv_handler_active;
    char uv_read_active;
    char uv_req_shutdown_active;
    hgobj gobj_connector;
    hgobj gobj_editline;
    grow_buffer_t bfinput;
} PRIVATE_DATA;




            /******************************
             *      Framework Methods
             ******************************/




/***************************************************************************
 *      Framework Method create
 ***************************************************************************/
PRIVATE void sig_handler(int sig)
{
    if (SIGWINCH == sig) {
        ioctl(0, TIOCGWINSZ, &winsz);
    }
}
PRIVATE void mt_create(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    ioctl(0, TIOCGWINSZ, &winsz);
    // Capture SIGWINCH
    signal(SIGWINCH, sig_handler);

    /*
     *  History filename, for editline
     */
    char history_file[PATH_MAX];
    get_history_file(history_file, sizeof(history_file));
    json_t *kw_editline = json_pack(
        "{s:s, s:i, s:i}",
        "history_file", history_file,
        "cx", winsz.ws_col,
        "cy", winsz.ws_row
    );

    priv->gobj_editline = gobj_create("", GCLASS_EDITLINE, kw_editline, gobj);

    /*
     *  Do copy of heavy used parameters, for quick access.
     *  HACK The writable attributes must be repeated in mt_writing method.
     */
    SET_PRIV(gobj_connector,        gobj_read_pointer_attr)
    SET_PRIV(verbose,               gobj_read_bool_attr)
    SET_PRIV(interactive,           gobj_read_bool_attr)
}

/***************************************************************************
 *      Framework Method writing
 ***************************************************************************/
PRIVATE void mt_writing(hgobj gobj, const char *path)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    IF_EQ_SET_PRIV(gobj_connector,     gobj_read_pointer_attr)
    END_EQ_SET_PRIV()
}

/***************************************************************************
 *      Framework Method destroy
 ***************************************************************************/
PRIVATE void mt_destroy(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    if(priv->uv_handler_active) {
        log_error(LOG_OPT_TRACE_STACK,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_OPERATIONAL_ERROR,
            "msg",          "%s", "GObj NOT STOPPED. UV handler ACTIVE!",
            NULL
        );
    }
    if(priv->uv_read_active) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_OPERATIONAL_ERROR,
            "msg",          "%s", "UV req_read ACTIVE",
            NULL
        );
    }
    if(priv->uv_req_shutdown_active) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_OPERATIONAL_ERROR,
            "msg",          "%s", "UV req_shutdown ACTIVE",
            NULL
        );
    }

    /*
     *  Free data
     */
    growbf_reset(&priv->bfinput);
}

/***************************************************************************
 *      Framework Method start
 ***************************************************************************/
PRIVATE int mt_start(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    if(priv->uv_handler_active) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_OPERATIONAL_ERROR,
            "msg",          "%s", "UV handler ALREADY ACTIVE!",
            NULL
        );
        return -1;
    }

    if(gobj_trace_level(gobj) & TRACE_UV) {
        trace_msg(">>> uv_init tty p=%p", &priv->uv_tty);
    }
    uv_tty_init(yuno_uv_event_loop(), &priv->uv_tty, STDIN_FILENO, 0);
    priv->uv_tty.data = gobj;
    priv->uv_handler_active = 1;

    uv_tty_set_mode(&priv->uv_tty, UV_TTY_MODE_RAW);

    priv->uv_read_active = 1;
    uv_read_start((uv_stream_t*)&priv->uv_tty, on_alloc_cb, on_read_cb);

    gobj_start(priv->gobj_editline);

    cmd_connect(gobj);
    return 0;
}

/***************************************************************************
 *      Framework Method stop
 ***************************************************************************/
PRIVATE int mt_stop(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    uv_tty_set_mode(&priv->uv_tty, UV_TTY_MODE_NORMAL);
    uv_tty_reset_mode();

    do_close(gobj);
    gobj_stop_tree(gobj);

    return 0;
}




            /***************************
             *      Local Methods
             ***************************/




PRIVATE char agent_insecure_config[]= "\
{                                               \n\
    'name': '(^^__url__^^)',                    \n\
    'gclass': 'IEvent_cli',                     \n\
    'as_unique': true,                          \n\
    'kw': {                                     \n\
        'remote_yuno_name': '(^^__yuno_name__^^)',      \n\
        'remote_yuno_role': '(^^__yuno_role__^^)',      \n\
        'remote_yuno_service': '(^^__yuno_service__^^)' \n\
    },                                          \n\
    'zchilds': [                                 \n\
        {                                               \n\
            'name': '(^^__url__^^)',                    \n\
            'gclass': 'IOGate',                         \n\
            'kw': {                                     \n\
            },                                          \n\
            'zchilds': [                                 \n\
                {                                               \n\
                    'name': '(^^__url__^^)',                    \n\
                    'gclass': 'Channel',                        \n\
                    'kw': {                                     \n\
                    },                                          \n\
                    'zchilds': [                                 \n\
                        {                                               \n\
                            'name': '(^^__url__^^)',                    \n\
                            'gclass': 'GWebSocket',                     \n\
                            'zchilds': [                                \n\
                                {                                       \n\
                                    'name': '(^^__url__^^)',            \n\
                                    'gclass': 'Connex',                 \n\
                                    'kw': {                             \n\
                                        'urls':[                        \n\
                                            '(^^__url__^^)'             \n\
                                        ]                               \n\
                                    }                                   \n\
                                }                                       \n\
                            ]                                           \n\
                        }                                               \n\
                    ]                                           \n\
                }                                               \n\
            ]                                           \n\
        }                                               \n\
    ]                                           \n\
}                                               \n\
";

PRIVATE char agent_secure_config[]= "\
{                                               \n\
    'name': '(^^__url__^^)',                    \n\
    'gclass': 'IEvent_cli',                     \n\
    'as_unique': true,                          \n\
    'kw': {                                     \n\
        'remote_yuno_name': '(^^__yuno_name__^^)',      \n\
        'remote_yuno_role': '(^^__yuno_role__^^)',      \n\
        'remote_yuno_service': '(^^__yuno_service__^^)' \n\
    },                                          \n\
    'zchilds': [                                 \n\
        {                                               \n\
            'name': '(^^__url__^^)',                    \n\
            'gclass': 'IOGate',                         \n\
            'kw': {                                     \n\
            },                                          \n\
            'zchilds': [                                 \n\
                {                                               \n\
                    'name': '(^^__url__^^)',                    \n\
                    'gclass': 'Channel',                        \n\
                    'kw': {                                     \n\
                    },                                          \n\
                    'zchilds': [                                 \n\
                        {                                               \n\
                            'name': '(^^__url__^^)',                    \n\
                            'gclass': 'GWebSocket',                     \n\
                            'zchilds': [                                \n\
                                {                                       \n\
                                    'name': '(^^__url__^^)',            \n\
                                    'gclass': 'Connexs',                \n\
                                    'kw': {                             \n\
                                        'crypto': {                     \n\
                                            'library': 'openssl',       \n\
                                            'trace': false              \n\
                                        },                              \n\
                                        'urls':[                        \n\
                                            '(^^__url__^^)'             \n\
                                        ]                               \n\
                                    }                                   \n\
                                }                                       \n\
                            ]                                           \n\
                        }                                               \n\
                    ]                                           \n\
                }                                               \n\
            ]                                           \n\
        }                                               \n\
    ]                                           \n\
}                                               \n\
";

PRIVATE int cmd_connect(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    const char *url = gobj_read_str_attr(gobj, "url");
    const char *yuno_name = gobj_read_str_attr(gobj, "yuno_name");
    const char *yuno_role = gobj_read_str_attr(gobj, "yuno_role");
    const char *yuno_service = gobj_read_str_attr(gobj, "yuno_service");

    /*
     *  Each display window has a gobj to send the commands (saved in user_data).
     *  For external agents create a filter-chain of gobjs
     */
    json_t * jn_config_variables = json_pack("{s:{s:s, s:s, s:s, s:s}}",
        "__json_config_variables__",
            "__url__", url,
            "__yuno_name__", yuno_name,
            "__yuno_role__", yuno_role,
            "__yuno_service__", yuno_service
    );
    char *sjson_config_variables = json2str(jn_config_variables);
    JSON_DECREF(jn_config_variables);

    /*
     *  Get schema to select tls or not
     */
    char schema[20]={0}, host[120]={0}, port[40]={0};
    parse_http_url(url, schema, sizeof(schema), host, sizeof(host), port, sizeof(port), FALSE);

    char *agent_config = agent_insecure_config;
    if(strcmp(schema, "wss")==0) {
        agent_config = agent_secure_config;
    }

    hgobj gobj_remote_agent = gobj_create_tree(
        gobj,
        agent_config,
        sjson_config_variables,
        "EV_ON_SETUP",
        "EV_ON_SETUP_COMPLETE"
    );
    gbmem_free(sjson_config_variables);

    gobj_start_tree(gobj_remote_agent);

    if(priv->verbose || priv->interactive) {
        printf("Connecting to %s...\n", url);
    }
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE struct keytable_s *event_by_key(int kb)
{
    for(int i=0; keytable[i].event!=0; i++) {
        if(kb == keytable[i].key) {
            return &keytable[i];
        }
    }
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int process_key(hgobj gobj, uint8_t kb)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    if(kb >= 0x20 && kb <= 0x7f) {
        json_t *kw_char = json_pack("{s:i}",
            "char", kb
        );
        gobj_send_event(priv->gobj_editline, "EV_KEYCHAR", kw_char, gobj);
    }

    return 0;
}

/***************************************************************************
 *  on alloc callback
 ***************************************************************************/
PRIVATE void on_alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf)
{
    hgobj gobj = handle->data;
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    growbf_ensure_size(&priv->bfinput, suggested_size);
    buf->base = priv->bfinput.bf;
    buf->len = priv->bfinput.allocated;
}

/***************************************************************************
 *  on read callback
 ***************************************************************************/
PRIVATE void on_read_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
    hgobj gobj = stream->data;
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    if(gobj_trace_level(gobj) & TRACE_UV) {
        trace_msg("<<< on_read_cb %d tcp p=%p",
            nread,
            &priv->uv_tty
        );
    }

    if(nread < 0) {
        if(nread == UV_ECONNRESET) {
            log_info(0,
                "gobj",         "%s", gobj_full_name(gobj),
                "msgset",       "%s", MSGSET_CONNECT_DISCONNECT,
                "msg",          "%s", "Connection Reset",
                NULL
            );
        } else if(nread == UV_EOF) {
            log_info(0,
                "gobj",         "%s", gobj_full_name(gobj),
                "msgset",       "%s", MSGSET_CONNECT_DISCONNECT,
                "msg",          "%s", "EOF",
                NULL
            );
        } else {
            log_error(0,
                "gobj",         "%s", gobj_full_name(gobj),
                "function",     "%s", __FUNCTION__,
                "msgset",       "%s", MSGSET_LIBUV_ERROR,
                "msg",          "%s", "read FAILED",
                "uv_error",     "%s", uv_err_name(nread),
                NULL
            );
        }
        if(gobj_is_running(gobj)) {
            gobj_stop(gobj); // auto-stop
        }
        return;
    }

    if(nread == 0) {
        // Yes, sometimes arrive with nread 0.
        return;
    }

    if(gobj_trace_level(gobj) & TRACE_UV) {
        log_debug_dump(
            0,
            buf->base,
            nread,
            ""
        );
    }

    if((buf->base[0] <= 0x1B && nread <= 8) || buf->base[0] == 0x7F) {
        if(buf->base[0] == 3) {
            gobj_stop(gobj);
            return;
        }

        unsigned char b[8];
        memset(b, 0, sizeof(b));
        memmove(b, buf->base, nread);
        struct keytable_s *kt = event_by_key(*((uint64_t *)b));

        if(kt && !empty_string(kt->event)) {
            if(strcmp(kt->dst_gobj, "screen")==0) {
                gobj_send_event(gobj, kt->event, 0, gobj);
            } else {
                gobj_send_event(priv->gobj_editline, kt->event, 0, gobj);
            }
        }

    } else {
        for(int i=0; i<nread; i++) {
            process_key(gobj, buf->base[i]);
        }
    }
}

/***************************************************************************
 *  Only NOW you can destroy this gobj,
 *  when uv has released the handler.
 ***************************************************************************/
PRIVATE void on_close_cb(uv_handle_t* handle)
{
    hgobj gobj = handle->data;
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    if(gobj_trace_level(gobj) & TRACE_UV) {
        trace_msg("<<< on_close_cb tcp0 p=%p", &priv->uv_tty);
    }
    priv->uv_handler_active = 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE void do_close(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    if(!priv->uv_handler_active) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_OPERATIONAL_ERROR,
            "msg",          "%s", "UV handler NOT ACTIVE!",
            NULL
        );
        return;
    }
    if(priv->uv_read_active) {
        uv_read_stop((uv_stream_t *)&priv->uv_tty);
        priv->uv_read_active = 0;
    }

    if(gobj_trace_level(gobj) & TRACE_UV) {
        trace_msg(">>> uv_close tcp p=%p", &priv->uv_tty);
    }
    uv_close((uv_handle_t *)&priv->uv_tty, on_close_cb);
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int do_command(hgobj gobj, const char *command)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    json_t *jn_resp = gobj_command(priv->gobj_connector, command, 0, gobj);
    json_decref(jn_resp);
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE GBUFFER *source2base64(const char *source, char **comment)
{
    /*------------------------------------------------*
     *          Check source
     *  Frequently, You want install install the output
     *  of your yuno's make install command.
     *------------------------------------------------*/
    if(empty_string(source)) {
        *comment = "source not found";
        return 0;
    }

    char path[NAME_MAX];
    if(access(source, 0)==0 && is_regular_file(source)) {
        snprintf(path, sizeof(path), "%s", source);
    } else {
        snprintf(path, sizeof(path), "/yuneta/development/output/yunos/%s", source);
    }

    if(access(path, 0)!=0) {
        *comment = "source not found";
        return 0;
    }
    if(!is_regular_file(path)) {
        *comment = "source is not a regular file";
        return 0;
    }
    GBUFFER *gbuf_b64 = gbuf_file2base64(path);
    if(!gbuf_b64) {
        *comment = "conversion to base64 failed";
    }
    return gbuf_b64;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE GBUFFER * replace_cli_vars(hgobj gobj, const char *command, char **comment)
{
    GBUFFER *gbuf = gbuf_create(4*1024, gbmem_get_maximum_block(), 0, 0);
    char *command_ = gbmem_strdup(command);
    char *p = command_;
    char *n, *f;
    while((n=strstr(p, "$$"))) {
        *n = 0;
        gbuf_append(gbuf, p, strlen(p));

        n += 2;
        if(*n == '(') {
            f = strchr(n, ')');
        } else {
            gbuf_decref(gbuf);
            gbmem_free(command_);
            *comment = "Bad format of $$: use $$(..)";
            return 0;
        }
        if(!f) {
            gbuf_decref(gbuf);
            gbmem_free(command_);
            *comment = "Bad format of $$: use $$(...)";
            return 0;
        }
        *n = 0;
        n++;
        *f = 0;
        f++;

        GBUFFER *gbuf_b64 = source2base64(n, comment);
        if(!gbuf_b64) {
            gbuf_decref(gbuf);
            gbmem_free(command_);
            return 0;
        }

        gbuf_append(gbuf, "'", 1);
        gbuf_append_gbuf(gbuf, gbuf_b64);
        gbuf_append(gbuf, "'", 1);
        gbuf_decref(gbuf_b64);

        p = f;
    }
    if(!empty_string(p)) {
        gbuf_append(gbuf, p, strlen(p));
    }

    gbmem_free(command_);
    return gbuf;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE GBUFFER *jsontable2str(json_t *jn_schema, json_t *jn_data)
{
    GBUFFER *gbuf = gbuf_create(4*1024, gbmem_get_maximum_block(), 0, 0);

    size_t col;
    json_t *jn_col;
    /*
     *  Paint Headers
     */
    json_array_foreach(jn_schema, col, jn_col) {
        const char *header = kw_get_str(jn_col, "header", "", 0);
        int fillspace = kw_get_int(jn_col, "fillspace", 10, 0);
        if(fillspace && fillspace < strlen(header)) {
            fillspace = strlen(header);
        }
        if(fillspace > 0) {
            gbuf_printf(gbuf, "%-*.*s ", fillspace, fillspace, header);
        }
    }
    gbuf_printf(gbuf, "\n");

    /*
     *  Paint ===
     */
    json_array_foreach(jn_schema, col, jn_col) {
        const char *header = kw_get_str(jn_col, "header", "", 0);
        int fillspace = kw_get_int(jn_col, "fillspace", 10, 0);
        if(fillspace && fillspace < strlen(header)) {
            fillspace = strlen(header);
        }
        if(fillspace > 0) {
            gbuf_printf(gbuf,
                "%*.*s ",
                fillspace,
                fillspace,
                "==========================================================================="
            );
        }
    }
    gbuf_printf(gbuf, "\n");

    /*
     *  Paint data
     */
    size_t row;
    json_t *jn_row;
    json_array_foreach(jn_data, row, jn_row) {
        json_array_foreach(jn_schema, col, jn_col) {
            const char *id = kw_get_str(jn_col, "id", 0, 0);
            int fillspace = kw_get_int(jn_col, "fillspace", 10, 0);
            const char *header = kw_get_str(jn_col, "header", "", 0);
            if(fillspace && fillspace < strlen(header)) {
                fillspace = strlen(header);
            }
            if(fillspace > 0) {
                json_t *jn_cell = kw_get_dict_value(jn_row, id, 0, 0);
                char *text = json2uglystr(jn_cell);
                if(json_is_number(jn_cell) || json_is_boolean(jn_cell)) {
                    //gbuf_printf(gbuf, "%*s ", fillspace, text);
                    gbuf_printf(gbuf, "%-*.*s ", fillspace, fillspace, text);
                } else {
                    gbuf_printf(gbuf, "%-*.*s ", fillspace, fillspace, text);
                }
                GBMEM_FREE(text);
            }
        }
        gbuf_printf(gbuf, "\n");
    }
    gbuf_printf(gbuf, "\nTotal: %d\n", row);

    return gbuf;
}

/***************************************************************************
 *  Print json response in display list window
 ***************************************************************************/
PRIVATE int display_webix_result(
    hgobj gobj,
    json_t *webix)
{
//     PRIVATE_DATA *priv = gobj_priv_data(gobj);
    int result = kw_get_int(webix, "result", -1, 0);
    const char *comment = kw_get_str(webix, "comment", "", 0);
    json_t *jn_schema = kw_get_dict_value(webix, "schema", 0, 0);
    json_t *jn_data = kw_get_dict_value(webix, "data", 0, 0);

    const char *display_mode = gobj_read_str_attr(gobj, "display_mode");
    json_t *jn_display_mode = kw_get_subdict_value(webix, "__md_iev__", "display_mode", 0, 0);
    if(jn_display_mode) {
        display_mode = json_string_value(jn_display_mode);
    }
    BOOL mode_form = FALSE;
    if(!empty_string(display_mode)) {
        if(strcasecmp(display_mode, "form")==0)  {
            mode_form = TRUE;
        }
    }

    if(result < 0) {
        printf("%sERROR %d: %s%s\n", On_Red BWhite, result, comment, Color_Off);
    } else {
        if(!empty_string(comment)) {
            printf("%s\n", comment);
        }
    }

    if(json_is_array(jn_data)) {
        if (mode_form) {
            char *data = json2str(jn_data);
            printf("%s\n", data);
            gbmem_free(data);
        } else {
            /*
             *  display as table
             */
            if(jn_schema && json_array_size(jn_schema)) {
                GBUFFER *gbuf = jsontable2str(jn_schema, jn_data);
                if(gbuf) {
                    char *p = gbuf_cur_rd_pointer(gbuf);
                    printf("%s\n", p);
                    gbuf_decref(gbuf);
                }
            } else {
                char *text = json2str(jn_data);
                if(text) {
                    printf("%s\n", text);
                    gbmem_free(text);
                }
            }
        }
    } else if(json_is_object(jn_data)) {
        char *data = json2str(jn_data);
        printf("%s\n", data);
        gbmem_free(data);
    }
    clear_input_line(gobj);

    JSON_DECREF(webix);
    return 0;
}

/***************************************************************************
 *  Clear input line
 ***************************************************************************/
PRIVATE int clear_input_line(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    printf("\n");

    json_t *kw_line = json_object();
    json_object_set_new(kw_line, "text", json_string(""));
    gobj_send_event(priv->gobj_editline, "EV_SETTEXT", kw_line, gobj);

    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE char *get_history_file(char *bf, int bfsize)
{
    char *home = getenv("HOME");
    memset(bf, 0, bfsize);
    if(home) {
        snprintf(bf, bfsize, "%s/.yuneta", home);
        mkdir(bf, 0700);
        strcat(bf, "/history.txt");
    }
    return bf;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int list_history(hgobj gobj)
{
    char history_file[PATH_MAX];
    get_history_file(history_file, sizeof(history_file));

    FILE *file = fopen(history_file, "r");
    if(file) {
        char temp[4*1024];
        while(fgets(temp, sizeof(temp), file)) {
            left_justify(temp);
            if(strlen(temp)>0) {
                printf("%s\n", temp);
            }
        }
        fclose(file);
    }
    clear_input_line(gobj);
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int save_local_json(hgobj gobj, char *path, int pathsize, const char *name, json_t *jn_content)
{
    const char *homedir;

    if ((homedir = getenv("HOME")) == NULL) {
        homedir = getpwuid(getuid())->pw_dir;
    }
    snprintf(path, pathsize, "%s/.yuneta/configs/", homedir);
    if(access(path, 0)!=0) {
        mkrdir(path, 0, 0700);
    }
    if(strlen(name) > 5 && strstr(name + strlen(name) - strlen(".json"), ".json")) {
        snprintf(path, pathsize, "%s/.yuneta/configs/%s", homedir, name);
    } else {
        snprintf(path, pathsize, "%s/.yuneta/configs/%s.json", homedir, name);
    }
    json_dump_file(jn_content, path, JSON_ENCODE_ANY | JSON_INDENT(4));
    JSON_DECREF(jn_content);
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
#ifdef PEPE // TODO
static BOOL fd_set_cloexec(const int fd)
{
    int flags = fcntl(fd, F_GETFD);
    if (flags < 0) return false;
    return (flags & FD_CLOEXEC) == 0 || fcntl(fd, F_SETFD, flags | FD_CLOEXEC) != -1;
}

static BOOL fd_duplicate(int fd, uv_pipe_t *pipe)
{
    int fd_dup = dup(fd);
    if (fd_dup < 0) return false;

    if (!fd_set_cloexec(fd_dup)) return false;

    int status = uv_pipe_open(pipe, fd_dup);
    if(status) close(fd_dup);
    return status == 0;
}

static void wait_cb(void *arg)
{
    pty_process *process = (pty_process *) arg;

    pid_t pid;
    int stat;
    do {
        pid = waitpid(process->pid, &stat, 0);
    } while (pid != process->pid && errno == EINTR);

    if (WIFEXITED(stat)) {
        process->exit_code = WEXITSTATUS(stat);
    }
    if (WIFSIGNALED(stat)) {
        int sig = WTERMSIG(stat);
        process->exit_code = 128 + sig;
        process->exit_signal = sig;
    }

    uv_async_send(&process->async);
}

static void async_cb(uv_async_t *async)
{
    pty_process *process = (pty_process *) async->data;
    process->exit_cb(process->ctx, process);

    uv_close((uv_handle_t *) async, NULL);
    process_free(process);
}

static void process_read_cb(void *ctx, pty_buf_t *buf, bool eof)
{
    struct pss_tty *pss = (struct pss_tty *) ctx;
    if (eof && !process_running(pss->process))
        pss->lws_close_status = pss->process->exit_code == 0 ? 1000 : 1006;
    else
        pss->pty_buf = buf;

    lws_callback_on_writable(pss->wsi);
}

static void process_exit_cb(void *ctx, pty_process *process)
{
    struct pss_tty *pss = (struct pss_tty *) ctx;
    pss->process = NULL;
    if (process->killed) {
        lwsl_notice("process killed with signal %d, pid: %d\n", process->exit_signal, process->pid);
    } else {
        lwsl_notice("process exited with code %d, pid: %d\n", process->exit_code, process->pid);
        pss->lws_close_status = process->exit_code == 0 ? 1000 : 1006;
        lws_callback_on_writable(pss->wsi);
    }
}

/***************************************************************************
 *  execlp("/bin/sh","/bin/sh", "-c", "ls -l /bin/??", (char *)NULL);
 ***************************************************************************/
PRIVATE int pty_async_spawn(
    hgobj gobj,
    const char *command
//     process_read_cb,
//     process_exit_cb
)
{
    int status = 0;

    uv_disable_stdio_inheritance();

    int master, pid;
    struct winsize size = {24, 80, 0, 0 };
    pid = forkpty(&master, NULL, NULL, &size);
    if (pid < 0) {
        // Can't fork
        status = -errno;
        goto error;

    } else if (pid == 0) {
        // Child
        setsid();
        printf("Child\n");
        int ret = execlp("/bin/sh","/bin/sh", "-c", command, (char *)NULL);
        if (ret < 0) {
            printf("ERROR %d %s\n", errno, strerror(errno));
            _exit(-errno);
        }
    } else {
        // Parent
        printf("Parent\n");
        while (waitpid(pid, &status, 0) == -1) {
            if (errno != EINTR) {       /* Error other than EINTR */
                status = -1;
                break;                  /* So exit loop */
            }
        }
    }

    int flags = fcntl(master, F_GETFL);
    if (flags == -1) {
        status = -errno;
        goto error;
    }
    if(fcntl(master, F_SETFD, flags | O_NONBLOCK) == -1) {
        status = -errno;
        goto error;
    }
    if (!fd_set_cloexec(master)) {
        status=-errno;
        goto error;
    }

//     pty_io_t *io = pty_io_init(process, read_cb);
//     if (!fd_duplicate(master, io->in) || !fd_duplicate(master, io->out)) {
//         status = -errno;
//         pty_io_free(io);
//         goto error;
//     }
//
//     process->pty = master;
//     process->pid = pid;
//     process->io = io;
//     process->exit_cb = exit_cb;
//     process->async.data = process;
//     uv_async_init(process->loop, &process->async, async_cb);
//     uv_thread_create(&process->tid, wait_cb, process);
    return 0;

    error:
        printf("ERROR %d %s\n", errno, strerror(errno));
        close(master);
        uv_kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        return status;
}
#endif

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int pty_sync_spawn(
    hgobj gobj,
    const char *command
)
{
    int master, pid;

    struct winsize size = {24, 80, 0, 0 };
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &size);

    pid = forkpty(&master, NULL, NULL, &size);
    if (pid < 0) {
        // Can't fork
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_SYSTEM_ERROR,
            "msg",          "%s", "forkpty() FAILED",
            "errno",        "%d", errno,
            "strerror",     "%s", strerror(errno),
            NULL
        );
        return -1;

    } else if (pid == 0) {
        // Child
        int ret = execlp("/bin/sh","/bin/sh", "-c", command, (char *)NULL);
        if (ret < 0) {
            log_error(0,
                "gobj",         "%s", gobj_full_name(gobj),
                "function",     "%s", __FUNCTION__,
                "msgset",       "%s", MSGSET_SYSTEM_ERROR,
                "msg",          "%s", "execlp() FAILED",
                "command",      "%s", command,
                "errno",        "%d", errno,
                "strerror",     "%s", strerror(errno),
                NULL
            );
            _exit(-errno);
        }
    } else {
        // Parent
        while(1) {
            fd_set read_fd;
            fd_set write_fd;
            fd_set except_fd;

            FD_ZERO(&read_fd);
            FD_ZERO(&write_fd);
            FD_ZERO(&except_fd);

            FD_SET(master, &read_fd);
            FD_SET(STDIN_FILENO, &read_fd);

            select(master+1, &read_fd, &write_fd, &except_fd, NULL);

            char input;
            char output;

            if (FD_ISSET(master, &read_fd)) {
                if (read(master, &output, 1) != -1) {   // read from program
                    write(STDOUT_FILENO, &output, 1);   // write to tty
                } else {
                    break;
                }
            }

            if (FD_ISSET(STDIN_FILENO, &read_fd)) {
                read(STDIN_FILENO, &input, 1);  // read from tty
                write(master, &input, 1);       // write to program
            }

            int status;
            if (waitpid(pid, &status, WNOHANG) && WIFEXITED(status)) {
                exit(EXIT_SUCCESS);
            }
        }
    }

    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int edit_json(hgobj gobj, const char *path)
{
    const char *editor = gobj_read_str_attr(gobj, "editor");
    char command[PATH_MAX];
    snprintf(command, sizeof(command), "%s %s", editor, path);

    return pty_sync_spawn(gobj, command);
//    return pty_async_spawn(gobj, command);
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int save_local_string(hgobj gobj, char *path, int pathsize, const char *name, json_t *jn_content)
{
    const char *homedir;

    if ((homedir = getenv("HOME")) == NULL) {
        homedir = getpwuid(getuid())->pw_dir;
    }
    snprintf(path, pathsize, "%s/.yuneta/configs/", homedir);
    if(access(path, 0)!=0) {
        mkrdir(path, 0, 0700);
    }
    snprintf(path, pathsize, "%s/.yuneta/configs/%s", homedir, name);
    const char *s = json_string_value(jn_content);
    if(s) {
        FILE *file = fopen(path, "w");
        if(file) {
            fwrite(s, strlen(s), 1, file);
            fclose(file);
        }
    }
    JSON_DECREF(jn_content);
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int save_local_base64(
    hgobj gobj,
    char *path,
    int pathsize,
    const char *name,
    json_t *jn_content
)
{
    const char *homedir;

    if ((homedir = getenv("HOME")) == NULL) {
        homedir = getpwuid(getuid())->pw_dir;
    }
    snprintf(path, pathsize, "%s/.yuneta/configs/", homedir);
    if(access(path, 0)!=0) {
        mkrdir(path, 0, 0700);
    }
    snprintf(path, pathsize, "%s/.yuneta/configs/%s", homedir, name);

    const char *s = json_string_value(jn_content);
    if(s) {
        GBUFFER *gbuf_bin = gbuf_decodebase64string(s);
        if(gbuf_bin) {
            int fp = newfile(path, 0700, TRUE);
            if(fp) {
                write(fp, gbuf_cur_rd_pointer(gbuf_bin), gbuf_leftbytes(gbuf_bin));
                close(fp);
            }
        }
    }
    JSON_DECREF(jn_content);
    return 0;
}




            /***************************
             *      Actions
             ***************************/




/***************************************************************************
 *  Execute batch of input parameters when the route is opened.
 ***************************************************************************/
PRIVATE int ac_on_open(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    const char *yuno_role = kw_get_str(kw, "remote_yuno_role", "", 0);
    const char *yuno_name = kw_get_str(kw, "remote_yuno_name", "", 0);

    if(priv->verbose || priv->interactive) {
        printf("Connected to '%s^%s', url:'%s'.\n",
            yuno_role,
            yuno_name,
            gobj_read_str_attr(gobj, "url")
        );
    }
    gobj_write_pointer_attr(gobj, "gobj_connector", src);

    const char *command = gobj_read_str_attr(gobj, "command");
    if(gobj_read_bool_attr(gobj, "interactive")) {
        if(!empty_string(command)) {
            do_command(gobj, command);
        } else {
            printf("Type 'quit' to exit, 'history' to show history\n");
            clear_input_line(gobj);
        }
    } else {
        if(empty_string(command)) {
            printf("What command?\n");
            gobj_set_exit_code(-1);
            gobj_shutdown();
        }
        do_command(gobj, command);
    }

    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_on_close(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    gobj_write_pointer_attr(gobj, "gobj_connector", 0);
    if(priv->verbose || priv->interactive) {
        printf("\nDisconnected.\n");
    }

    gobj_set_exit_code(-1);
    gobj_shutdown();

    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *  HACK Este evento solo puede venir de GCLASS_EDITLINE
 ***************************************************************************/
PRIVATE int ac_command(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    json_t *kw_input_command = json_object();
    gobj_send_event(src, "EV_GETTEXT", kw_input_command, gobj); // EV_GETTEXT is EVF_KW_WRITING
    const char *command = kw_get_str(kw_input_command, "text", 0, 0);

    if(empty_string(command)) {
        clear_input_line(gobj);
        KW_DECREF(kw_input_command);
        KW_DECREF(kw);
        return 0;
    }
    if(strcasecmp(command, "exit")==0 || strcasecmp(command, "quit")==0) {
        gobj_stop(gobj);
        KW_DECREF(kw_input_command);
        KW_DECREF(kw);
        return 0;
    }

    if(strcasecmp(command, "history")==0) {
        list_history(gobj);
        KW_DECREF(kw_input_command);
        KW_DECREF(kw);
        return 0;
    }

    char *comment;
    GBUFFER *gbuf_parsed_command = replace_cli_vars(gobj, command, &comment);
    if(!gbuf_parsed_command) {
        printf("%s%s%s\n", On_Red BWhite, command, Color_Off);
        clear_input_line(gobj);
        KW_DECREF(kw_input_command);
        KW_DECREF(kw);
        return 0;
    }
    char *xcmd = gbuf_cur_rd_pointer(gbuf_parsed_command);
    json_t *kw_command = json_object();
    if(*xcmd == '*') {
        xcmd++;
        kw_set_subdict_value(kw_command, "__md_iev__", "display_mode", json_string("form"));
    }
    json_t *webix = 0;
    if(priv->gobj_connector) {
        webix = gobj_command(priv->gobj_connector, xcmd, kw_command, gobj);
    } else {
        printf("%s%s%s\n", On_Red BWhite, "No connection", Color_Off);
    }
    gbuf_decref(gbuf_parsed_command);

    /*
     *  Print json response in display window
     */
    if(webix) {
        display_webix_result(
            gobj,
            webix
        );
    } else {
        /* asychronous responses return 0 */
        printf("\n"); fflush(stdout);
    }
    KW_DECREF(kw_input_command);
    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *  Command received.
 ***************************************************************************/
PRIVATE int ac_command_answer(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    if(gobj_read_bool_attr(gobj, "interactive")) {
        return display_webix_result(
            gobj,
            kw
        );
    } else {
        int result = WEBIX_RESULT(kw);
        const char *comment = WEBIX_COMMENT(kw);
        if(result != 0){
            printf("%sERROR %d: %s%s\n", On_Red BWhite, result, comment, Color_Off);
        } else {
            if(!empty_string(comment)) {
                printf("%s\n", comment);
            }
            json_t *jn_data = WEBIX_DATA(kw);
            if(json_is_string(jn_data)) {
                const char *data = json_string_value(jn_data);
                printf("%s\n", data);
            } else {
                print_json(jn_data);
            }
        }
        KW_DECREF(kw);
        gobj_set_exit_code(result);
        gobj_shutdown();
    }
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_edit_config(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    int result = WEBIX_RESULT(kw);
    const char *comment = WEBIX_COMMENT(kw);
    if(result != 0) {
        printf("%sERROR %d: %s%s\n", On_Red BWhite, result, comment, Color_Off);
        clear_input_line(gobj);
        KW_DECREF(kw);
        return 0;
    }
    json_t *record = json_array_get(kw_get_dict_value(kw, "data", 0, 0), 0);
    if(!record) {
        printf("%sERROR %d: %s%s\n", On_Red BWhite, result, "Internal error, no data", Color_Off);
        clear_input_line(gobj);
        KW_DECREF(kw);
        return 0;
    }

    const char *id = kw_get_str(record, "id", 0, 0);
    if(!id) {
        printf("%sERROR %d: %s%s\n", On_Red BWhite, result, "Internal error, no id", Color_Off);
        clear_input_line(gobj);
        KW_DECREF(kw);
        return 0;
    }

    json_t *jn_content = kw_get_dict_value(record, "zcontent", 0, 0);
    if(!jn_content) {
        printf("%sERROR %d: %s%s\n", On_Red BWhite, result, "Internal error, no content", Color_Off);
        clear_input_line(gobj);
        KW_DECREF(kw);
        return 0;
    }

    JSON_INCREF(jn_content);
    char path[NAME_MAX];

    save_local_json(gobj, path, sizeof(path), id, jn_content);
    //log_debug_printf("save_local_json %s", path);
    edit_json(gobj, path);

    size_t flags = 0;
    json_error_t error;
    json_t *jn_new_content = json_load_file(path, flags, &error);
    if(!jn_new_content) {
        printf("%sERROR %d: Bad json format in '%s' source. Line %d, Column %d, Error '%s'%s\n",
            On_Red BWhite,
            result,
            path,
            error.line,
            error.column,
            error.text,
            Color_Off
        );
        clear_input_line(gobj);
        KW_DECREF(kw);
        return 0;
    }
    JSON_DECREF(jn_new_content);

    char upgrade_command[512];
    snprintf(upgrade_command, sizeof(upgrade_command),
        "create-config id='%s' content64=$$(%s) ",
        id,
        path
    );

    json_t *kw_line = json_object();
    json_object_set_new(kw_line, "text", json_string(upgrade_command));
    gobj_send_event(priv->gobj_editline, "EV_SETTEXT", kw_line, gobj);

    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_view_config(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    int result = WEBIX_RESULT(kw);
    const char *comment = WEBIX_COMMENT(kw);
    if(result != 0) {
        printf("%sERROR %d: %s%s\n", On_Red BWhite, result, comment, Color_Off);
        clear_input_line(gobj);
        KW_DECREF(kw);
        return 0;
    }
    json_t *record = json_array_get(kw_get_dict_value(kw, "data", 0, 0), 0);
    if(!record) {
        printf("%sERROR %d: %s%s\n", On_Red BWhite, result, "Internal error, no data", Color_Off);
        clear_input_line(gobj);
        KW_DECREF(kw);
        return 0;
    }

    json_t *jn_content = kw_get_dict_value(record, "zcontent", 0, 0);
    if(!jn_content) {
        printf("%sERROR %d: %s%s\n", On_Red BWhite, result, "Internal error, no content", Color_Off);
        clear_input_line(gobj);
        KW_DECREF(kw);
        return 0;
    }

    const char *name = kw_get_str(record, "name", "__temporal__", 0);
    JSON_INCREF(jn_content);
    char path[NAME_MAX];

    save_local_json(gobj, path, sizeof(path), name, jn_content);
    //log_debug_printf("save_local_json %s", path);
    edit_json(gobj, path);

    clear_input_line(gobj);

    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_read_json(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    int result = WEBIX_RESULT(kw);
    const char *comment = WEBIX_COMMENT(kw);
    if(result != 0) {
        printf("%sERROR %d: %s%s\n", On_Red BWhite, result, comment, Color_Off);
        clear_input_line(gobj);
        KW_DECREF(kw);
        return 0;
    }
    json_t *record = json_array_get(kw_get_dict_value(kw, "data", 0, 0), 0);
    if(!record) {
        printf("%sERROR %d: %s%s\n", On_Red BWhite, result, "Internal error, no data", Color_Off);
        clear_input_line(gobj);
        KW_DECREF(kw);
        return 0;
    }

    json_t *jn_content = kw_get_dict_value(record, "zcontent", 0, 0);
    if(!jn_content) {
        printf("%sERROR %d: %s%s\n", On_Red BWhite, result, "Internal error, no content", Color_Off);
        clear_input_line(gobj);
        KW_DECREF(kw);
        return 0;
    }

    const char *name = kw_get_str(record, "name", "__temporal__", 0);
    JSON_INCREF(jn_content);
    char path[NAME_MAX];

    save_local_json(gobj, path, sizeof(path), name, jn_content);
    //log_debug_printf("save_local_json %s", path);
    edit_json(gobj, path);

    clear_input_line(gobj);

    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_read_file(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    int result = WEBIX_RESULT(kw);
    const char *comment = WEBIX_COMMENT(kw);
    if(result != 0) {
        printf("%sERROR %d: %s%s\n", On_Red BWhite, result, comment, Color_Off);
        clear_input_line(gobj);
        KW_DECREF(kw);
        return 0;
    }
    json_t *record = json_array_get(kw_get_dict_value(kw, "data", 0, 0), 0);
    if(!record) {
        printf("%sERROR %d: %s%s\n", On_Red BWhite, result, "Internal error, no data", Color_Off);
        clear_input_line(gobj);
        KW_DECREF(kw);
        return 0;
    }

    json_t *jn_content = kw_get_dict_value(record, "zcontent", 0, 0);
    if(!jn_content) {
        printf("%sERROR %d: %s%s\n", On_Red BWhite, result, "Internal error, no content", Color_Off);
        clear_input_line(gobj);
        KW_DECREF(kw);
        return 0;
    }

    const char *name = kw_get_str(record, "name", "__temporal__", 0);
    JSON_INCREF(jn_content);
    char path[NAME_MAX];

    save_local_string(gobj, path, sizeof(path), name, jn_content);
    //log_debug_printf("save_local_json %s", path);
    edit_json(gobj, path);

    clear_input_line(gobj);

    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_read_binary_file(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    int result = WEBIX_RESULT(kw);
    const char *comment = WEBIX_COMMENT(kw);
    if(result != 0) {
        printf("%sERROR %d: %s%s\n", On_Red BWhite, result, comment, Color_Off);
        clear_input_line(gobj);
        KW_DECREF(kw);
        return 0;
    }
    json_t *record = json_array_get(kw_get_dict_value(kw, "data", 0, 0), 0);
    if(!record) {
        printf("%sERROR %d: %s%s\n", On_Red BWhite, result, "Internal error, no data", Color_Off);
        clear_input_line(gobj);
        KW_DECREF(kw);
        return 0;
    }

    json_t *jn_content = kw_get_dict_value(record, "content64", 0, 0);
    if(!jn_content) {
        printf("%sERROR %d: %s%s\n", On_Red BWhite, result, "Internal error, no content", Color_Off);
        clear_input_line(gobj);
        KW_DECREF(kw);
        return 0;
    }

    const char *name = kw_get_str(record, "name", "__temporal__", 0);
    JSON_INCREF(jn_content);
    char path[NAME_MAX];
    save_local_base64(gobj, path, sizeof(path), name, jn_content);

    clear_input_line(gobj);

    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_screen_ctrl(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    SWITCHS(event) {
        CASES("EV_CLRSCR")
            printf(Clear_Screen);
            fflush(stdout);
            gobj_send_event(priv->gobj_editline, "EV_REFRESH_LINE", 0, gobj);
            break;
        CASES("EV_SCROLL_PAGE_UP")
            break;
        CASES("EV_SCROLL_PAGE_DOWN")
            break;
        CASES("EV_SCROLL_LINE_UP")
            break;
        CASES("EV_SCROLL_LINE_DOWN")
            break;
        CASES("EV_SCROLL_TOP")
            break;
        CASES("EV_SCROLL_BOTTOM")
            break;
        DEFAULTS
            break;
    } SWITCHS_END;

    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_timeout(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *                          FSM
 ***************************************************************************/
PRIVATE const EVENT input_events[] = {
    // top input
    {"EV_COMMAND",              0, 0, 0},
    {"EV_MT_COMMAND_ANSWER",    EVF_PUBLIC_EVENT,  0,  0},
    {"EV_EDIT_CONFIG",          EVF_PUBLIC_EVENT, 0, 0},
    {"EV_VIEW_CONFIG",          EVF_PUBLIC_EVENT, 0, 0},
    {"EV_EDIT_YUNO_CONFIG",     EVF_PUBLIC_EVENT, 0, 0},
    {"EV_VIEW_YUNO_CONFIG",     EVF_PUBLIC_EVENT, 0, 0},
    {"EV_READ_JSON",            EVF_PUBLIC_EVENT, 0, 0},
    {"EV_READ_FILE",            EVF_PUBLIC_EVENT, 0, 0},
    {"EV_READ_BINARY_FILE",     EVF_PUBLIC_EVENT, 0, 0},

    {"EV_CLRSCR",               0, 0, 0},

    {"EV_SCROLL_PAGE_UP",       0, 0, 0},
    {"EV_SCROLL_PAGE_DOWN",     0, 0, 0},

    {"EV_SCROLL_LINE_UP",       0, 0, 0},
    {"EV_SCROLL_LINE_DOWN",     0, 0, 0},
    {"EV_SCROLL_TOP",           0, 0, 0},
    {"EV_SCROLL_BOTTOM",        0, 0, 0},

    {"EV_ON_OPEN",          0,  0,  0},
    {"EV_ON_CLOSE",         0,  0,  0},
    // bottom input
    {"EV_TIMEOUT",          0,  0,  0},
    {"EV_STOPPED",          0,  0,  0},
    // internal
    {NULL, 0, 0, 0}
};
PRIVATE const EVENT output_events[] = {
    {NULL, 0, 0, 0}
};
PRIVATE const char *state_names[] = {
    "ST_DISCONNECTED",
    "ST_CONNECTED",
    NULL
};

PRIVATE EV_ACTION ST_DISCONNECTED[] = {
    {"EV_ON_OPEN",                  ac_on_open,                 "ST_CONNECTED"},
    {"EV_ON_CLOSE",                 ac_on_close,                0},
    {"EV_STOPPED",                  0,                          0},
    {0,0,0}
};
PRIVATE EV_ACTION ST_CONNECTED[] = {
    {"EV_COMMAND",                  ac_command,                 0},
    {"EV_MT_COMMAND_ANSWER",        ac_command_answer,          0},
    {"EV_EDIT_CONFIG",              ac_edit_config,             0},
    {"EV_VIEW_CONFIG",              ac_view_config,             0},
    {"EV_EDIT_YUNO_CONFIG",         ac_edit_config,             0},
    {"EV_VIEW_YUNO_CONFIG",         ac_view_config,             0},
    {"EV_READ_JSON",                ac_read_json,               0},
    {"EV_READ_FILE",                ac_read_file,               0},
    {"EV_READ_BINARY_FILE",         ac_read_binary_file,        0},
    {"EV_CLRSCR",                   ac_screen_ctrl,             0},
    {"EV_SCROLL_PAGE_UP",           ac_screen_ctrl,             0},
    {"EV_SCROLL_PAGE_DOWN",         ac_screen_ctrl,             0},
    {"EV_SCROLL_LINE_UP",           ac_screen_ctrl,             0},
    {"EV_SCROLL_LINE_DOWN",         ac_screen_ctrl,             0},
    {"EV_SCROLL_TOP",               ac_screen_ctrl,             0},
    {"EV_SCROLL_BOTTOM",            ac_screen_ctrl,             0},
    {"EV_ON_CLOSE",                 ac_on_close,                "ST_DISCONNECTED"},
    {"EV_TIMEOUT",                  ac_timeout,                 0},
    {"EV_STOPPED",                  0,                          0},
    {0,0,0}
};

PRIVATE EV_ACTION *states[] = {
    ST_DISCONNECTED,
    ST_CONNECTED,
    NULL
};

PRIVATE FSM fsm = {
    input_events,
    output_events,
    state_names,
    states,
};

/***************************************************************************
 *              GClass
 ***************************************************************************/
/*---------------------------------------------*
 *              Local methods table
 *---------------------------------------------*/
PRIVATE LMETHOD lmt[] = {
    {0, 0, 0}
};

/*---------------------------------------------*
 *              GClass
 *---------------------------------------------*/
PRIVATE GCLASS _gclass = {
    0,  // base
    GCLASS_YCOMMAND_NAME,
    &fsm,
    {
        mt_create,
        0, //mt_create2,
        mt_destroy,
        mt_start,
        mt_stop,
        0, //mt_play,
        0, //mt_pause,
        mt_writing,
        0, //mt_reading,
        0, //mt_subscription_added,
        0, //mt_subscription_deleted,
        0, //mt_child_added,
        0, //mt_child_removed,
        0, //mt_stats,
        0, //mt_command_parser,
        0, //mt_inject_event,
        0, //mt_create_resource,
        0, //mt_list_resource,
        0, //mt_update_resource,
        0, //mt_delete_resource,
        0, //mt_add_child_resource_link
        0, //mt_delete_child_resource_link
        0, //mt_get_resource
        0, //mt_authorization_parser,
        0, //mt_authenticate,
        0, //mt_list_childs,
        0, //mt_stats_updated,
        0, //mt_disable,
        0, //mt_enable,
        0, //mt_trace_on,
        0, //mt_trace_off,
        0, //mt_gobj_created,
        0, //mt_future33,
        0, //mt_future34,
        0, //mt_publish_event,
        0, //mt_publication_pre_filter,
        0, //mt_publication_filter,
        0, //mt_authz_checker,
        0, //mt_future39,
        0, //mt_create_node,
        0, //mt_update_node,
        0, //mt_delete_node,
        0, //mt_link_nodes,
        0, //mt_future44,
        0, //mt_unlink_nodes,
        0, //mt_topic_jtree,
        0, //mt_get_node,
        0, //mt_list_nodes,
        0, //mt_shoot_snap,
        0, //mt_activate_snap,
        0, //mt_list_snaps,
        0, //mt_treedbs,
        0, //mt_treedb_topics,
        0, //mt_topic_desc,
        0, //mt_topic_links,
        0, //mt_topic_hooks,
        0, //mt_node_parents,
        0, //mt_node_childs,
        0, //mt_list_instances,
        0, //mt_node_tree,
        0, //mt_topic_size,
        0, //mt_future62,
        0, //mt_future63,
        0, //mt_future64
    },
    lmt,
    tattr_desc,
    sizeof(PRIVATE_DATA),
    0,  // acl
    s_user_trace_level,
    0,  // cmds
    0,  // gcflag
};

/***************************************************************************
 *              Public access
 ***************************************************************************/
PUBLIC GCLASS *gclass_ycommand(void)
{
    return &_gclass;
}
