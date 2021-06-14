/***********************************************************************
 *          C_YCOMMAND.C
 *          YCommand GClass.
 *
 *          Yuneta Statistics
 *
 *          Copyright (c) 2016 Niyamaka.
 *          All Rights Reserved.
 ***********************************************************************/
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

    KEY_START =         0x1B5B48,       // .[H
    KEY_PREV_PAGE =     0x1B5B357E,     // .[5~
    KEY_NEXT_PAGE =     0x1B5B367E,     // .[6~
    KEY_END =           0x1B5B46,       // .[F
    KEY_UP =            0x1B5B41,       // .[A
    KEY_DOWN =          0x1B5B42,       // .[B
    KEY_LEFT =          0x1B5B44,       // .[D
    KEY_RIGHT =         0x1B5B43,       // .[C
    KEY_INS =           0x1B5B327E,     // .[2~
    KEY_DEL =           0x1B5B337E,     // .[3~
    KEY_ALT_START =     0x1B5B313B3348, // .[1;3H
    KEY_ALT_PREV_PAGE = 0x1B5B353B337E, // .[5;3~
    KEY_ALT_NEXT_PAGE = 0x1B5B363B337E, // .[6;3~
    KEY_ALT_END =       0x1B5B313B3346, // .[1;3F
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

/***************************************************************************
 *          Data: config, public data, private data
 ***************************************************************************/
struct {
    const char *event;
    unsigned long long key;
} keytable[] = {
{"EV_EDITLINE_MOVE_START",       CTRL_A},
{"EV_EDITLINE_MOVE_START",       KEY_START},
{"EV_EDITLINE_MOVE_END",         CTRL_E},
{"EV_EDITLINE_MOVE_END",         KEY_END},
{"EV_EDITLINE_MOVE_LEFT",        CTRL_B},
{"EV_EDITLINE_MOVE_LEFT",        KEY_LEFT},
{"EV_EDITLINE_MOVE_RIGHT",       CTRL_F},
{"EV_EDITLINE_MOVE_RIGHT",       KEY_RIGHT},
{"EV_EDITLINE_DEL_CHAR",         CTRL_D},
{"EV_EDITLINE_DEL_CHAR",         KEY_DEL},
{"EV_EDITLINE_BACKSPACE",        CTRL_H},
{"EV_EDITLINE_BACKSPACE",        BACKSPACE},
{"EV_EDITLINE_COMPLETE_LINE",    TAB},
{"EV_EDITLINE_ENTER",            ENTER},
{"EV_EDITLINE_PREV_HIST",        KEY_UP},
{"EV_EDITLINE_NEXT_HIST",        KEY_DOWN},
{"EV_EDITLINE_SWAP_CHAR",        CTRL_T},
{"EV_EDITLINE_DEL_LINE",         CTRL_U},
{"EV_EDITLINE_DEL_LINE",         CTRL_Y},
{"EV_EDITLINE_DEL_PREV_WORD",    CTRL_W},

{"EV_CLRSCR",                    CTRL_K},

{"EV_SCROLL_PAGE_UP",            KEY_PREV_PAGE},
{"EV_SCROLL_PAGE_DOWN",          KEY_NEXT_PAGE},

{"EV_SCROLL_LINE_UP",            KEY_ALT_PREV_PAGE},
{"EV_SCROLL_LINE_DOWN",          KEY_ALT_NEXT_PAGE},
{"EV_SCROLL_TOP",                KEY_ALT_START},
{"EV_SCROLL_BOTTOM",             KEY_ALT_END},

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
PRIVATE void mt_create(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    priv->gobj_editline = gobj_create("", GCLASS_EDITLINE, 0, gobj);

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
PRIVATE const char *event_by_key(int kb)
{
    for(int i=0; keytable[i].event!=0; i++) {
        if(kb == keytable[i].key) {
            return keytable[i].event;
        }
    }
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int process_key(hgobj gobj, int kb)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    const char *event = event_by_key(kb);

    if(!empty_string(event)) {
        gobj_send_event(priv->gobj_editline, event, 0, gobj);
        return 0;
    }

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

    if(priv->verbose) {
        log_debug_dump(
            0,
            buf->base,
            nread,
            ""
        );
    }

    for(int i=0; i<nread; i++) {
        process_key(gobj, buf->base[i]);
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
            printf("Type 'quit' or 'exit' to exit\n");
            printf("ycommand> ");
            fflush(stdout);
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
//     if(!gobj_is_running(gobj)) {
//         KW_DECREF(kw);
//         return 0;
//     }
    if(priv->verbose || priv->interactive) {
        printf("Disconnected.\n");
    }

    gobj_set_exit_code(-1);
    gobj_shutdown();

    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *  Command received.
 ***************************************************************************/
PRIVATE int ac_command(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    int result = WEBIX_RESULT(kw);
    const char *comment = WEBIX_COMMENT(kw);
    if(result != 0){
        printf("%sERROR %d: '%s'%s\n", On_Red BWhite, result, comment, Color_Off);
    } else {
        if(!empty_string(comment)) {
            printf("%s\n", comment);
        }
        json_t *jn_data = WEBIX_DATA(kw); //kw_get_dict_value(kw, "data", 0, 0);
        if(json_array_size(jn_data) || json_object_size(jn_data)) {
            print_json(jn_data);
        }
    }
    KW_DECREF(kw);

    if(gobj_read_bool_attr(gobj, "interactive")) {
        printf("ycommand> ");
        fflush(stdout);
    } else {
        gobj_set_exit_code(result);
        gobj_shutdown();
    }
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
    {"EV_MT_COMMAND_ANSWER",EVF_PUBLIC_EVENT,  0,  0},
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
    {"EV_MT_COMMAND_ANSWER",        ac_command,                   0},
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
