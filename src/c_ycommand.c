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
#include "c_ycommand.h"

/***************************************************************************
 *              Constants
 ***************************************************************************/

/***************************************************************************
 *              Structures
 ***************************************************************************/

/***************************************************************************
 *              Prototypes
 ***************************************************************************/
PRIVATE int cmd_connect(hgobj gobj);
PRIVATE int do_command(hgobj gobj);

/***************************************************************************
 *          Data: config, public data, private data
 ***************************************************************************/

/*---------------------------------------------*
 *      Attributes - order affect to oid's
 *---------------------------------------------*/
PRIVATE sdata_desc_t tattr_desc[] = {
/*-ATTR-type------------name----------------flag--------default---------description---------- */
SDATA (ASN_BOOLEAN,     "verbose",          0,          1,              "Verbose mode."),
SDATA (ASN_OCTET_STR,   "command",          0,          "",             "Command."),
SDATA (ASN_OCTET_STR,   "url",              0,          "ws://127.0.0.1:1991",  "Url to get Statistics. Can be a ip/hostname or a full url"),
SDATA (ASN_OCTET_STR,   "realm_name",       0,          0,              "Realm name"),
SDATA (ASN_OCTET_STR,   "yuno_name",        0,          0,              "Yuno name"),
SDATA (ASN_OCTET_STR,   "yuno_role",        0,          0,              "Yuno role"),
SDATA (ASN_OCTET_STR,   "yuno_service",     0,          "__yuno__",     "Yuno service"),
SDATA (ASN_OCTET_STR,   "gobj_name",        0,          "__default_service__", "Gobj."),

SDATA (ASN_POINTER,     "gobj_connector",   0,          0,              "connection gobj"),
SDATA (ASN_POINTER,     "user_data",        0,          0,              "user data"),
SDATA (ASN_POINTER,     "user_data2",       0,          0,              "more user data"),
SDATA_END()
};

/*---------------------------------------------*
 *      GClass trace levels
 *---------------------------------------------*/
enum {
    TRACE_USER = 0x0001,
};
PRIVATE const trace_level_t s_user_trace_level[16] = {
{"trace_user",        "Trace user description"},
{0, 0},
};


/*---------------------------------------------*
 *              Private data
 *---------------------------------------------*/
typedef struct _PRIVATE_DATA {
    int32_t verbose;

    hgobj gobj_connector;
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

    /*
     *  Do copy of heavy used parameters, for quick access.
     *  HACK The writable attributes must be repeated in mt_writing method.
     */
    SET_PRIV(gobj_connector,        gobj_read_pointer_attr)
    SET_PRIV(verbose,               gobj_read_bool_attr)
}

/***************************************************************************
 *      Framework Method writing
 ***************************************************************************/
PRIVATE void mt_writing(hgobj gobj, const char *path)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    IF_EQ_SET_PRIV(gobj_connector,     gobj_read_pointer_attr)
    ELIF_EQ_SET_PRIV(verbose,           gobj_read_bool_attr)
    END_EQ_SET_PRIV()
}

/***************************************************************************
 *      Framework Method destroy
 ***************************************************************************/
PRIVATE void mt_destroy(hgobj gobj)
{
}

/***************************************************************************
 *      Framework Method start
 ***************************************************************************/
PRIVATE int mt_start(hgobj gobj)
{
    cmd_connect(gobj);
    return 0;
}

/***************************************************************************
 *      Framework Method stop
 ***************************************************************************/
PRIVATE int mt_stop(hgobj gobj)
{
    return 0;
}




            /***************************
             *      Local Methods
             ***************************/




PRIVATE char agent_filter_chain_config[]= "\
{                                               \n\
    'name': '(^^__url__^^)',                    \n\
    'gclass': 'IEvent_cli',                     \n\
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
                            'kw': {                                     \n\
                                'kw_connex': {                          \n\
                                    'urls':[                            \n\
                                        '(^^__url__^^)'                 \n\
                                    ]                                   \n\
                                }                                       \n\
                            }                                           \n\
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
    char _url[128];
    if(!strchr(url, ':')) {
        snprintf(_url, sizeof(_url), "ws://%s:1991", url); // TODO saca el puerto 1991 a configuración
        url = _url;
    }
    const char *yuno_name = ""; // No direct connection, all through agent. gobj_read_str_attr(gobj, "yuno_name");
    const char *yuno_role = "yuneta_agent"; // No direct connection, all through agent. gobj_read_str_attr(gobj, "yuno_role");
    const char *yuno_service = "__default_service__"; //gobj_read_str_attr(gobj, "yuno_service");

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

    hgobj gobj_remote_agent = gobj_create_tree(
        gobj,
        agent_filter_chain_config,
        sjson_config_variables,
        "EV_ON_SETUP",
        "EV_ON_SETUP_COMPLETE"
    );
    gbmem_free(sjson_config_variables);

    gobj_start_tree(gobj_remote_agent);

    if(priv->verbose) {
        printf("Connecting to %s...\n", url);
    }
    return 0;
}


/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int do_command(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    GBUFFER *gbuf = gbuf_create(8*1024, 8*1024, 0, 0);
    const char *realm_name = gobj_read_str_attr(gobj, "realm_name");
    const char *yuno_name = gobj_read_str_attr(gobj, "yuno_name");
    const char *yuno_role = gobj_read_str_attr(gobj, "yuno_role");
    const char *yuno_service = gobj_read_str_attr(gobj, "yuno_service");
    const char *command = gobj_read_str_attr(gobj, "command");
    const char *gobj_name_ = gobj_read_str_attr(gobj, "gobj_name");

    if(yuno_service && (
            strcmp(yuno_service, "__agent__")==0 ||
            strcmp(yuno_service, "__agent_yuno__")==0 ||
            strcmp(yuno_service, "__yuneta_agent__")==0)) {
        gbuf_printf(gbuf, "command-agent command=%s", command);
        if(strcmp(yuno_service, "__agent_yuno__")==0) {
            gbuf_printf(gbuf, " service=%s", "__yuno__");
        }
    } else {
        gbuf_printf(gbuf, "command-yuno command=%s", command);
        if(yuno_service) {
            gbuf_printf(gbuf, " service=%s", yuno_service);
        }
    }
    if(realm_name) {
        gbuf_printf(gbuf, " realm_name=%s", realm_name);
    }
    if(yuno_role) {
        gbuf_printf(gbuf, " yuno_role=%s", yuno_role);
    }
    if(yuno_name) {
        gbuf_printf(gbuf, " yuno_name=%s", yuno_name);
    }
    if(gobj_name_) {
        gbuf_printf(gbuf, " gobj_name='%s'", gobj_name_);
    }

    gobj_command(priv->gobj_connector, gbuf_cur_rd_pointer(gbuf), 0, gobj);
    GBUF_DECREF(gbuf);
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
    const char *agent_name = kw_get_str(kw, "remote_yuno_name", 0, 0); // remote agent name

    if(priv->verbose) {
        printf("Connected to '%s', url: '%s'.\n", agent_name, gobj_read_str_attr(gobj, "url"));
    }
    gobj_write_pointer_attr(gobj, "gobj_connector", src);

    const char *command = gobj_read_str_attr(gobj, "command");
    if(empty_string(command)) {
        printf("What command?\n");
        gobj_set_exit_code(-1);
        gobj_shutdown();
    } else {
        do_command(gobj);
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
    if(!gobj_is_running(gobj)) {
        KW_DECREF(kw);
        return 0;
    }
    if(priv->verbose) {
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
        printf("Error %d: %s\n", result, comment);
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
    gobj_set_exit_code(result);
    gobj_shutdown();
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
    GCLASS_YCOMMAND_NAME,      // CHANGE WITH each gclass
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
        0, //mt_future24,
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
        0, //mt_future38,
        0, //mt_future39,
        0, //mt_create_node,
        0, //mt_update_node,
        0, //mt_delete_node,
        0, //mt_link_nodes,
        0, //mt_link_nodes2,
        0, //mt_unlink_nodes,
        0, //mt_unlink_nodes2,
        0, //mt_get_node,
        0, //mt_list_nodes,
        0, //mt_snap_nodes,
        0, //mt_set_nodes_snap,
        0, //mt_list_nodes_snaps,
        0, //mt_future52,
        0, //mt_future53,
        0, //mt_future54,
        0, //mt_future55,
        0, //mt_future56,
        0, //mt_future57,
        0, //mt_future58,
        0, //mt_future59,
        0, //mt_future60,
        0, //mt_future61,
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
