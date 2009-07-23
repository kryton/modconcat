/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * mod_concat.c: concatantes several files together
 * URLs will be in the form /<basedir>/??file1,dir2/file2,...
 * The Idea was initially thought of by David Davis in Vox, and reimplemented in perlbal.
 * Ian Holsman
 * 15/6/7
 */

#include "apr_strings.h"
#include "apr_fnmatch.h"
#include "apr_strings.h"
#include "apr_lib.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"

#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#define CORE_PRIVATE
#include "http_core.h"
#include "http_request.h"
#include "http_protocol.h"
#include "http_log.h"
#include "http_main.h"
#include "util_script.h"

#include "mod_core.h"

module AP_MODULE_DECLARE_DATA concat_module;

/****************************************************************
 *
 * Handling configuration directives...
 */

typedef struct concat_config_struct {
    int disabled;
} concat_config_rec;

static const command_rec concat_cmds[] =
{
   
    AP_INIT_FLAG("concat_disable", ap_set_flag_slot,
                  (void *)APR_OFFSETOF(concat_config_rec, disabled),
                  OR_INDEXES, "disable concat in this location"),
    {NULL}
};

static void *create_concat_config(apr_pool_t *p, char *dummy)
{
    concat_config_rec *new =
    (concat_config_rec *) apr_pcalloc(p, sizeof(concat_config_rec));

    new->disabled = 2;

    return (void *) new;
}

static void *merge_concat_configs(apr_pool_t *p, void *basev, void *addv)
{
    concat_config_rec *new;
    concat_config_rec *base = (concat_config_rec *) basev;
    concat_config_rec *add = (concat_config_rec *) addv;

    new = (concat_config_rec *) apr_pcalloc(p, sizeof(concat_config_rec));
    if (add->disabled == 2) {
        new->disabled = base->disabled;
    }
    else {
        new->disabled = add->disabled;
    }
    return new;
}

static int concat_handler(request_rec *r)
{
    concat_config_rec *conf;
    conn_rec *c = r->connection;

    core_dir_config *d;
    apr_file_t *f = NULL;
    apr_off_t length=0;
    apr_time_t mtime;
    int count=0;
    char *file_string;
    char *token;
    char *strtokstate;
    apr_bucket_brigade *bb;

    apr_bucket *b;
    apr_status_t rv;

    r->allowed |= (AP_METHOD_BIT << M_GET);
    if (r->method_number != M_GET) {
        return DECLINED;
    }

    if (!r->args) {
        return DECLINED;
    }

    if (r->args[0] != '?') {
        return DECLINED;
    }

    conf = (concat_config_rec *) ap_get_module_config(r->per_dir_config, &concat_module);
    if (conf->disabled == 1)
        return DECLINED;

    d = (core_dir_config *)ap_get_module_config(r->per_dir_config,
                                                &core_module);

    file_string = &(r->args[1]);
    token = apr_strtok(file_string, ",", &strtokstate);
    bb = apr_brigade_create(r->pool, c->bucket_alloc);
    while (token) {
        char *filename;
        char *file2;
        apr_file_t *f = NULL;
        apr_finfo_t finfo;
        count++;

        rv = apr_filepath_merge(&file2, NULL, token,
                                APR_FILEPATH_SECUREROOTTEST |
                                APR_FILEPATH_NOTABSOLUTE, r->pool);


        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                "mod_concat:filename looks fishy: %s", token);
            return HTTP_FORBIDDEN;
        }
        filename = apr_pstrcat (r->pool, r->filename,  file2, NULL);
        if ((rv = apr_file_open(&f, filename, APR_READ
#if APR_HAS_SENDFILE
                    | ((d->enable_sendfile == ENABLE_SENDFILE_OFF)
                        ? 0 : APR_SENDFILE_ENABLED)
#endif
                , APR_OS_DEFAULT, r->pool)) != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                        "mod_concat:file permissions deny server access: %s %s", filename,r->uri);
            return HTTP_FORBIDDEN;
        }
        if (( rv = apr_file_info_get( &finfo, APR_FINFO_MIN, f))!= APR_SUCCESS )  {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                        "mod_concat:file info failure: %s", filename);
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        length += finfo.size;
        if (count == 1) {
            request_rec *sub_req;
            mtime = finfo.mtime;
            sub_req = ap_sub_req_lookup_file(filename, r, NULL);
            if (sub_req->status != HTTP_OK) {
                int res = sub_req->status;
                ap_destroy_sub_req(sub_req);
                return res;
            }
            ap_set_content_type(r, sub_req->content_type);
        }
        else {
            if (finfo.mtime > mtime ) {
                mtime = finfo.mtime;
            }
        }
        apr_brigade_insert_file(bb, f, 0, finfo.size, r->pool);
        token = apr_strtok( NULL, ",", &strtokstate);
    }
    b = apr_bucket_eos_create(c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, b);
    ap_set_content_length(r, length);
    apr_table_unset(r->headers_out, "ETag");
    r->mtime = mtime;
    ap_set_last_modified(r);
    rv = ap_pass_brigade(r->output_filters, bb);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "mod_concat: ap_pass_brigade failed for uri %s", r->uri);
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    return OK;
}
static void register_hooks(apr_pool_t *p)
{
    static const char * const aszPost[] = { "mod_autoindex.c", NULL };
    // we want to have a look at the directories *BEFORE* autoindex gets to it
    ap_hook_handler(concat_handler,NULL,aszPost,APR_HOOK_MIDDLE);

}

module AP_MODULE_DECLARE_DATA concat_module =
{
    STANDARD20_MODULE_STUFF,
    create_concat_config,    /* dir config creater */
    merge_concat_configs,    /* dir merger --- default is to override */
    NULL,                       /* server config */
    NULL,                       /* merge server config */
    concat_cmds,             /* command apr_table_t */
    register_hooks              /* register hooks */
};
