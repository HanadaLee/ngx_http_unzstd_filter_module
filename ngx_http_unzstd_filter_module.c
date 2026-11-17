/*
 * Copyright (C) Hanada
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Google Inc.
 * Copyright (C) Alex Zhang
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <zstd.h>

#if (NGX_EXPR)
#include <ngx_http_expr_module.h>
#endif


#define NGX_HTTP_UNZSTD_PROCESS    0
#define NGX_HTTP_UNZSTD_FLUSH      1
#define NGX_HTTP_UNZSTD_FINISH     2
#define NGX_HTTP_UNZSTD_CHUNK      (64 * 1024)


typedef struct {
    ngx_str_t    dict_file;
    ZSTD_DDict  *dict;
} ngx_http_unzstd_main_conf_t;


typedef struct {
#if (NGX_EXPR)
    ngx_array_t  *enable;
    ngx_array_t  *force;
#else
    ngx_flag_t    enable;
    ngx_flag_t    force;
#endif
    ngx_bufs_t    bufs;
} ngx_http_unzstd_conf_t;


typedef struct {
    ngx_http_request_t      *request;
    ngx_http_unzstd_conf_t  *conf;
    ngx_chain_t             *in;
    ngx_chain_t             *out;
    ngx_chain_t            **last_out;
    ngx_chain_t             *free;
    ngx_chain_t             *busy;
    ngx_buf_t               *in_buf;
    ngx_buf_t               *out_buf;
    ZSTD_DCtx               *state;
    off_t                    bytes_in;
    off_t                    bytes_out;
    ngx_uint_t               bufs;
    ngx_uint_t               operation;
    unsigned                 initialized:1;
    unsigned                 complete:1;
    unsigned                 done:1;
} ngx_http_unzstd_ctx_t;


static ngx_int_t ngx_http_unzstd_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_unzstd_body_filter(ngx_http_request_t *r,
    ngx_chain_t *in);
static ngx_int_t ngx_http_unzstd_get_buffer(ngx_http_unzstd_ctx_t *ctx);
static ngx_int_t ngx_http_unzstd_output(ngx_http_unzstd_ctx_t *ctx);
static ngx_int_t ngx_http_unzstd_result(ngx_http_unzstd_ctx_t *ctx,
    ngx_flag_t  more);
static void ngx_http_unzstd_cleanup(void *data);
static ngx_int_t ngx_http_unzstd_init(ngx_http_unzstd_ctx_t *ctx);
static ngx_int_t ngx_http_unzstd_process(ngx_http_unzstd_ctx_t *ctx);
static void ngx_http_unzstd_close(ngx_http_unzstd_ctx_t *ctx);
static ngx_int_t ngx_http_unzstd_ok(ngx_http_request_t *r);
static ngx_int_t ngx_http_unzstd_accept_encoding(ngx_str_t *ae);
static ngx_uint_t ngx_http_unzstd_quantity(u_char *p, u_char *last);
static ngx_int_t ngx_http_unzstd_cache_control(ngx_http_request_t *r);
static ngx_int_t ngx_http_unzstd_policy(ngx_http_request_t *r);
static void *ngx_http_unzstd_create_conf(ngx_conf_t *cf);
static char *ngx_http_unzstd_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_unzstd_filter_init(ngx_conf_t *cf);
static void *ngx_http_unzstd_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_unzstd_init_main_conf(ngx_conf_t *cf, void *conf);
static void ngx_http_unzstd_free_ddict(void *data);


static ngx_command_t  ngx_http_unzstd_commands[] = {

    { ngx_string("unzstd"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
#if (NGX_EXPR)
                        |NGX_HTTP_MAIN_WHEN_CONF|NGX_HTTP_SRV_WHEN_CONF
                        |NGX_HTTP_LOC_WHEN_CONF
#endif
                        |NGX_CONF_FLAG,
#if (NGX_EXPR)
      ngx_conf_set_conditional_flag_slot,
#else
      ngx_conf_set_flag_slot,
#endif
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_unzstd_conf_t, enable),
      NULL },

    { ngx_string("unzstd_force"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
#if (NGX_EXPR)
                        |NGX_HTTP_MAIN_WHEN_CONF|NGX_HTTP_SRV_WHEN_CONF
                        |NGX_HTTP_LOC_WHEN_CONF
#endif
                        |NGX_CONF_FLAG,
#if (NGX_EXPR)
      ngx_conf_set_conditional_flag_slot,
#else
      ngx_conf_set_flag_slot,
#endif
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_unzstd_conf_t, force),
      NULL },

    { ngx_string("unzstd_buffers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_bufs_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_unzstd_conf_t, bufs),
      NULL },

    { ngx_string("unzstd_dict_file"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_unzstd_main_conf_t, dict_file),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_unzstd_module_ctx = {
    NULL, /* preconfiguration */
    ngx_http_unzstd_filter_init, /* postconfiguration */

    ngx_http_unzstd_create_main_conf, /* create main configuration */
    ngx_http_unzstd_init_main_conf, /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    ngx_http_unzstd_create_conf, /* create location configuration */
    ngx_http_unzstd_merge_conf /* merge location configuration */
};


ngx_module_t  ngx_http_unzstd_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_unzstd_module_ctx, /* module context */
    ngx_http_unzstd_commands, /* module directives */
    NGX_HTTP_MODULE, /* module type */
    NULL, /* init master */
    NULL, /* init module */
    NULL, /* init process */
    NULL, /* init thread */
    NULL, /* exit thread */
    NULL, /* exit process */
    NULL, /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;
static ngx_buf_t                        ngx_http_unzstd_empty_buf;


static ngx_int_t
ngx_http_unzstd_header_filter(ngx_http_request_t *r)
{
    ngx_str_t               *value;
    ngx_flag_t               enabled, force;
    ngx_pool_cleanup_t      *cln;
    ngx_http_unzstd_ctx_t   *ctx;
    ngx_http_unzstd_conf_t  *conf;

    conf = ngx_http_get_module_loc_conf(r,
                                        ngx_http_unzstd_filter_module);

#if (NGX_EXPR)
    enabled = ngx_http_get_expr_flag_value(r, conf->enable);
#else
    enabled = conf->enable;
#endif

    if (!enabled || r->headers_out.content_encoding == NULL
        || r->headers_out.content_range != NULL
        || r->headers_out.status == NGX_HTTP_PARTIAL_CONTENT
        || ngx_http_unzstd_cache_control(r) != NGX_OK)
    {
        return ngx_http_next_header_filter(r);
    }

#if (NGX_EXPR)
    force = ngx_http_get_expr_flag_value(r, conf->force);
#else
    force = conf->force;
#endif

    value = &r->headers_out.content_encoding->value;
    if (value->len != sizeof("zstd") - 1
        || ngx_strncasecmp(value->data, (u_char *) "zstd", value->len) != 0)
    {
        return ngx_http_next_header_filter(r);
    }

    if (!force) {
        r->gzip_vary = 1;

        if (ngx_http_unzstd_ok(r) == NGX_OK
            && ngx_http_unzstd_policy(r) == NGX_OK)
        {
            return ngx_http_next_header_filter(r);
        }
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_unzstd_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    cln = ngx_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
        return NGX_ERROR;
    }

    ctx->request = r;
    ctx->conf = conf;
    ctx->last_out = &ctx->out;
    cln->handler = ngx_http_unzstd_cleanup;
    cln->data = ctx;

    ngx_http_set_ctx(r, ctx, ngx_http_unzstd_filter_module);
    r->filter_need_in_memory = 1;
    r->headers_out.content_encoding->hash = 0;
    r->headers_out.content_encoding = NULL;

    ngx_http_clear_content_length(r);
    ngx_http_clear_accept_ranges(r);
    ngx_http_weak_etag(r);

    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_unzstd_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    off_t                   before_in, before_out;
    ngx_int_t               rc;
    ngx_uint_t              blocked;
    ngx_chain_t            *cl;
    ngx_http_unzstd_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_unzstd_filter_module);

    if (ctx == NULL || ctx->done || r->header_only) {
        return ngx_http_next_body_filter(r, in);
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http unzstd filter");

    for (cl = in; cl; cl = cl->next) {
        if (ngx_buf_size(cl->buf) && !ngx_buf_in_memory(cl->buf)) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "unzstd filter received a file buffer");
            goto failed;
        }
    }

    if (ngx_chain_add_copy(r->pool, &ctx->in, in) != NGX_OK) {
        goto failed;
    }

    if (!ctx->initialized) {
        if (ngx_http_unzstd_init(ctx) != NGX_OK) {
            goto failed;
        }

        ctx->initialized = 1;
    }

    for ( ;; ) {
        blocked = 0;

        for ( ;; ) {
            if (ctx->in_buf == NULL) {
                if (ctx->in == NULL) {
                    break;
                }

                cl = ctx->in;
                ctx->in = cl->next;
                ctx->in_buf = cl->buf;
                ngx_free_chain(r->pool, cl);

                if (ctx->in_buf->last_buf
                    || (r != r->main && ctx->in_buf->last_in_chain))
                {
                    ctx->operation = NGX_HTTP_UNZSTD_FINISH;

                } else if (ctx->in_buf->flush) {
                    ctx->operation = NGX_HTTP_UNZSTD_FLUSH;

                } else {
                    ctx->operation = NGX_HTTP_UNZSTD_PROCESS;
                }

                if (ngx_buf_size(ctx->in_buf) == 0
                    && ctx->operation == NGX_HTTP_UNZSTD_PROCESS)
                {
                    ctx->in_buf = NULL;
                    continue;
                }
            }

            rc = ngx_http_unzstd_get_buffer(ctx);
            if (rc == NGX_ERROR) {
                goto failed;
            }

            if (rc == NGX_AGAIN) {
                blocked = 1;
                break;
            }

            before_in = ctx->bytes_in;
            before_out = ctx->bytes_out;
            rc = ngx_http_unzstd_process(ctx);

            if (rc == NGX_ERROR) {
                goto failed;
            }

            if (rc == NGX_OK
                && ctx->operation != NGX_HTTP_UNZSTD_PROCESS)
            {
                if (ctx->operation == NGX_HTTP_UNZSTD_FINISH) {
                    ctx->out_buf->last_buf = (r == r->main);
                    ctx->out_buf->last_in_chain = 1;
                    ctx->done = 1;
                    ngx_http_unzstd_cleanup(ctx);

                } else {
                    ctx->out_buf->flush = 1;
                }

                if (ngx_http_unzstd_output(ctx) != NGX_OK) {
                    goto failed;
                }

            } else if (ctx->out_buf->last == ctx->out_buf->end) {
                if (ngx_http_unzstd_output(ctx) != NGX_OK) {
                    goto failed;
                }
            }

            if (rc == NGX_OK) {
                ctx->in_buf = NULL;

            } else if (before_in == ctx->bytes_in
                       && before_out == ctx->bytes_out)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "unzstd decoder made no progress");
                goto failed;
            }

            if (rc == NGX_AGAIN && ngx_buf_size(ctx->in_buf) == 0) {
                ctx->in_buf = &ngx_http_unzstd_empty_buf;
            }

            if (ctx->done) {
                break;
            }
        }

        if (ctx->out_buf && ctx->out_buf->last != ctx->out_buf->pos) {
            if (ngx_http_unzstd_output(ctx) != NGX_OK) {
                goto failed;
            }
        }

        rc = NGX_OK;

        if (ctx->out || ctx->busy) {
            rc = ngx_http_next_body_filter(r, ctx->out);
            if (rc == NGX_ERROR) {
                goto failed;
            }

            ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &ctx->out,
                         (ngx_buf_tag_t) &ngx_http_unzstd_filter_module);
            ctx->last_out = &ctx->out;
        }

        if (ctx->done || !blocked) {
            return rc;
        }

        if (ctx->free == NULL) {
            return NGX_AGAIN;
        }
    }

failed:

    ctx->done = 1;
    ngx_http_unzstd_cleanup(ctx);

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_unzstd_get_buffer(ngx_http_unzstd_ctx_t *ctx)
{
    ngx_buf_t    *b;
    ngx_chain_t  *cl;

    if (ctx->out_buf) {
        return NGX_OK;
    }

    if (ctx->free) {
        cl = ctx->free;
        ctx->free = cl->next;
        b = cl->buf;
        ngx_free_chain(ctx->request->pool, cl);

    } else if (ctx->bufs < (ngx_uint_t) ctx->conf->bufs.num) {
        b = ngx_create_temp_buf(ctx->request->pool, ctx->conf->bufs.size);
        if (b == NULL) {
            return NGX_ERROR;
        }

        ctx->bufs++;

    } else {
        return NGX_AGAIN;
    }

    b->pos = b->start;
    b->last = b->start;
    b->tag = (ngx_buf_tag_t) &ngx_http_unzstd_filter_module;
    b->temporary = 1;
    b->recycled = 1;
    b->flush = 0;
    b->sync = 0;
    b->last_buf = 0;
    b->last_in_chain = 0;

    ctx->out_buf = b;

    return NGX_OK;
}


static ngx_int_t
ngx_http_unzstd_output(ngx_http_unzstd_ctx_t *ctx)
{
    ngx_chain_t  *cl;

    cl = ngx_alloc_chain_link(ctx->request->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    if (ctx->out_buf->pos == ctx->out_buf->last) {
        ctx->out_buf->temporary = 0;
        ctx->out_buf->sync = 1;
    }

    cl->buf = ctx->out_buf;
    cl->next = NULL;
    *ctx->last_out = cl;
    ctx->last_out = &cl->next;
    ctx->out_buf = NULL;

    return NGX_OK;
}


static ngx_int_t
ngx_http_unzstd_result(ngx_http_unzstd_ctx_t *ctx,
    ngx_flag_t more)
{
    if (ngx_buf_size(ctx->in_buf) || more) {
        return NGX_AGAIN;
    }

    if (ctx->operation == NGX_HTTP_UNZSTD_FINISH && !ctx->complete) {
        ngx_log_error(NGX_LOG_ERR, ctx->request->connection->log, 0,
                      "truncated zstd response");
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_http_unzstd_cleanup(void *data)
{
    ngx_http_unzstd_ctx_t  *ctx = data;

    ngx_http_unzstd_close(ctx);
    ctx->initialized = 0;
}


static ngx_int_t
ngx_http_unzstd_init(ngx_http_unzstd_ctx_t *ctx)
{
    size_t                        rc;
    ngx_http_unzstd_main_conf_t  *conf;

    ctx->state = ZSTD_createDCtx();

    if (ctx->state == NULL) {
        return NGX_ERROR;
    }

    conf = ngx_http_get_module_main_conf(ctx->request,
                                         ngx_http_unzstd_filter_module);
    if (conf->dict) {
        rc = ZSTD_DCtx_refDDict(ctx->state, conf->dict);
        if (ZSTD_isError(rc)) {
            ngx_log_error(NGX_LOG_ERR, ctx->request->connection->log, 0,
                          "ZSTD_DCtx_refDDict() failed: %s",
                          ZSTD_getErrorName(rc));
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_unzstd_process(ngx_http_unzstd_ctx_t *ctx)
{
    size_t          rc;
    ZSTD_inBuffer   in;
    ZSTD_outBuffer  out;

    if (ctx->complete && ngx_buf_size(ctx->in_buf) == 0) {
        return NGX_OK;
    }

    in.src = ctx->in_buf->pos;
    in.size = ngx_min(ngx_buf_size(ctx->in_buf), NGX_HTTP_UNZSTD_CHUNK);
    in.pos = 0;
    out.dst = ctx->out_buf->last;
    out.size = ngx_min(ctx->out_buf->end - ctx->out_buf->last,
                       NGX_HTTP_UNZSTD_CHUNK);
    out.pos = 0;

    rc = ZSTD_decompressStream(ctx->state, &out, &in);

    if (in.pos) {
        ctx->in_buf->pos += in.pos;
        ctx->bytes_in += in.pos;
    }

    ctx->out_buf->last += out.pos;
    ctx->bytes_out += out.pos;

    if (ZSTD_isError(rc)) {
        ngx_log_error(NGX_LOG_ERR, ctx->request->connection->log, 0,
                      "ZSTD_decompressStream() failed: %s",
                      ZSTD_getErrorName(rc));
        return NGX_ERROR;
    }

    ctx->complete = (rc == 0);

    return ngx_http_unzstd_result(ctx,
                                         !ctx->complete && out.pos == out.size);
}


static void
ngx_http_unzstd_close(ngx_http_unzstd_ctx_t *ctx)
{
    if (ctx->state) {
        ZSTD_freeDCtx(ctx->state);
        ctx->state = NULL;
    }
}


static ngx_int_t
ngx_http_unzstd_ok(ngx_http_request_t *r)
{
    ngx_table_elt_t  *ae;

    if (r != r->main) {
        return NGX_DECLINED;
    }

    ae = r->headers_in.accept_encoding;
    if (ae == NULL) {
        return NGX_DECLINED;
    }

    if (ae->value.len < sizeof("zstd") - 1) {
        return NGX_DECLINED;
    }

    if (ngx_memcmp(ae->value.data, "zstd,", 5) != 0
        && ngx_http_unzstd_accept_encoding(&ae->value) != NGX_OK)
    {
        return NGX_DECLINED;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_unzstd_accept_encoding(ngx_str_t *ae)
{
    u_char  *p, *start, *last;

    start = ae->data;
    last = start + ae->len;

    for ( ;; ) {
        p = ngx_strcasestrn(start, "zstd", 4 - 1);
        if (p == NULL) {
            return NGX_DECLINED;
        }

        if (p == start || (*(p - 1) == ',' || *(p - 1) == ' ')) {
            break;
        }

        start = p + 4;
    }

    p += 4;

    while (p < last) {
        switch (*p++) {
        case ',':
            return NGX_OK;
        case ';':
            goto quantity;
        case ' ':
            continue;
        default:
            return NGX_DECLINED;
        }
    }

    return NGX_OK;

quantity:

    while (p < last) {
        switch (*p++) {
        case 'q':
        case 'Q':
            goto equal;
        case ' ':
            continue;
        default:
            return NGX_DECLINED;
        }
    }

    return NGX_OK;

equal:

    if (p + 2 > last || *p++ != '=') {
        return NGX_DECLINED;
    }

    if (ngx_http_unzstd_quantity(p, last) == 0) {
        return NGX_DECLINED;
    }

    return NGX_OK;
}


static ngx_uint_t
ngx_http_unzstd_quantity(u_char *p, u_char *last)
{
    u_char      c;
    ngx_uint_t  n, q;

    c = *p++;

    if (c != '0' && c != '1') {
        return 0;
    }

    q = (c - '0') * 100;

    if (p == last) {
        return q;
    }

    c = *p++;

    if (c == ',' || c == ' ') {
        return q;
    }

    if (c != '.') {
        return 0;
    }

    n = 0;

    while (p < last) {
        c = *p++;

        if (c == ',' || c == ' ') {
            break;
        }

        if (c >= '0' && c <= '9') {
            q += c - '0';
            n++;
            continue;
        }

        return 0;
    }

    if (q > 100 || n > 3) {
        return 0;
    }

    return q;
}


static ngx_int_t
ngx_http_unzstd_cache_control(ngx_http_request_t *r)
{
    u_char           *p, *last, *start;
    ngx_uint_t        i, quoted;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h;

    part = &r->headers_out.headers.part;
    h = part->elts;

    for (i = 0; /* void */; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (h[i].hash == 0
            || h[i].key.len != sizeof("Cache-Control") - 1
            || ngx_strncasecmp(h[i].key.data, (u_char *) "Cache-Control",
                               sizeof("Cache-Control") - 1) != 0)
        {
            continue;
        }

        p = h[i].value.data;
        last = p + h[i].value.len;

        while (p < last) {
            while (p < last && (*p == ' ' || *p == '\t' || *p == ',')) {
                p++;
            }

            start = p;

            while (p < last && *p != ' ' && *p != '\t'
                   && *p != ',' && *p != '=')
            {
                p++;
            }

            if (p - start == sizeof("no-transform") - 1
                && ngx_strncasecmp(start, (u_char *) "no-transform",
                                   sizeof("no-transform") - 1) == 0)
            {
                return NGX_DECLINED;
            }

            quoted = 0;

            while (p < last) {
                if (*p == ',' && !quoted) {
                    p++;
                    break;
                }

                if (*p == '"') {
                    quoted = !quoted;

                } else if (*p == '\\' && quoted && p + 1 < last) {
                    p++;
                }

                p++;
            }
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_unzstd_policy(ngx_http_request_t *r)
{
    time_t                     date, expires;
    ngx_uint_t                 p;
    ngx_table_elt_t           *e, *d, *cc;
    ngx_http_core_loc_conf_t  *clcf;

    static ngx_str_t  no_cache = ngx_string("no-cache");
    static ngx_str_t  no_store = ngx_string("no-store");
    static ngx_str_t  private = ngx_string("private");

    if (ngx_http_unzstd_cache_control(r) != NGX_OK) {
        return NGX_DECLINED;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (r->http_version < clcf->gzip_http_version
        || (r->headers_in.msie6 && clcf->gzip_disable_msie6))
    {
        return NGX_DECLINED;
    }

#if (NGX_HTTP_DEGRADATION)
    if (clcf->gzip_disable_degradation && ngx_http_degraded(r)) {
        return NGX_DECLINED;
    }

#endif

    if (r->headers_in.via == NULL) {
        goto ok;
    }

    p = clcf->gzip_proxied;

    if (p & NGX_HTTP_GZIP_PROXIED_OFF) {
        return NGX_DECLINED;
    }

    if (p & NGX_HTTP_GZIP_PROXIED_ANY) {
        goto ok;
    }

    if (r->headers_in.authorization && (p & NGX_HTTP_GZIP_PROXIED_AUTH)) {
        goto ok;
    }

    e = r->headers_out.expires;

    if (e) {
        if (!(p & NGX_HTTP_GZIP_PROXIED_EXPIRED)) {
            return NGX_DECLINED;
        }

        expires = ngx_parse_http_time(e->value.data, e->value.len);
        if (expires == NGX_ERROR) {
            return NGX_DECLINED;
        }

        d = r->headers_out.date;

        if (d) {
            date = ngx_parse_http_time(d->value.data, d->value.len);
            if (date == NGX_ERROR) {
                return NGX_DECLINED;
            }

        } else {
            date = ngx_time();
        }

        if (expires < date) {
            goto ok;
        }

        return NGX_DECLINED;
    }

    cc = r->headers_out.cache_control;

    if (cc) {
        if ((p & NGX_HTTP_GZIP_PROXIED_NO_CACHE)
            && ngx_http_parse_multi_header_lines(r, cc, &no_cache, NULL))
        {
            goto ok;
        }

        if ((p & NGX_HTTP_GZIP_PROXIED_NO_STORE)
            && ngx_http_parse_multi_header_lines(r, cc, &no_store, NULL))
        {
            goto ok;
        }

        if ((p & NGX_HTTP_GZIP_PROXIED_PRIVATE)
            && ngx_http_parse_multi_header_lines(r, cc, &private, NULL))
        {
            goto ok;
        }

        return NGX_DECLINED;
    }

    if ((p & NGX_HTTP_GZIP_PROXIED_NO_LM) && r->headers_out.last_modified) {
        return NGX_DECLINED;
    }

    if ((p & NGX_HTTP_GZIP_PROXIED_NO_ETAG) && r->headers_out.etag) {
        return NGX_DECLINED;
    }

ok:

#if (NGX_PCRE)
    if (clcf->gzip_disable && r->headers_in.user_agent
        && ngx_regex_exec_array(clcf->gzip_disable,
                                &r->headers_in.user_agent->value,
                                r->connection->log)
           != NGX_DECLINED)
    {
        return NGX_DECLINED;
    }

#endif

    return NGX_OK;
}


static void *
ngx_http_unzstd_create_conf(ngx_conf_t *cf)
{
    ngx_http_unzstd_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_unzstd_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->bufs.num = 0;
     */

#if (NGX_EXPR)
    conf->enable = NGX_CONF_UNSET_PTR;
    conf->force = NGX_CONF_UNSET_PTR;
#else
    conf->enable = NGX_CONF_UNSET;
    conf->force = NGX_CONF_UNSET;
#endif

    return conf;
}


static char *
ngx_http_unzstd_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_unzstd_conf_t *prev = parent;
    ngx_http_unzstd_conf_t *conf = child;

#if (NGX_EXPR)
    if (ngx_conf_merge_expr_flag_value(cf, &conf->enable,
                                       prev->enable, 0) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (ngx_conf_merge_expr_flag_value(cf, &conf->force,
                                       prev->force, 0) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
#else
    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_value(conf->force, prev->force, 0);
#endif

    ngx_conf_merge_bufs_value(conf->bufs, prev->bufs,
                              (128 * 1024) / ngx_pagesize, ngx_pagesize);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_unzstd_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_unzstd_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_unzstd_body_filter;

    return NGX_OK;
}


static void *
ngx_http_unzstd_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_unzstd_main_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_unzstd_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}


static char *
ngx_http_unzstd_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_fd_t                      fd;
    size_t                        size;
    ssize_t                       n;
    u_char                       *buf;
    ngx_file_info_t               info;
    ngx_pool_cleanup_t           *cln;
    ngx_http_unzstd_main_conf_t  *umcf;

    umcf = conf;
    fd = NGX_INVALID_FILE;
    buf = NULL;

    if (umcf->dict_file.len == 0) {
        return NGX_CONF_OK;
    }

    if (ngx_conf_full_name(cf->cycle, &umcf->dict_file, 1) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    fd = ngx_open_file(umcf->dict_file.data, NGX_FILE_RDONLY,
                       NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_open_file_n " \"%V\" failed",
                           &umcf->dict_file);
        return NGX_CONF_ERROR;
    }

    if (ngx_fd_info(fd, &info) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_fd_info_n " \"%V\" failed",
                           &umcf->dict_file);
        goto failed;
    }

    size = ngx_file_size(&info);
    buf = ngx_palloc(cf->temp_pool, size);
    if (buf == NULL) {
        goto failed;
    }

    n = ngx_read_fd(fd, buf, size);
    if (n < 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_read_fd_n " \"%V\" failed",
                           &umcf->dict_file);
        goto failed;
    }

    if ((size_t) n != size) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_read_fd_n " \"%V\" incomplete",
                           &umcf->dict_file);
        goto failed;
    }

    umcf->dict = ZSTD_createDDict(buf, size);
    if (umcf->dict == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "ZSTD_createDDict() failed");
        goto failed;
    }

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        ZSTD_freeDDict(umcf->dict);
        umcf->dict = NULL;
        goto failed;
    }

    cln->handler = ngx_http_unzstd_free_ddict;
    cln->data = umcf->dict;

    if (ngx_close_file(fd) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_close_file_n " \"%V\" failed",
                           &umcf->dict_file);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;

failed:

    if (fd != NGX_INVALID_FILE && ngx_close_file(fd) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_close_file_n " \"%V\" failed",
                           &umcf->dict_file);
    }

    return NGX_CONF_ERROR;
}


static void
ngx_http_unzstd_free_ddict(void *data)
{
    (void) ZSTD_freeDDict(data);
}
