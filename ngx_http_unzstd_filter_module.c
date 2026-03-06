
/*
 * Copyright (C) Hanada
 * Copyright (C) Alex Zhang
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <zstd.h>


#define NGX_HTTP_UNZSTD_IN_BUF_NO_FLUSH        0
#define NGX_HTTP_UNZSTD_IN_BUF_SYNC_FLUSH      1
#define NGX_HTTP_UNZSTD_IN_BUF_FINISH          2


typedef struct {
    ngx_str_t                    dict_file;
    ZSTD_DDict                  *dict;
} ngx_http_unzstd_main_conf_t;


typedef struct {
    ngx_flag_t                   enable;
    ngx_array_t                 *force;
    ngx_bufs_t                   bufs;
} ngx_http_unzstd_conf_t;


typedef struct {
    ngx_chain_t                 *in;
    ngx_chain_t                 *free;
    ngx_chain_t                 *busy;
    ngx_chain_t                 *out;
    ngx_chain_t                **last_out;

    ngx_buf_t                   *in_buf;
    ngx_buf_t                   *out_buf;
    ngx_int_t                    bufs;

    ZSTD_inBuffer                buffer_in;
    ZSTD_outBuffer               buffer_out;
    ZSTD_DStream                *dstream;

    unsigned                     started:1;
    unsigned                     flush:2;
    unsigned                     redo:1;
    unsigned                     done:1;
    unsigned                     nomem:1;

    ngx_http_request_t          *request;
} ngx_http_unzstd_ctx_t;


static ngx_int_t ngx_http_unzstd_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_unzstd_body_filter(ngx_http_request_t *r,
    ngx_chain_t *in);

static ngx_int_t ngx_http_unzstd_filter_inflate_start(ngx_http_request_t *r,
    ngx_http_unzstd_ctx_t *ctx);
static ngx_int_t ngx_http_unzstd_filter_add_data(ngx_http_request_t *r,
    ngx_http_unzstd_ctx_t *ctx);
static ngx_int_t ngx_http_unzstd_filter_get_buf(ngx_http_request_t *r,
    ngx_http_unzstd_ctx_t *ctx);
static ngx_int_t ngx_http_unzstd_filter_inflate(ngx_http_request_t *r,
    ngx_http_unzstd_ctx_t *ctx);
static ngx_int_t ngx_http_unzstd_filter_inflate_end(ngx_http_request_t *r,
    ngx_http_unzstd_ctx_t *ctx);

static ngx_int_t ngx_http_zstd_ok(ngx_http_request_t *r);
static ngx_int_t ngx_http_zstd_accept_encoding(ngx_str_t *ae);
static ngx_uint_t ngx_http_zstd_quantity(u_char *p, u_char *last);

static ngx_int_t ngx_http_unzstd_filter_init(ngx_conf_t *cf);
static void *ngx_http_unzstd_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_unzstd_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_http_unzstd_create_conf(ngx_conf_t *cf);
static char *ngx_http_unzstd_merge_conf(ngx_conf_t *cf,
    void *parent, void *child);
static void ngx_http_unzstd_free_ddict(void *data);


static ngx_command_t  ngx_http_unzstd_filter_commands[] = {

    { ngx_string("unzstd"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_unzstd_conf_t, enable),
      NULL },

    { ngx_string("unzstd_force"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_set_predicate_slot,
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


static ngx_http_module_t  ngx_http_unzstd_filter_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_http_unzstd_filter_init,            /* postconfiguration */

    ngx_http_unzstd_create_main_conf,       /* create main configuration */
    ngx_http_unzstd_init_main_conf,         /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    ngx_http_unzstd_create_conf,            /* create location configuration */
    ngx_http_unzstd_merge_conf              /* merge location configuration */
};


ngx_module_t  ngx_http_unzstd_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_unzstd_filter_module_ctx,     /* module context */
    ngx_http_unzstd_filter_commands,        /* module directives */
    NGX_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


static ngx_int_t
ngx_http_unzstd_header_filter(ngx_http_request_t *r)
{
    ngx_http_unzstd_ctx_t   *ctx;
    ngx_http_unzstd_conf_t  *conf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_unzstd_filter_module);

    /* TODO support multiple content-codings */
    /* TODO ignore content encoding? */

    if (!conf->enable
        || r->headers_out.content_encoding == NULL
        || r->headers_out.content_encoding->value.len != 4
        || ngx_strncasecmp(r->headers_out.content_encoding->value.data,
                           (u_char *) "zstd", 4) != 0)
    {
        return ngx_http_next_header_filter(r);
    }

    switch (ngx_http_test_predicates(r, conf->force)) {

    case NGX_ERROR:
        return NGX_ERROR;

    case NGX_OK:
        r->gzip_vary = 1;

        if (ngx_http_zstd_ok(r) == NGX_OK) {
            return ngx_http_next_header_filter(r);
        }
        break;

    default: /* NGX_DECLINED */
        break;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_unzstd_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_unzstd_filter_module);

    ctx->request = r;

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
    size_t                  free_rc;
    ngx_int_t               rc;
    ngx_uint_t              flush;
    ngx_chain_t            *cl;
    ngx_http_unzstd_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_unzstd_filter_module);

    if (ctx == NULL || ctx->done) {
        return ngx_http_next_body_filter(r, in);
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http unzstd filter");

    if (!ctx->started) {
        if (ngx_http_unzstd_filter_inflate_start(r, ctx) != NGX_OK) {
            goto failed;
        }
    }

    if (in) {
        if (ngx_chain_add_copy(r->pool, &ctx->in, in) != NGX_OK) {
            goto failed;
        }
    }

    if (ctx->nomem) {

        /* flush busy buffers */

        if (ngx_http_next_body_filter(r, NULL) == NGX_ERROR) {
            goto failed;
        }

        cl = NULL;

        ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &cl,
                                (ngx_buf_tag_t) &ngx_http_unzstd_filter_module);
        ctx->nomem = 0;
        flush = 0;

    } else {
        flush = ctx->busy ? 1 : 0;
    }

    for ( ;; ) {

        /* cycle while we can write to a client */

        for ( ;; ) {

            rc = ngx_http_unzstd_filter_add_data(r, ctx);

            if (rc == NGX_DECLINED) {
                break;
            }

            if (rc == NGX_AGAIN) {
                continue;
            }

            rc = ngx_http_unzstd_filter_get_buf(r, ctx);

            if (rc == NGX_DECLINED) {
                break;
            }

            if (rc == NGX_ERROR) {
                goto failed;
            }

            rc = ngx_http_unzstd_filter_inflate(r, ctx);

            if (rc == NGX_OK) {
                break;
            }

            if (rc == NGX_ERROR) {
                goto failed;
            }

            /* rc == NGX_AGAIN */
        }

        if (ctx->out == NULL && !flush) {
            return ctx->busy ? NGX_AGAIN : NGX_OK;
        }

        rc = ngx_http_next_body_filter(r, ctx->out);

        if (rc == NGX_ERROR) {
            goto failed;
        }

        ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &ctx->out,
                                (ngx_buf_tag_t) &ngx_http_unzstd_filter_module);
        ctx->last_out = &ctx->out;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "unzstd out: %p", ctx->out);

        ctx->nomem = 0;
        flush = 0;

        if (ctx->done) {
            return rc;
        }
    }

    /* unreachable */

failed:

    ctx->done = 1;

    if (ctx->dstream != NULL) {
        free_rc = ZSTD_freeDStream(ctx->dstream);
        ctx->dstream = NULL;

        if (ZSTD_isError(free_rc)) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "ZSTD_freeDStream() failed: %s",
                          ZSTD_getErrorName(free_rc));
        }
    }

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_zstd_ok(ngx_http_request_t *r)
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

    if (ngx_memcmp(ae->value.data, "zstd", 4) != 0
        && ngx_http_zstd_accept_encoding(&ae->value) != NGX_OK)
    {
        return NGX_DECLINED;
    }

    r->gzip_tested = 1;
    r->gzip_ok = 0;

    return NGX_OK;
}


/*
 * a copy of ngx_http_gzip_accept_encoding, for zstd content encoding
 */

static ngx_int_t
ngx_http_zstd_accept_encoding(ngx_str_t *ae)
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

    if (ngx_http_zstd_quantity(p, last) == 0) {
        return NGX_DECLINED;
    }

    return NGX_OK;
}


/*
 * a copy of ngx_http_gzip_quantity
 */

static ngx_uint_t
ngx_http_zstd_quantity(u_char *p, u_char *last)
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
ngx_http_unzstd_filter_inflate_start(ngx_http_request_t *r,
    ngx_http_unzstd_ctx_t *ctx)
{
    size_t                        rc;
    ngx_http_unzstd_main_conf_t  *umcf;

    umcf = ngx_http_get_module_main_conf(r, ngx_http_unzstd_filter_module);

    ctx->dstream = ZSTD_createDStream();
    if (ctx->dstream == NULL) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "ZSTD_createDStream() failed");
        return NGX_ERROR;
    }

    rc = ZSTD_initDStream(ctx->dstream);
    if (ZSTD_isError(rc)) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "ZSTD_initDStream() failed: %s",
                      ZSTD_getErrorName(rc));
        goto failed;
    }

    if (umcf->dict != NULL) {
        rc = ZSTD_DCtx_refDDict(ctx->dstream, umcf->dict);
        if (ZSTD_isError(rc)) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "ZSTD_DCtx_refDDict() failed: %s",
                          ZSTD_getErrorName(rc));
            goto failed;
        }
    }

    ctx->started = 1;
    ctx->last_out = &ctx->out;
    ctx->flush = NGX_HTTP_UNZSTD_IN_BUF_NO_FLUSH;

    return NGX_OK;

failed:

    rc = ZSTD_freeDStream(ctx->dstream);
    ctx->dstream = NULL;

    if (ZSTD_isError(rc)) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "ZSTD_freeDStream() failed: %s",
                      ZSTD_getErrorName(rc));
    }

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_unzstd_filter_add_data(ngx_http_request_t *r,
    ngx_http_unzstd_ctx_t *ctx)
{
    if (ctx->buffer_in.pos < ctx->buffer_in.size
        || ctx->flush != NGX_HTTP_UNZSTD_IN_BUF_NO_FLUSH
        || ctx->redo)
    {
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "unzstd in: %p", ctx->in);

    if (ctx->in == NULL) {
        return NGX_DECLINED;
    }

    ctx->in_buf = ctx->in->buf;
    ctx->in = ctx->in->next;

    ctx->buffer_in.src = ctx->in_buf->pos;
    ctx->buffer_in.pos = 0;
    ctx->buffer_in.size = ngx_buf_size(ctx->in_buf);

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "unzstd in_buf:%p src:%p size:%uz",
                   ctx->in_buf, ctx->buffer_in.src, ctx->buffer_in.size);

    if (ctx->in_buf->last_buf) {
        ctx->flush = NGX_HTTP_UNZSTD_IN_BUF_FINISH;

    } else if (ctx->in_buf->flush || ctx->in_buf->last_in_chain) {
        ctx->flush = NGX_HTTP_UNZSTD_IN_BUF_SYNC_FLUSH;

    } else if (ctx->buffer_in.size == 0) {
        return NGX_AGAIN;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_unzstd_filter_get_buf(ngx_http_request_t *r,
    ngx_http_unzstd_ctx_t *ctx)
{
    ngx_chain_t            *cl;
    ngx_http_unzstd_conf_t *conf;

    if (ctx->buffer_out.pos < ctx->buffer_out.size) {
        return NGX_OK;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_unzstd_filter_module);

    if (ctx->free) {
        cl = ctx->free;
        ctx->out_buf = cl->buf;
        ctx->free = cl->next;

        ngx_free_chain(r->pool, cl);

        ctx->out_buf->flush = 0;

    } else if (ctx->bufs < conf->bufs.num) {

        ctx->out_buf = ngx_create_temp_buf(r->pool, conf->bufs.size);
        if (ctx->out_buf == NULL) {
            return NGX_ERROR;
        }

        ctx->out_buf->tag = (ngx_buf_tag_t) &ngx_http_unzstd_filter_module;
        ctx->out_buf->recycled = 1;
        ctx->bufs++;

    } else {
        ctx->nomem = 1;
        return NGX_DECLINED;
    }

    ctx->buffer_out.dst = ctx->out_buf->pos;
    ctx->buffer_out.pos = 0;
    ctx->buffer_out.size = ctx->out_buf->end - ctx->out_buf->pos;

    return NGX_OK;
}


static ngx_int_t
ngx_http_unzstd_filter_inflate(ngx_http_request_t *r,
    ngx_http_unzstd_ctx_t *ctx)
{
    size_t        rc;
    ngx_uint_t    more;
    ngx_buf_t    *b;
    ngx_chain_t  *cl;

    ngx_log_debug6(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ZSTD_decompressStream() in: src:%p dst:%p ip:%uz op:%uz "
                   "flush:%d redo:%d",
                   ctx->buffer_in.src, ctx->buffer_out.dst,
                   ctx->buffer_in.pos, ctx->buffer_out.pos,
                   ctx->flush, ctx->redo);

    rc = ZSTD_decompressStream(ctx->dstream, &ctx->buffer_out, &ctx->buffer_in);

    if (ZSTD_isError(rc)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ZSTD_decompressStream() failed: %s",
                      ZSTD_getErrorName(rc));
        return NGX_ERROR;
    }

    ngx_log_debug5(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ZSTD_decompressStream() out: ip:%uz is:%uz op:%uz os:%uz "
                   "rc:%uz",
                   ctx->buffer_in.pos, ctx->buffer_in.size,
                   ctx->buffer_out.pos, ctx->buffer_out.size, rc);

    more = ctx->buffer_in.pos < ctx->buffer_in.size;

    ctx->in_buf->pos += ctx->buffer_in.pos;
    ctx->out_buf->last = ctx->out_buf->pos + ctx->buffer_out.pos;

    if (!more) {
        ngx_memzero(&ctx->buffer_in, sizeof(ZSTD_inBuffer));
    }

    if (ctx->buffer_out.pos == ctx->buffer_out.size) {

        /* zstd wants to output some more data */

        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        cl->buf = ctx->out_buf;
        cl->next = NULL;
        *ctx->last_out = cl;
        ctx->last_out = &cl->next;

        ctx->redo = 1;

        return NGX_AGAIN;
    }

    ctx->redo = 0;

    if (ctx->flush == NGX_HTTP_UNZSTD_IN_BUF_SYNC_FLUSH) {

        ctx->flush = NGX_HTTP_UNZSTD_IN_BUF_NO_FLUSH;

        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        b = ctx->out_buf;

        if (ngx_buf_size(b) == 0) {

            b = ngx_calloc_buf(ctx->request->pool);
            if (b == NULL) {
                return NGX_ERROR;
            }

        } else {
            ctx->buffer_out.pos = ctx->buffer_out.size;
        }

        b->flush = 1;

        cl->buf = b;
        cl->next = NULL;
        *ctx->last_out = cl;
        ctx->last_out = &cl->next;

        return NGX_OK;
    }

    if (ctx->flush == NGX_HTTP_UNZSTD_IN_BUF_FINISH
        && ctx->buffer_in.pos == ctx->buffer_in.size)
    {
        if (ngx_http_unzstd_filter_inflate_end(r, ctx) != NGX_OK) {
            return NGX_ERROR;
        }

        return NGX_OK;
    }

    if (rc == 0 && more) {
        return NGX_AGAIN;
    }

    if (ctx->in == NULL) {

        b = ctx->out_buf;

        if (ngx_buf_size(b) == 0) {
            return NGX_OK;
        }

        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        ctx->buffer_out.pos = ctx->buffer_out.size;

        cl->buf = b;
        cl->next = NULL;
        *ctx->last_out = cl;
        ctx->last_out = &cl->next;

        return NGX_OK;
    }

    return NGX_AGAIN;
}


static ngx_int_t
ngx_http_unzstd_filter_inflate_end(ngx_http_request_t *r,
    ngx_http_unzstd_ctx_t *ctx)
{
    size_t        rc;
    ngx_buf_t    *b;
    ngx_chain_t  *cl;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "unzstd inflate end");

    rc = ZSTD_freeDStream(ctx->dstream);
    ctx->dstream = NULL;

    if (ZSTD_isError(rc)) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "ZSTD_freeDStream() failed: %s",
                      ZSTD_getErrorName(rc));
        return NGX_ERROR;
    }

    b = ctx->out_buf;

    if (ngx_buf_size(b) == 0) {

        b = ngx_calloc_buf(ctx->request->pool);
        if (b == NULL) {
            return NGX_ERROR;
        }
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = b;
    cl->next = NULL;
    *ctx->last_out = cl;
    ctx->last_out = &cl->next;

    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;
    b->sync = 1;

    ctx->done = 1;

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

    fd = ngx_open_file(umcf->dict_file.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
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
    buf = ngx_palloc(cf->pool, size);
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

    conf->enable = NGX_CONF_UNSET;
    conf->force  = NGX_CONF_UNSET_PTR;

    return conf;
}


static char *
ngx_http_unzstd_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_unzstd_conf_t *prev = parent;
    ngx_http_unzstd_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_ptr_value(conf->force, prev->force, NULL);

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


static void
ngx_http_unzstd_free_ddict(void *data)
{
    (void) ZSTD_freeDDict(data);
}
