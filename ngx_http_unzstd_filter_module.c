
/*
 * Copyright (C) Hanada
 * Copyright (C) Alex Zhang
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <zstd.h>


#define NGX_HTTP_UNZSTD_FILTER_DECOMPRESS     0
#define NGX_HTTP_UNZSTD_FILTER_FLUSH          1
#define NGX_HTTP_UNZSTD_FILTER_END            2


typedef struct {
    ngx_str_t            dict_file;
} ngx_http_unzstd_main_conf_t;


typedef struct {
    ngx_flag_t           enable;
    ngx_array_t         *force;

    ngx_bufs_t           bufs;

    ZSTD_DDict          *dict;
} ngx_http_unzstd_loc_conf_t;


typedef struct {
    ngx_chain_t         *in;
    ngx_chain_t         *free;
    ngx_chain_t         *busy;
    ngx_chain_t         *out;
    ngx_chain_t        **last_out;

    ngx_buf_t           *in_buf;
    ngx_buf_t           *out_buf;
    ngx_int_t            bufs;

    ZSTD_inBuffer        buffer_in;
    ZSTD_outBuffer       buffer_out;

    ZSTD_DStream        *dstream;

    ngx_http_request_t  *request;

    size_t               bytes_in;
    size_t               bytes_out;

    unsigned             action:2;
    unsigned             last:1;
    unsigned             redo:1;
    unsigned             flush:1;
    unsigned             done:1;
    unsigned             nomem:1;
} ngx_http_unzstd_ctx_t;


static ngx_int_t ngx_http_unzstd_check_request(ngx_http_request_t *r);
static ZSTD_DStream *ngx_http_unzstd_filter_create_dstream(
    ngx_http_request_t *r, ngx_http_unzstd_ctx_t *ctx);
static ngx_int_t ngx_http_unzstd_filter_add_data(ngx_http_request_t *r,
    ngx_http_unzstd_ctx_t *ctx);
static ngx_int_t ngx_http_unzstd_filter_get_buf(ngx_http_request_t *r,
    ngx_http_unzstd_ctx_t *ctx);
static ngx_int_t ngx_http_unzstd_filter_decompress(ngx_http_request_t *r,
    ngx_http_unzstd_ctx_t *ctx);

static void *ngx_http_unzstd_filter_alloc(void *opaque, size_t size);
static void ngx_http_unzstd_filter_free(void *opaque, void *address);

static ngx_int_t ngx_http_unzstd_filter_init(ngx_conf_t *cf);
static void *ngx_http_unzstd_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_unzstd_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_http_unzstd_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_unzstd_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);


static ngx_command_t  ngx_http_unzstd_filter_commands[] = {

    { ngx_string("unzstd"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_unzstd_loc_conf_t, enable),
      NULL },

    { ngx_string("unzstd_force"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_set_predicate_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_unzstd_loc_conf_t, force),
      NULL },

    { ngx_string("unzstd_buffers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_bufs_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_unzstd_loc_conf_t, bufs),
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
    NULL,                                  /* preconfiguration */
    ngx_http_unzstd_filter_init,           /* postconfiguration */

    ngx_http_unzstd_create_main_conf,      /* create main configuration */
    ngx_http_unzstd_init_main_conf,        /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_unzstd_create_loc_conf,       /* create location configuration */
    ngx_http_unzstd_merge_loc_conf         /* merge location configuration */
};


ngx_module_t  ngx_http_unzstd_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_unzstd_filter_module_ctx,    /* module context */
    ngx_http_unzstd_filter_commands,       /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


static ngx_int_t
ngx_http_unzstd_header_filter(ngx_http_request_t *r)
{
    ngx_http_unzstd_ctx_t       *ctx;
    ngx_http_unzstd_loc_conf_t  *uzlcf;

    uzlcf = ngx_http_get_module_loc_conf(r, ngx_http_unzstd_filter_module);

    /* TODO support multiple content-codings */
    /* TODO ignore content encoding? */

    if (!uzlcf->enable
        || r->headers_out.content_encoding == NULL
        || r->headers_out.content_encoding->value.len != 4
        || ngx_strncasecmp(r->headers_out.content_encoding->value.data,
                           (u_char *) "zstd", 4) != 0)
    {
        return ngx_http_next_header_filter(r);
    }

    switch (ngx_http_test_predicates(r, uzlcf->force)) {

    case NGX_ERROR:
        return NGX_ERROR;

    case NGX_OK:
        r->gzip_vary = 1;

        if (ngx_http_unzstd_check_request(r) == NGX_OK) {
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
    size_t                  rv;
    ngx_int_t               flush, rc;
    ngx_chain_t            *cl;
    ngx_http_unzstd_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_unzstd_filter_module);

    if (ctx == NULL || ctx->done) {
        return ngx_http_next_body_filter(r, in);
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http unzstd filter");

    if (ctx->dstream == NULL) {
        ctx->dstream = ngx_http_unzstd_filter_create_dstream(r, ctx);
        if (ctx->dstream == NULL) {
            goto failed;
        }
    }

#if 0
    ctx->last_out = &ctx->out;
    ctx->flush = IN_BUF_NO_FLUSH;
#endif

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

            /* cycle while there is data to feed zlib and ... */

            rc = ngx_http_unzstd_filter_add_data(r, ctx);

            if (rc == NGX_DECLINED) {
                break;
            }

            if (rc == NGX_AGAIN) {
                continue;
            }


            /* ... there are buffers to write zlib output */

            rc = ngx_http_unzstd_filter_get_buf(r, ctx);

            if (rc == NGX_DECLINED) {
                break;
            }

            if (rc == NGX_ERROR) {
                goto failed;
            }

            rc = ngx_http_unzstd_filter_decompress(r, ctx);

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
            rv = ZSTD_freeDStream(ctx->dstream);
            if (ZSTD_isError(rv)) {
                ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                              "ZSTD_freeDStream() failed: %s",
                              ZSTD_getErrorName(rc));

                rc = NGX_ERROR;
            }

            return rc;
        }
    }

    /* unreachable */

failed:

    ctx->done = 1;
    rv = ZSTD_freeDStream(ctx->dstream);
    if (ZSTD_isError(rv)) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "ZSTD_freeDStream() failed: %s", ZSTD_getErrorName(rc));
    }

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_unzstd_check_accept_encoding(ngx_http_request_t* r)
{
    ngx_table_elt_t *accept_encoding_entry;
    ngx_str_t       *accept_encoding;
    u_char          *cursor;
    u_char          *end;
    u_char           before;
    u_char           after;

    accept_encoding_entry = r->headers_in.accept_encoding;
    if (accept_encoding_entry == NULL) {
        return NGX_DECLINED;
    }

    accept_encoding = &accept_encoding_entry->value;
    cursor = accept_encoding->data;
    end = cursor + accept_encoding->len;

    static const char keyword_encoding[] = "zstd";
    static const size_t keyword_encoding_len = 4;

    while (1) {
        u_char digit;
        /* It would be an idiotic idea to rely on compiler to produce performant
             binary, that is why we just do -1 at every call site. */
        cursor = ngx_strcasestrn(cursor, (char *)keyword_encoding, keyword_encoding_len - 1);

        if (cursor == NULL) {
            return NGX_DECLINED;
        }

        before = (cursor == accept_encoding->data) ? ' ' : cursor[-1];
        cursor += keyword_encoding_len;
        after = (cursor >= end) ? ' ' : *cursor;

        if (before != ',' && before != ' ') {
            continue;
        }

        if (after != ',' && after != ' ' && after != ';') {
            continue;
        }

        /* Check for ";q=0[.[0[0[0]]]]" */
        while (*cursor == ' ') {
            cursor++;
        }

        if (*(cursor++) != ';') {
            break;
        }

        while (*cursor == ' ') {
            cursor++;
        }

        if (*(cursor++) != 'q') {
            break;
        }

        while (*cursor == ' ') {
            cursor++;
        }

        if (*(cursor++) != '=') {
            break;
        }

        while (*cursor == ' ') {
            cursor++;
        }

        if (*(cursor++) != '0') {
            break;
        }

        if (*(cursor++) != '.') { /* ;q=0, */
            return NGX_DECLINED;
        }

        digit = *(cursor++);
        if (digit < '0' || digit > '9') { /* ;q=0., */
            return NGX_DECLINED;
        }

        if (digit > '0') {
            break;
        }

        digit = *(cursor++);
        if (digit < '0' || digit > '9') { /* ;q=0.0, */
            return NGX_DECLINED;
        }

        if (digit > '0') {
            break;
        }

        digit = *(cursor++);
        if (digit < '0' || digit > '9') { /* ;q=0.00, */
            return NGX_DECLINED;
        }

        if (digit > '0') {
            break;
        }

        return NGX_DECLINED; /* ;q=0.000 */
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_unzstd_check_request(ngx_http_request_t* r)
{
    if (r != r->main) {
        return NGX_DECLINED;
    }

    if (ngx_http_unzstd_check_accept_encoding(r) != NGX_OK) {
        return NGX_DECLINED;
    }

    return NGX_OK;
}


static ZSTD_DStream *
ngx_http_unzstd_filter_create_dstream(ngx_http_request_t *r,
    ngx_http_unzstd_ctx_t *ctx)
{
    size_t                        rc;
    ZSTD_DStream                 *dstream;
    ZSTD_customMem                cmem;
    ngx_http_unzstd_loc_conf_t   *uzlcf;

    uzlcf = ngx_http_get_module_loc_conf(r, ngx_http_unzstd_filter_module);

    cmem.customAlloc = ngx_http_unzstd_filter_alloc;
    cmem.customFree = ngx_http_unzstd_filter_free;
    cmem.opaque = ctx;

    dstream = ZSTD_createDStream_advanced(cmem);
    if (dstream == NULL) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "ZSTD_createDStream_advanced() failed");
        return NGX_ERROR;
    }

    /* TODO: use the advanced initialize functions */

    if (uzlcf->dict) {
#if ZSTD_VERSION_NUMBER >= 10500
        rc = ZSTD_DCtx_reset(dstream, ZSTD_reset_session_only);
        if (ZSTD_isError(rc)) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "ZSTD_DCtx_reset() failed: %s",
                          ZSTD_getErrorName(rc));
            goto failed;
        }

        rc = ZSTD_DCtx_refDDict(dstream, uzlcf->dict);
        if (ZSTD_isError(rc)) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "ZSTD_DCtx_refDDict() failed: %s",
                          ZSTD_getErrorName(rc));
            goto failed;
        }
#else
        rc = ZSTD_initDStream_usingDDict(dstream, uzlcf->dict);
#endif
        if (ZSTD_isError(rc)) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "ZSTD_initDStream_usingDDict() failed: %s",
                          ZSTD_getErrorName(rc));

            goto failed;
        }

    } else {
        rc = ZSTD_initDStream(dstream);
        if (ZSTD_isError(rc)) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                        "ZSTD_initDStream() failed: %s",
                        ZSTD_getErrorName(rc));

            goto failed;
        }
    }

    return dstream;

failed:
    rc = ZSTD_freeDStream(dstream);
    if (ZSTD_isError(rc)) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "ZSTD_freeDStream() failed: %s", ZSTD_getErrorName(rc));
    }

    return NULL;
}


static ngx_int_t
ngx_http_unzstd_filter_add_data(ngx_http_request_t *r,
    ngx_http_unzstd_ctx_t *ctx)
{
    if (ctx->buffer_in.pos < ctx->buffer_in.size
        || ctx->flush
        || ctx->last
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

    if (ctx->in_buf->flush) {
        ctx->flush = 1;

    } else if (ctx->in_buf->last_buf) {
        ctx->last = 1;
    }

    ctx->buffer_in.src = ctx->in_buf->pos;
    ctx->buffer_in.pos = 0;
    ctx->buffer_in.size = ngx_buf_size(ctx->in_buf);

    ctx->bytes_in += ngx_buf_size(ctx->in_buf);

    if (ctx->buffer_in.size == 0) {
        return NGX_AGAIN;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_unzstd_filter_get_buf(ngx_http_request_t *r,
    ngx_http_unzstd_ctx_t *ctx)
{
    ngx_chain_t                 *cl;
    ngx_http_unzstd_loc_conf_t  *uzlcf;

    if (ctx->buffer_out.pos < ctx->buffer_out.size) {
        return NGX_OK;
    }

    uzlcf = ngx_http_get_module_loc_conf(r, ngx_http_unzstd_filter_module);

    if (ctx->free) {
        cl = ctx->free;
        ctx->free = ctx->free->next;
        ctx->out_buf = cl->buf;
        ngx_free_chain(r->pool, cl);

    } else if (ctx->bufs < uzlcf->bufs.num) {
        ctx->out_buf = ngx_create_temp_buf(r->pool, uzlcf->bufs.size);
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
    ctx->buffer_out.size = ctx->out_buf->end - ctx->out_buf->start;

    return NGX_OK;
}


static ngx_int_t
ngx_http_unzstd_filter_decompress(ngx_http_request_t *r,
    ngx_http_unzstd_ctx_t *ctx)
{
    size_t        rc, pos_in, pos_out;
    char         *hint;
    ngx_chain_t  *cl;
    ngx_buf_t    *b;

    ngx_log_debug8(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "zstd decompress in: src:%p pos:%ud size: %ud, "
                   "dst:%p pos:%ud size:%ud flush:%d redo:%d",
                   ctx->buffer_in.src, ctx->buffer_in.pos, ctx->buffer_in.size,
                   ctx->buffer_out.dst, ctx->buffer_out.pos,
                   ctx->buffer_out.size, ctx->flush, ctx->redo);

    pos_in = ctx->buffer_in.pos;
    pos_out = ctx->buffer_out.pos;

    switch (ctx->action) {

    case NGX_HTTP_UNZSTD_FILTER_FLUSH:
        hint = "ZSTD_flushStream() ";
        rc = ZSTD_flushStream(ctx->dstream, &ctx->buffer_out);
        break;

    case NGX_HTTP_UNZSTD_FILTER_END:
        hint = "ZSTD_endStream() ";
        rc = ZSTD_endStream(ctx->dstream, &ctx->buffer_out);
        break;

    default: /* NGX_HTTP_UNZSTD_FILTER_DECOMPRESS */
        hint = "ZSTD_compressStream() ";
        rc = ZSTD_decompressStream(ctx->dstream, &ctx->buffer_out,
                                 &ctx->buffer_in);
        break;
    }

    if (ZSTD_isError(rc)) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "%s failed: %s", hint, ZSTD_getErrorName(rc));

        return NGX_ERROR;
    }

    ngx_log_debug6(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "zstd decompress out: src:%p pos:%ud size: %ud, "
                   "dst:%p pos:%ud size:%ud",
                   ctx->buffer_in.src, ctx->buffer_in.pos, ctx->buffer_in.size,
                   ctx->buffer_out.dst, ctx->buffer_out.pos,
                   ctx->buffer_out.size);

    ctx->in_buf->pos += ctx->buffer_in.pos - pos_in;
    ctx->out_buf->last += ctx->buffer_out.pos - pos_out;
    ctx->redo = 0;

    if (rc > 0) {
        if (ctx->action == NGX_HTTP_UNZSTD_FILTER_DECOMPRESS) {
            ctx->action = NGX_HTTP_UNZSTD_FILTER_FLUSH;
        }

        ctx->redo = 1;

    } else if (ctx->last && ctx->action != NGX_HTTP_UNZSTD_FILTER_END) {
        ctx->redo = 1;
        ctx->action = NGX_HTTP_UNZSTD_FILTER_END;

        /* pending to call the ZSTD_endStream() */

        return NGX_AGAIN;

    } else {
        ctx->action = NGX_HTTP_UNZSTD_FILTER_DECOMPRESS; /* restore */
    }

    if (ngx_buf_size(ctx->out_buf) == 0) {
        return NGX_AGAIN;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    b = ctx->out_buf;

    if (rc == 0 && (ctx->flush || ctx->last)) {
        b->flush = ctx->flush;
        b->last_buf = ctx->last;

        ctx->done = ctx->last;
        ctx->flush = 0;
    }

    ctx->bytes_out += ngx_buf_size(b);

    cl->next = NULL;
    cl->buf = b;

    *ctx->last_out = cl;
    ctx->last_out = &cl->next;

    ngx_memzero(&ctx->buffer_out, sizeof(ZSTD_outBuffer));

    return ctx->last && rc == 0 ? NGX_OK : NGX_AGAIN;
}


static void *
ngx_http_unzstd_filter_alloc(void *opaque, size_t size)
{
    ngx_http_unzstd_ctx_t *ctx = opaque;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->request->connection->log, 0,
                   "unzstd alloc: size:%zu",
                   size);

    return ngx_palloc(ctx->request->pool, size);
}


static void
ngx_http_unzstd_filter_free(void *opaque, void *address)
{
#if 0
    ngx_http_unzstd_ctx_t *ctx = opaque;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->request->connection->log, 0,
                   "unzstd free: %p", address);
#endif
}


static void *
ngx_http_unzstd_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_unzstd_main_conf_t  *uzmcf;

    uzmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_unzstd_main_conf_t));
    if (uzmcf == NULL) {
        return NULL;
    }

    return uzmcf;
}


static char *
ngx_http_unzstd_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_unzstd_main_conf_t *uzmcf = conf;

    if (uzmcf->dict_file.len == 0) {
        return NGX_CONF_OK;
    }

    if (ngx_conf_full_name(cf->cycle, &uzmcf->dict_file, 1) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static void *
ngx_http_unzstd_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_unzstd_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_unzstd_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->bufs.num = 0;
     *     conf->dict = NULL;
     */

    conf->enable = NGX_CONF_UNSET;
    conf->force  = NGX_CONF_UNSET_PTR;

    return conf;
}


static char *
ngx_http_unzstd_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_unzstd_loc_conf_t *prev = parent;
    ngx_http_unzstd_loc_conf_t *conf = child;

    ngx_fd_t                      fd;
    size_t                        size;
    ssize_t                       n;
    char                         *rc;
    u_char                       *buf;
    ngx_file_info_t               info;
    ngx_http_unzstd_main_conf_t  *uzmcf;

    rc = NGX_OK;
    buf = NULL;
    fd = NGX_INVALID_FILE;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_ptr_value(conf->force, prev->force, NULL);

    ngx_conf_merge_bufs_value(conf->bufs, prev->bufs,
                              (128 * 1024) / ngx_pagesize, ngx_pagesize);

    uzmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_unzstd_filter_module);

    if (conf->enable && uzmcf->dict_file.len > 0) {
        fd = ngx_open_file(uzmcf->dict_file.data, NGX_FILE_RDONLY,
                            NGX_FILE_OPEN, 0);

        if (fd == NGX_INVALID_FILE) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                                ngx_open_file_n " \"%V\" failed",
                                &uzmcf->dict_file);

            return NGX_CONF_ERROR;
        }

        if (ngx_fd_info(fd, &info) == NGX_FILE_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                                ngx_fd_info_n " \"%V\" failed",
                                &uzmcf->dict_file);

            rc = NGX_CONF_ERROR;
            goto close;
        }

        size = ngx_file_size(&info);
        buf = ngx_palloc(cf->pool, size);
        if (buf == NULL) {
            rc = NGX_CONF_ERROR;
            goto close;
        }

        n = ngx_read_fd(fd, (void *) buf, size);
        if (n < 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                                ngx_read_fd_n " %V\" failed",
                                &uzmcf->dict_file);

            rc = NGX_CONF_ERROR;
            goto close;

        } else if ((size_t) n != size) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                                ngx_read_fd_n "\"%V incomplete\"",
                                &uzmcf->dict_file);

            rc = NGX_CONF_ERROR;
            goto close;
        }

        conf->dict = ZSTD_createDDict_byReference(buf, size);
        if (conf->dict == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                "ZSTD_createDDict_byReference() failed");
            rc = NGX_CONF_ERROR;
            goto close;
        }
    }

close:

    if (fd != NGX_INVALID_FILE && ngx_close_file(fd) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_close_file_n " \"%V\" failed",
                           &uzmcf->dict_file);

        rc = NGX_CONF_ERROR;
    }

    return rc;
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
