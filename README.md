# Name
ngx_http_unzstd_filter_module is a filter that decompresses responses with “Content-Encoding: zstd” for clients that do not support “zstd” ([Zstandard compression](https://facebook.github.io/zstd/)) encoding method. The module will be useful when it is desirable to store data compressed to save space and reduce I/O costs.

# Table of Content

- [Name](#name)
- [Table of Content](#table-of-content)
- [Status](#status)
- [Synopsis](#synopsis)
- [Installation](#installation)
- [Directives](#directives)
  - [unzstd](#unzstd)
  - [unzstd\_force](#unzstd_force)
  - [unzstd\_buffers](#unzstd_buffers)
- [Author](#author)
- [License](#license)
# Status

This Nginx module is currently considered experimental. Issues and PRs are welcome if you encounter any problems.

# Synopsis

```nginx
server {
    listen 127.0.0.1:8080;
    server_name localhost;

    location / {
        # enable zstd decompression for clients that do not support zstd compression
        unzstd on;

        proxy_pass http://foo.com;
    }
}
```

# Installation

To use theses modules, configure your nginx branch with `--add-module=/path/to/ngx_http_unzstd_filter_module`. Several points should be taken care.

* Zstandard 1.4.0 or later is required.
* You can set environment variables `ZSTD_INC` and `ZSTD_LIB` to specify the path to `zstd.h` and the path to the zstd library respectively.
* A shared library is used when present; otherwise, the static library is used. Static linking is recommended because this Nginx module uses **advanced APIs**.
* System's zstd bundle will be linked if `ZSTD_INC` and `ZSTD_LIB` are not specified.

# Directives

## unzstd

**Syntax:** *unzstd on | off;*

**Default:** *unzstd off;*

**Context:** *http, server, location, when*

Enables or disables decompression of zstd compressed responses for clients that lack zstd support.
When built with `ngx_expr_module`, this directive can also be configured
inside a `when` block.

## unzstd_force

**Syntax:** *unzstd_force on | off;*

**Default:** *unzstd_force off;*

**Context:** *http, server, location, when*

When enabled, decompresses zstd responses without checking whether the client
accepts zstd. Responses without `Content-Encoding: zstd` are not affected.
When built with `ngx_expr_module`, this directive can also be configured
inside a `when` block.

## unzstd_buffers

**Syntax:** *unzstd_buffers number size;*

**Default:** *unzstd_buffers 32 4k | 16 8k;*

**Context:** *http, server, location*

Sets the number and size of buffers used to decompress a response. By default, the buffer size is equal to one memory page. This is either 4K or 8K, depending on a platform.

# Author

Hanada im@hanada.info

This module is based on [ngx_http_gunzip_module](https://nginx.org/en/docs/http/ngx_http_gunzip_module.html), one of nginx core modules and [ngx_unbrotli](https://github.com/clyfish/ngx_unbrotli), a nginx module for brotli decompression.

# License

This Nginx module is licensed under [BSD 2-Clause License](LICENSE).
