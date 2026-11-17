use strict;
use warnings;

use Test::More;
use Test::Nginx qw/:DEFAULT http_content/;
use FindBin;
use lib "$FindBin::Bin/lib";
use Compression;

my $t = Test::Nginx->new()->has(qw/http proxy/);
my $plain = 'protected compressed representation ' x 1024;
$t->write_file('plain', $plain);
is(system('python3', '-B', "$FindBin::Bin/lib/encode.py", 'zstd',
    $t->testdir() . '/plain', $t->testdir() . '/encoded'), 0, 'encoded fixture');
my $encoded = $t->read_file('encoded');
write_config($t, <<'EOF');
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    default_type text/plain;
    server {
        listen 127.0.0.1:8080;
        unzstd on;
        unzstd_force on;
        location / { proxy_pass http://127.0.0.1:8081; }
    }
    server {
        listen 127.0.0.1:8081;
        location /protected {
            alias %%TESTDIR%%/encoded;
            add_header Content-Encoding zstd;
            add_header Cache-Control public;
            add_header Cache-Control 'No-Transform';
        }
        location /stacked {
            alias %%TESTDIR%%/encoded;
            add_header Content-Encoding 'zstd, gzip';
        }
        location /ordinary {
            alias %%TESTDIR%%/encoded;
            add_header Content-Encoding zstd;
        }
    }
}
EOF
$t->run();
for my $case (['/protected', 'zstd'], ['/stacked', 'zstd, gzip']) {
    my ($path, $encoding) = @$case;
    my $response = request($path, 'identity');
    like($response, qr/^Content-Encoding: \Q$encoding\E\r?$/mi,
        "$path encoding is preserved even with force");
    is(http_content($response), $encoded, "$path representation is unchanged");
}
check_response($t, request('/ordinary', 'identity'), undef, $plain,
    'ordinary response is still decompressed');
$t->stop();
unlike($t->read_file('error.log'), qr/\[(?:alert|emerg)\]|Sanitizer|runtime error:/,
    'no decoder policy errors');
undef $t;
done_testing();
