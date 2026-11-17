#!/usr/bin/perl

# Tests for ngx_http_unzstd_filter_module.

###############################################################################

use warnings;
use strict;

use IO::Socket::INET;
use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use Test::Nginx qw/ :DEFAULT :gzip http_content /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http gzip proxy ssi/)->has_daemon('zstd')
    ->plan(46);

my $plain = join('', map { sprintf "X%03dXXXXXX", $_ } (0 .. 999));
my $boundary = 'B' x 1024;
my $dict = join('', map { "dictionary-token-$_:common-prefix/common-suffix\n" }
    (0 .. 255));
my $wrong_dict = join('', map { "different-token-$_:other-prefix/other-suffix\n" }
    (0 .. 255));

$t->write_file('dict', $dict);
$t->write_file('wrong-dict', $wrong_dict);

my $encoded = zstd_file($t, 'basic', $plain);
my $first = zstd_file($t, 'first', 'first-frame:');
my $second = zstd_file($t, 'second', 'second-frame');
my $empty = zstd_file($t, 'empty', '');
my $boundary_encoded = zstd_file($t, 'boundary', $boundary);
my $dict_plain = join('', map { "dictionary-token-$_:common-suffix\n" }
    (0 .. 255));
my $dict_encoded = zstd_file($t, 'with-dict', $dict_plain,
    '-D', $t->testdir() . '/dict');
my $wrong_dict_encoded = zstd_file($t, 'with-wrong-dict', $dict_plain,
    '-D', $t->testdir() . '/wrong-dict');

$t->write_file('concat', $first . $second);
$t->write_file('trailing', $encoded . 'not-a-zstd-frame');
$t->write_file('truncated', substr($encoded, 0, length($encoded) - 3));
$t->write_file('missing-frame', '');

my $corrupt = $encoded;
substr($corrupt, int(length($corrupt) / 2), 1) =
    chr(ord(substr($corrupt, int(length($corrupt) / 2), 1)) ^ 1);
$t->write_file('corrupt', $corrupt);
$t->write_file('identity', 'identity response');
$t->write_file('page.html',
    'before <!--# include virtual="/basic" --> after');

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    gzip_vary on;
    gzip_http_version 1.0;
    unzstd_dict_file %%TESTDIR%%/dict;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location = /force {
            unzstd on;
            unzstd_force on;
            proxy_pass http://127.0.0.1:8081/basic;
        }

        location = /gzip {
            unzstd on;
            gzip on;
            gzip_min_length 0;
            gzip_http_version 1.0;
            gzip_types text/plain;
            proxy_pass http://127.0.0.1:8081/basic;
        }

        location = /error {
            error_page 500 = /basic;
            return 500;
        }

        location = /stream {
            unzstd on;
            unzstd_buffers 2 1k;
            proxy_buffering off;
            proxy_pass http://127.0.0.1:8082/;
        }

        location = /page.html {
            ssi on;
            root %%TESTDIR%%;
        }

        location / {
            unzstd on;
            proxy_pass http://127.0.0.1:8081;
        }
    }

    server {
        listen       127.0.0.1:8081;
        server_name  localhost;

        location = /identity {
            root %%TESTDIR%%;
        }

        location / {
            root %%TESTDIR%%;
            default_type text/plain;
            etag off;
            add_header Content-Encoding zstd always;
            add_header ETag '"strong"' always;
        }
    }
}

EOF

$t->run_daemon(\&stream_daemon, port(8082), $boundary_encoded);
$t->run();

###############################################################################

my $r = get('/basic');
unlike($r, qr/^Content-Encoding:/mi, 'content encoding removed');
is(http_content($r), $plain, 'response decompressed');
unlike($r, qr/^Content-Length:/mi, 'content length removed');
unlike($r, qr/^Accept-Ranges:/mi, 'accept ranges removed');
like($r, qr/^ETag: W\/"strong"/mi, 'etag weakened');
like($r, qr/^Vary: Accept-Encoding/mi, 'vary added');

$r = get('/basic', 'zstd');
like($r, qr/^Content-Encoding: zstd/mi, 'accepted encoding preserved');
is(http_content($r), $encoded, 'accepted body preserved');

$r = get('/basic', 'zstd;q=0');
is(http_content($r), $plain, 'q zero decompressed');

$r = get('/basic', 'zstdx');
is(http_content($r), $plain, 'coding prefix rejected');

$r = get('/basic', 'zstd, gzip');
like($r, qr/^Content-Encoding: zstd/mi, 'fast path accepted');

$r = get('/basic', 'ZSTD');
like($r, qr/^Content-Encoding: zstd/mi, 'coding is case insensitive');

$r = get('/basic', 'zstd;q=0.001');
like($r, qr/^Content-Encoding: zstd/mi, 'positive minimum q accepted');

$r = get('/basic', 'zstd;q=0.000');
is(http_content($r), $plain, 'zero fractional q decompressed');

$r = get('/basic', 'zstd;q=1.001');
is(http_content($r), $plain, 'invalid q decompressed');

$r = get('/basic', 'zstd;');
like($r, qr/^Content-Encoding: zstd/mi,
    'trailing semicolon follows gzip parser behavior');

$r = get('/force', 'zstd');
unlike($r, qr/^Content-Encoding:/mi, 'force removes encoding');
is(http_content($r), $plain, 'force decompresses accepted encoding');

$r = get('/gzip', 'zstd, gzip');
like($r, qr/^Content-Encoding: zstd/mi,
    'accepted zstd is not recompressed');
is(http_content($r), $encoded, 'accepted zstd body is preserved with gzip on');

$r = http_gzip_request('/gzip');
like($r, qr/^Content-Encoding: gzip/mi,
    'gzip still works after zstd decompression');
http_gzip_like($r, qr/^\Q$plain\E$/,
    'zstd response is recompressed for gzip client');

$r = get('/concat');
is(http_content($r), 'first-frame:second-frame',
    'concatenated frames decompressed');

$r = get('/empty');
like($r, qr/ 200 /, 'empty frame status');
is(http_content($r), '', 'empty frame decompressed');

$r = get('/stream');
like($r, qr/ 200 /, 'chunked boundary status');
is(http_content($r), $boundary,
    'chunked frame ending before final buffer decompressed');

$r = get('/page.html');
unlike($r, qr/^Content-Encoding:/mi, 'ssi response is not encoded');
is(http_content($r), "before $plain after", 'ssi subrequest decompressed');

$r = get('/with-dict');
is(http_content($r), $dict_plain, 'dictionary frame decompressed');

$r = get('/identity');
is(http_content($r), 'identity response', 'identity response preserved');
unlike($r, qr/^Vary:/mi, 'identity response has no vary');

$r = head('/basic');
unlike($r, qr/^Content-Encoding:/mi, 'head content encoding removed');
unlike($r, qr/^Content-Length:/mi, 'head content length removed');
like($r, qr/^Vary: Accept-Encoding/mi, 'head vary added');

is(http_content(get('/error')), $plain,
    'response after internal redirect decompressed');

$r = get('/truncated');
like($t->read_file('error.log'),
    qr/truncated zstd response/,
    'truncated frame rejected');

my $errors = zstd_error_count($t);
$r = get('/corrupt');
cmp_ok(zstd_error_count($t), '>', $errors, 'corrupt frame rejected');

$errors = zstd_error_count($t);
$r = get('/with-wrong-dict');
cmp_ok(zstd_error_count($t), '>', $errors, 'wrong dictionary rejected');

$errors = zstd_error_count($t);
$r = get('/trailing');
cmp_ok(zstd_error_count($t), '>', $errors, 'trailing garbage rejected');

$errors = response_end_error_count($t);
$r = get('/missing-frame');
cmp_ok(response_end_error_count($t), '>', $errors, 'missing frame rejected');

$t->reload();
pass('configuration reloaded');
is(http_content(get('/with-dict')), $dict_plain,
    'dictionary works after reload');

like($t->read_file('error.log'), qr/http unzstd filter/,
    'body filter exercised');
unlike($t->read_file('error.log'), qr/ZSTD_freeDStream\(\) failed/,
    'decoder cleanup succeeded');
unlike($t->read_file('error.log'), qr/worker process exited on signal/,
    'worker remained healthy');

###############################################################################

sub get {
    my ($uri, $accept_encoding) = @_;
    my $header = defined $accept_encoding
        ? "Accept-Encoding: $accept_encoding\r\n" : '';

    return http("GET $uri HTTP/1.0\r\n"
        . "Host: localhost\r\n"
        . $header
        . "Connection: close\r\n\r\n");
}


sub head {
    my ($uri) = @_;

    return http("HEAD $uri HTTP/1.0\r\n"
        . "Host: localhost\r\n"
        . "Connection: close\r\n\r\n");
}


sub zstd_file {
    my ($test, $name, $content, @options) = @_;
    my $source = "$name.source";
    my $testdir = $test->testdir();

    $test->write_file($source, $content);

    system('zstd', '-q', '-f', '--no-progress', @options,
           "$testdir/$source", '-o', "$testdir/$name") == 0
        or die "zstd failed for $name: $?";

    return $test->read_file($name);
}


sub zstd_error_count {
    my ($test) = @_;
    my $log = $test->read_file('error.log');

    return () = $log =~ /ZSTD_decompressStream\(\) failed/g;
}


sub response_end_error_count {
    my ($test) = @_;
    my $log = $test->read_file('error.log');

    return () = $log =~ /truncated zstd response/g;
}


sub stream_daemon {
    my ($port, $content) = @_;

    my $server = IO::Socket::INET->new(
        LocalAddr => '127.0.0.1',
        LocalPort => $port,
        Listen => 5,
        ReuseAddr => 1,
        Proto => 'tcp'
    ) or die "cannot create stream test server: $!";

    while (my $client = $server->accept()) {
        $client->autoflush(1);

        my $request = '';
        while ($request !~ /\r?\n\r?\n/) {
            my $n = sysread($client, my $buffer, 1024);
            last if !defined $n || $n == 0;
            $request .= $buffer;
        }

        print $client "HTTP/1.1 200 OK\r\n"
            . "Content-Type: text/plain\r\n"
            . "Content-Encoding: zstd\r\n"
            . "Transfer-Encoding: chunked\r\n"
            . "Connection: close\r\n\r\n";

        for my $byte (split //, $content) {
            print $client "1\r\n$byte\r\n";
            select undef, undef, undef, 0.001;
        }

        select undef, undef, undef, 0.02;
        print $client "0\r\n\r\n";
        close $client;
    }
}

###############################################################################
