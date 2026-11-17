#!/usr/bin/perl

use strict;
use warnings;

use Test::More;
use Test::Nginx;
use Digest::SHA qw/sha256/;
use IO::Socket::INET;
use Time::HiRes qw/sleep time/;
use FindBin;
use lib "$FindBin::Bin/lib";
use Compression;

my $t = Test::Nginx->new()->has(qw/http proxy sub/);
my $plain = ('replace_me ' x 8192) . join('', map { sha256(pack 'N', $_) } 0..4095);
my @encodings = decodings();
$t->write_file('plain', $plain);
my $locations = '';
for my $encoding (@encodings) {
    mkdir $t->testdir() . '/' . $encoding;
    my $path = $t->testdir() . '/' . $encoding . '/body';
    is(system('python3', '-B', "$FindBin::Bin/lib/encode.py", $encoding,
        $t->testdir() . '/plain', $path), 0, "$encoding fixture");
    my $data = $t->read_file("$encoding/body");
    $t->write_file("$encoding/short", substr($data, 0, length($data) - 3));
    $t->write_file("$encoding/concat", $data . $data);
    $t->write_file("$encoding/trailing", $data . 'garbage');
    my $header = $encoding eq 'raw' ? 'deflate' : $encoding;
    $locations .= "location /$encoding/ { add_header Content-Encoding $header; }\n";
}
my $conditional = $ENV{TEST_NGINX_EXPR} ? <<'EOF' : '';
    expr skip str_eq $arg_skip 1;
    when skip { unzstd off; }
EOF
my $config = <<'EOF';
%%TEST_GLOBALS%%
daemon off;
error_log %%TESTDIR%%/error.log debug;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    default_type text/plain;
    gzip off;
    gzip_vary on;
    server {
        listen 127.0.0.1:8080 sndbuf=8k;
        gzip_disable BadAgent;
__CONDITIONAL__
        unzstd on;
        unzstd_buffers 2 1k;
        location /on/ {
            proxy_pass http://127.0.0.1:8081/;
            proxy_buffering on;
            proxy_buffer_size 1k;
            proxy_buffers 4 1k;
            proxy_busy_buffers_size 2k;
        }
        location /off/ {
            proxy_pass http://127.0.0.1:8081/;
            proxy_buffering off;
            proxy_buffer_size 1k;
        }
        location /force/ {
            proxy_pass http://127.0.0.1:8081/;
            unzstd_force on;
        }
        location /chain/ {
            proxy_pass http://127.0.0.1:8081/;
            proxy_buffering off;
            unzstd_force on;
            sub_filter_types *;
            sub_filter_once off;
            sub_filter replace_me replaced;
            gzip on;
            gzip_min_length 0;
            gzip_types *;

        }
        location /disabled/ {
            proxy_pass http://127.0.0.1:8081/;
            unzstd off;
        }
    }
    server {
        listen 127.0.0.1:8081;
        root %%TESTDIR%%;
__LOCATIONS__
    }
}
EOF
$config =~ s/__CONDITIONAL__/$conditional/;
$config =~ s/__LOCATIONS__/$locations/;
write_config($t, $config);
$t->run();

for my $mode (qw/on off/) {
    for my $encoding (@encodings) {
        my $header = $encoding eq 'raw' ? 'deflate' : $encoding;
        check_response($t, request("/$mode/$encoding/body", 'identity'),
            undef, $plain, "$mode $encoding decompressed");
        check_response($t, request("/$mode/$encoding/body", "$header;q=0"),
            undef, $plain, "$mode $encoding q=0 decompressed");
    }
    for my $encoding (@encodings) {
        my $socket = IO::Socket::INET->new(PeerAddr => '127.0.0.1',
            PeerPort => port(8080), Proto => 'tcp', Timeout => 5) or die $!;
        $socket->autoflush(1);
        print $socket "GET /$mode/$encoding/body HTTP/1.1\r\nHost: localhost\r\n"
            . "Accept-Encoding: identity\r\nConnection: close\r\n\r\n";
        sleep 0.1;
        my $response = '';
        my $deadline = time() + 8;
        while (time() < $deadline) {
            my $n = sysread($socket, my $part, 257);
            last if !defined($n) || !$n;
            $response .= $part;
        }
        close $socket;
        check_response($t, $response, undef, $plain,
            "$mode $encoding slow client");
        $socket = IO::Socket::INET->new(PeerAddr => '127.0.0.1',
            PeerPort => port(8080), Proto => 'tcp', Timeout => 5) or die $!;
        $socket->autoflush(1);
        print $socket "GET /$mode/$encoding/body HTTP/1.1\r\nHost: localhost\r\n"
            . "Accept-Encoding: identity\r\n\r\n";
        sysread($socket, my $part, 512);
        close $socket;
    }
}
for my $encoding (@encodings) {
    check_response($t, request("/on/$encoding/body", $encoding),
        $encoding, $plain, "$encoding accepted unchanged");
    check_response($t, request("/on/$encoding/body", $encoding,
        "User-Agent: BadAgent\r\n"), undef, $plain,
        "$encoding core client restriction");
    check_response($t, request("/force/$encoding/body", $encoding),
        undef, $plain, "$encoding forced unzstd");
    check_response($t, request("/disabled/$encoding/body", $encoding),
        $encoding, $plain, "$encoding unzstd disabled");
    my $replaced = $plain;
    $replaced =~ s/replace_me/replaced/g;
    check_response($t, request("/chain/$encoding/body", 'gzip'),
        'gzip', $replaced, "$encoding unzstd then sub then compression");
    my $response = request("/on/$encoding/body", 'identity',
        "Range: bytes=0-9\r\n");
    like($response, qr/^HTTP\/1.1 206 /, "$encoding partial response unchanged");
    like($response, qr/^Content-Encoding: \Q$encoding\E\r?$/mi,
        "$encoding partial encoding preserved");
    if ($ENV{TEST_NGINX_EXPR}) {
        check_response($t, request("/on/$encoding/body?skip=1", 'identity'),
            $encoding, $plain, "$encoding conditional unzstd disable");
    }
}
for my $encoding (grep { $_ eq 'gzip' || $_ eq 'zstd' } @encodings) {
    check_response($t, request("/off/$encoding/concat", 'identity'), undef,
        $plain . $plain, "$encoding concatenated frames");
}
for my $encoding (@encodings) {
    unlike(request("/off/$encoding/short", 'identity'), qr/\r\n0\r\n\r\n\z/,
        "$encoding truncated response is not completed");
    unlike(request("/off/$encoding/trailing", 'identity'), qr/\r\n0\r\n\r\n\z/,
        "$encoding trailing data response is not completed");
    check_response($t, request('/off/zstd/body', 'identity'), undef, $plain,
        "worker survives invalid $encoding response");
}

$t->stop();
my $log = $t->read_file('error.log');
like($log, qr/truncated|inflate\(\) failed|DecompressStream\(\) failed/,
    'invalid compressed responses are rejected');
unlike($log, qr/\[(?:alert|emerg)\]|Sanitizer|runtime error:/,
    'no decoder lifecycle errors');
undef $t;
done_testing();
