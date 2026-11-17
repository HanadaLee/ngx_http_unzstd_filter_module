package Compression;

use strict;
use warnings;

use Exporter 'import';
use Test::More;
use Test::Nginx qw/http http_content/;
use File::Basename qw/dirname/;
use File::Spec;

our @EXPORT = qw/request decoded check_response encodings decodings write_config/;

sub encodings { return ('zstd'); }


sub decodings { return ('zstd'); }

sub write_config {
    my ($t, $config) = @_;
    my $encodings = join ' ', encodings();
    $config =~ s/__ENCODINGS__/$encodings/g;
    if (defined $ENV{TEST_NGINX_GZIP} && !$ENV{TEST_NGINX_GZIP}) {
        $config =~ s/^\s*gzip off;\n//mg;
    }
    return $t->write_file_expand('nginx.conf', $config);
}

sub request {
    my ($path, $encoding, $headers, $version) = @_;
    $headers //= '';
    $version //= '1.1';
    my $accept = defined $encoding ? "Accept-Encoding: $encoding\r\n" : '';
    return http("GET $path HTTP/$version\r\nHost: localhost\r\n"
        . "Connection: close\r\n$accept$headers\r\n");
}

sub decoded {
    my ($t, $response, $plain) = @_;
    my ($encoding) = $response =~ /^Content-Encoding:\s*(\S+)\r?$/mi;
    my $data = http_content($response);
    return $data if !defined $encoding;
    $t->write_file('encoded', $data);
    my $dir = $t->testdir();
    my $decoder = File::Spec->rel2abs(dirname(__FILE__) . '/decode.py');
    my $status = system('python3', '-B', $decoder, $encoding,
        "$dir/encoded", "$dir/decoded", length $plain);
    if ($status != 0) {
        fail("$encoding decoder accepts the complete response");
        return '';
    }
    return $t->read_file('decoded');
}

sub check_response {
    my ($t, $response, $encoding, $plain, $name) = @_;
    like($response, qr/^HTTP\/1\.[01] 200 /, "$name status");
    if (defined $encoding) {
        like($response, qr/^Content-Encoding: \Q$encoding\E\r?$/mi,
            "$name encoding");
    } else {
        unlike($response, qr/^Content-Encoding:/mi, "$name identity");
    }
    is(decoded($t, $response, $plain), $plain, "$name round trip");
}

1;
