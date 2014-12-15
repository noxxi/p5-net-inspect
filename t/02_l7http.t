use strict;
use warnings;
use Net::Inspect::L7::HTTP;
use Test::More;
$Net::Inspect::Debug::DEBUG = 0;

my @result;
{
    # collect called hooks
    package myRequest;
    use base 'Net::Inspect::Flow';
    sub new_request        { return bless {},ref(shift) }
    sub in_request_header  { push @result, [ 'request_header',  $_[1] ] }
    sub in_request_body    { push @result, [ 'request_body',    $_[1] ] }
    sub in_response_header { push @result, [ 'response_header', $_[1] ] }
    sub in_response_body   { push @result, [ 'response_body',   $_[1] ] }
    sub in_chunk_header    { push @result, [ 'chunk_header',  @_[1,2] ] }
    sub in_chunk_trailer   { push @result, [ 'chunk_trailer', @_[1,2] ] }
    sub in_data            { push @result, [ 'data',          @_[1,2] ] }
    sub fatal              { push @result, [ 'fatal',         @_[1,2] ] }
}

my @tests = (
    [ "Simple GET with response body",
	0 => "GET / HTTP/1.0\r\n\r\n",
	request_header => "GET / HTTP/1.0\r\n\r\n",
	request_body => '',
	1 => "HTTP/1.0 200 Ok\r\n\r\n",
	response_header => "HTTP/1.0 200 Ok\r\n\r\n",
	1 => 'This ends with EOF',
	response_body => 'This ends with EOF',
	1 => '',
	response_body => '',
    ],

    [ "HTTP header in multiple parts",
	0 => "GET / HTTP/1.",
	0 => "0\r\n\r\n",
	request_header => "GET / HTTP/1.0\r\n\r\n",
	request_body => '',
	1 => "HTTP/1.0 2",
	1 => "00 Ok\r\n\r\n",
	response_header => "HTTP/1.0 200 Ok\r\n\r\n",
	1 => 'This ends with EOF',
	response_body => 'This ends with EOF',
	1 => '',
	response_body => '',
    ],

    [ "HTTP header in multiple parts (2)",
	0 => "GET http://foo",
	0 => "/bar HTTP/1.0\r\n",
	0 => "\r\n",
	request_header => "GET http://foo/bar HTTP/1.0\r\n\r\n",
	request_body => '',
    ],

    [ "chunked response",
	0 => "GET / HTTP/1.1\r\n\r\n",
	request_header => "GET / HTTP/1.1\r\n\r\n",
	request_body => '',
	1 => "HTTP/1.1 200 Ok\r\nTransfer-Encoding: chunked\r\n\r\n",
	response_header => "HTTP/1.1 200 Ok\r\nTransfer-Encoding: chunked\r\n\r\n",
	1 => "a\r\n",
	chunk_header => "1|a\r\n",
	1 => "0123456789\r\n",
	response_body => "0123456789",
	1 => "0\r\n\r\n",
	chunk_header  => "1|0\r\n",
	response_body => "",
	chunk_trailer  => "1|\r\n",
    ],

    [ "chunked request",
	0 => "POST / HTTP/1.1\r\nTransfer-Encoding: chUNkeD\r\n\r\n",
	request_header => "POST / HTTP/1.1\r\nTransfer-Encoding: chUNkeD\r\n\r\n",
	0 => "a\r\n",
	chunk_header => "0|a\r\n",
	0 => "0123456789\r\n",
	request_body => "0123456789",
	0 => "0\r\n\r\n",
	chunk_header  => "0|0\r\n",
	request_body => "",
	chunk_trailer  => "0|\r\n",
    ],

    [ "chunked POST followed by simple GET pipelined",
	0 => "POST / HTTP/1.1\r\nTransfer-Encoding: chUNkeD\r\n\r\n",
	request_header => "POST / HTTP/1.1\r\nTransfer-Encoding: chUNkeD\r\n\r\n",
	0 => "a\r\n",
	chunk_header => "0|a\r\n",
	0 => "0123456789\r\n",
	request_body => "0123456789",
	0 => "0\r\n\r\n",
	chunk_header  => "0|0\r\n",
	request_body => "",
	chunk_trailer  => "0|\r\n",
	0 => "GET / HTTP/1.1\r\n\r\n",
	request_header => "GET / HTTP/1.1\r\n\r\n",
	request_body => "",
	1 => "HTTP/1.1 204 no content\r\n\r\n",
	response_header => "HTTP/1.1 204 no content\r\n\r\n",
	response_body => '',
	1 => "HTTP/1.1 200 ok\r\nContent-length: 0\r\n\r\n",
	response_header => "HTTP/1.1 200 ok\r\nContent-length: 0\r\n\r\n",
	response_body => '',
    ],

    [ "1xx continue response", 
	0 => "GET / HTTP/1.1\r\n\r\n",
	request_header => "GET / HTTP/1.1\r\n\r\n",
	request_body => '',
	1 => "HTTP/1.0 100 Continue\r\n\r\n",
	response_header => "HTTP/1.0 100 Continue\r\n\r\n",
	1 => "HTTP/1.1 204 no content\r\n\r\n",
	response_header => "HTTP/1.1 204 no content\r\n\r\n",
	response_body => '',
    ],

    [ "invalid content-length request", 
	0 => "POST / HTTP/1.1\r\nContent-length: -10\r\n\r\n",
	fatal => "invalid content-length '-10' in request|0",
    ],

    [ "invalid content-length response", 
	0 => "GET / HTTP/1.1\r\n\r\n",
	request_header => "GET / HTTP/1.1\r\n\r\n",
	request_body => '',
	1 => "HTTP/1.1 200 ok\r\nContent-length: 0xab\r\n\r\n",
	fatal => "invalid content-length '0xab' in response|1",
    ],
);

plan tests => 0+@tests;

my $req = myRequest->new;
my $http = Net::Inspect::L7::HTTP->new($req);
for my $t (@tests) {
    my $conn = $http->new_connection({});
    my $desc = shift(@$t);
    my @buf;
    @result = ();
    if ( eval {
	while (@$t) {
	    my ($what,$data) = splice(@$t,0,2);
	    if ( $what eq '0' or $what eq '1' ) {
		die "expected no hooks, got @{$result[0]}" if @result;
		# put into $conn
		$buf[$what] .= $data;
		my $processed = $conn->in(0+$what,$buf[$what],$data eq '' ? 1:0,0);
		substr( $buf[$what],0,$processed,'' );
	    } elsif ( ! @result ) {
		die "expected $what, got no results"
	    } else {
		my $r = join('|',@{shift(@result)});
		die "expected '$what|$data', got '$r'" if "$what|$data" ne $r;
	    }
	}
	die "expected no hooks, got @{$result[0]}" if @result;
	1;
    }) {
	pass($desc)
    } else {
	diag($@);
	fail($desc);
    }
}

