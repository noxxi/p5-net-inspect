############################################################################
# finds HTTP requests + responses in tcp connection
# chunked HTTP responses are supported
############################################################################
use strict;
use warnings;
package Net::Inspect::L7::HTTP;
use base 'Net::Inspect::Flow';
use Net::Inspect::Debug qw(:DEFAULT $DEBUG %TRACE);
use Hash::Util 'lock_keys';
use Digest::SHA 'sha1_base64';
use Carp 'croak';
use Scalar::Util 'weaken';
use fields (
    'replay',   # collected and replayed in guess_protocol
    'meta',     # meta data from connection
    'requests', # list of open requests, see _in0 for fields
    'error',    # connection has error like server sending data w/o request
    'upgrade',  # true if got upgrade, CONNECT, WebSockets..
    'connid',   # connection id
    'lastreqid',# id of last request
    'offset',   # offset in data stream 
    'gap_upto', # up to which offset we could manage a gap, that is where we
		# only get body data (no header, chunked info..).
		# [off,off] similar to offset and off is set to -1 if umlimited
		# (i.e. body ends with end of file)
    'hdr_maxsz',# maximum header size for request(0), response(1) and
                # chunk header(2). Defaults to 64k, 16k and 2k.
);

use Exporter 'import';
our (@EXPORT_OK,%EXPORT_TAGS);
{
    %EXPORT_TAGS = (
	need_body => [qw(
	    METHODS_WITHOUT_RQBODY METHODS_WITH_RQBODY METHODS_WITHOUT_RPBODY
	    CODE_WITHOUT_RPBODY
	)]
    );
    push @EXPORT_OK,@$_ for (values %EXPORT_TAGS);
    push @EXPORT_OK,'parse_hdrfields','parse_reqhdr','parse_rsphdr';
}

use constant {
    METHODS_WITHOUT_RQBODY => [qw(GET HEAD DELETE CONNECT)],
    METHODS_WITH_RQBODY    => [qw(POST PUT)],
    METHODS_WITHOUT_RPBODY => [qw(HEAD)],
    CODE_WITHOUT_RPBODY    => [100..199, 204, 205, 304],
};

use constant {
    RQHDR_DONE => 0b00001,
    RQBDY_DONE => 0b00010,
    RQ_ERROR   => 0b00100,
    RPHDR_DONE => 0b01000,
    RPBDY_DONE_ON_EOF => 0b10000,
};

my %Upgrade2Sub = (
    'websocket' => \&upgrade_websocket,
    'CONNECT'   => \&upgrade_CONNECT,
);

# rfc2616, 2.2
#  token          = 1*<any CHAR except CTLs or separators>
#  separators     = "(" | ")" | "<" | ">" | "@"
#                 | "," | ";" | ":" | "\" | <">
#                 | "/" | "[" | "]" | "?" | "="
#                 | "{" | "}" | SP | HT

my $separator = qr{[()<>@,;:\\"/\[\]?={} \t]};
my $token = qr{[^()<>@,;:\\"/\[\]?={}\x00-\x20\x7f]+};
my $token_value_cont = qr{
    ($token):                      # key:
    [\040\t]*([^\r\n]*?)[\040\t]*  # <space>value<space>
    ((?:\r?\n[\040\t][^\r\n]*)*)   # continuation lines
    \r?\n                          # (CR)LF
}x;

# common error: "Last Modified" instead of "Last-Modified"
# squid seems to just strip invalid headers, try the same
my $xtoken = qr{[^()<>@,;:\\"/\[\]?={}\x00-\x20\x7f][^:[:^print:]]*};

my %METHODS_WITHOUT_RQBODY = map { ($_,1) } @{METHODS_WITHOUT_RQBODY()};
my %METHODS_WITH_RQBODY    = map { ($_,1) } @{METHODS_WITH_RQBODY()};
my %METHODS_WITHOUT_RPBODY = map { ($_,1) } @{METHODS_WITHOUT_RPBODY()};
my %CODE_WITHOUT_RPBODY    = map { ($_,1) } @{CODE_WITHOUT_RPBODY()};

sub guess_protocol {
    my ($self,$guess,$dir,$data,$eof,$time,$meta) = @_;

    if ( $dir == 0 ) {
	my $rp = $self->{replay} ||= [];
	push @$rp,[$data,$eof,$time];
	my $buf = join('',map { $_->[0] } @$rp);
	if ( $buf =~m{
	    \A[\r\n]*                                   # initial junk
	    [A-Z]{2,20}[\040\t]{1,3}                    # method
	    \S+[\040\t]{1,3}                            # path/URI
	    HTTP/1\.[01][\040\t]{0,3}                   # version
	    \r?\n                                       # (CR)LF
	    (?:$xtoken:.*\r?\n(?:[\t\040].*\r?\n)* )*   # field:..+cont
	    \r?\n                                       # empty line
	}xi) {
	    # looks like HTTP request
	    my $obj =  $self->new_connection($meta);
	    # replay as one piece
	    my $n = $obj->in(0,$buf,$rp->[-1][1],$rp->[-1][2]);
	    undef $self->{replay};
	    $n += -length($buf) + length($data);
	    $n<=0 and die "object $obj did not consume alle replayed bytes";
	    debug("consumed $n of ".length($data)." bytes");
	    return ($obj,$n);

	} elsif ( $buf =~m{[^\n]\r?\n\r?\n}
	    or length($buf)>2**16 ) {
	    # does not look like a HTTP header for me
	    debug("does not look like HTTP header: $buf");
	    $guess->detach($self);
	} else {
	    debug("need more data to decide if HTTP");
	    return;
	}
    } else {
	# data from server but no request header from
	# client yet - cannot be HTTP
	debug("got data from server before getting request from client -> no HTTP");
	$guess->detach($self);
    }
    return;
}


{
    my $connid = 0;
    sub syn { 1 }; # in case it is attached to Net::Inspect::Tcp
    sub new_connection {
	my ($self,$meta,%args) = @_;
	my $obj = $self->new;
	$obj->{meta} = $meta;
	$obj->{requests} = [];
	$obj->{connid} = ++$connid;
	$obj->{lastreqid} = 0;
	$obj->{offset} = [0,0];
	$obj->{gap_upto} = [0,0];
	$obj->{hdr_maxsz} = delete $args{header_maxsize};
	$obj->{hdr_maxsz}[0] ||= 2**16;
	$obj->{hdr_maxsz}[1] ||= 2**14;
	$obj->{hdr_maxsz}[2] ||= 2**11;

	return $obj;
    }
}

sub in {
    my ($self,$dir,$data,$eof,$time) = @_;
    $DEBUG && $self->xdebug("got %s bytes from %d, eof=%d",
	ref($data) ? join(":",@$data): length($data),
	$dir,$eof//0
    );
    my $bytes = $dir == 0
	? _in0($self,$data,$eof,$time)
	: _in1($self,$data,$eof,$time);
    #$self->dump_state if $DEBUG;
    return $bytes;
}

sub offset {
    my $self = shift;
    return @{ $self->{offset} }[wantarray ? @_:$_[0]];
}

sub gap_diff {
    my $self = shift;
    my @rv;
    for(@_) {
	my $off = $self->{gap_upto}[$_];
	push @rv,
	    $off == -1 ? -1 :
	    ($off-=$self->{offset}[$_]) > 0 ? $off :
	    0;
    }
    return wantarray ? @rv : $rv[0];
}

sub gap_offset {
    my $self = shift;
    my @rv;
    for(@_) {
	my $off = $self->{gap_upto}[$_];
	push @rv,
	    $off == -1 ? -1 :
	    $off > $self->{offset}[$_] ? $off :
	    0
    }
    return wantarray ? @rv : $rv[0];
}

# give requests a chance to cleanup before destroying connection
sub DESTROY {
    my $self = shift;
    @{$self->{requests}} = ();
}


# process request data
sub _in0 {
    my ($self,$data,$eof,$time) = @_;
    my $bytes = 0; # processed bytes
    my $rqs = $self->{requests};

    if ( ref($data)) {
	# process gap in request data
	croak "unknown type $data->[0]" if $data->[0] ne 'gap';
	my $len = $data->[1];

	croak 'existing error in connection' if $self->{error};

	my $rqs = $self->{requests};
	croak 'no open request' if ! @$rqs or
	    $rqs->[0]{state} & RQBDY_DONE && ! $self->{upgrade};
	croak 'existing error in request' if $rqs->[0]{state} & RQ_ERROR;
	croak "gap too large" if $self->{gap_upto}[0]>=0
	    && $self->{gap_upto}[0] < $self->{offset}[0] + $len;

	if (defined $rqs->[0]{rqclen}) {
	    $rqs->[0]{rqclen} -= $len;
	    if ( ! $rqs->[0]{rqclen} && ! $rqs->[0]{rqchunked} ) {
		$rqs->[0]{state} |= RQBDY_DONE;
	    }
	}

	$self->{offset}[0] += $len;
	my $obj = $rqs->[0]{obj};
	if ($self->{upgrade}) {
	    $self->{upgrade}[0]([ gap => $len ],$eof,$time);
	} elsif ($obj) {
	    $obj->in_request_body(
		[ gap => $len ],
		$eof || ($rqs->[0]{state} & RQBDY_DONE ? 1:0),
		$time
	    );
	}
	return $len;
    }

    READ_DATA:

    if ($self->{error}) {
	$DEBUG && $self->xdebug("no more data because of server side error");
	return $bytes;
    }

    if ($self->{upgrade}) {
	$self->{offset}[0] += length($data);
	$self->{upgrade}[0]($data,$eof,$time);
	return $bytes + length($data);
    }

    if (@$rqs and $rqs->[0]{state} & RQ_ERROR ) {
	# error reading request
	$DEBUG && $self->xdebug("no more data because of client side error");
	return $bytes;
    }

    if ( ( ! @$rqs or $rqs->[0]{state} & RQBDY_DONE )
	and $data =~m{\A[\r\n]+}g ) {
	# first request or previous request body done
	# new request might follow but maybe we only have trailing lines after
	# the last request: eat empty lines
	my $n = pos($data);
	$bytes += $n;
	$self->{offset}[0] += $n;
	substr($data,0,$n,'');
	%TRACE && $self->xtrace("eat empty lines before request header");
    }

    if ( $data eq '' ) {
	$DEBUG && $self->xdebug("no data, eof=$eof, bytes=$bytes");
	return $bytes if ! $eof; # need more data

	# handle EOF
	# check if we got request body for last request
	if ( @$rqs and not $rqs->[0]{state} & RQBDY_DONE ) {
	    # request body not done yet
	    %TRACE && ($rqs->[0]{obj}||$self)->xtrace("request body not done but eof");
	    ($rqs->[0]{obj}||$self)->fatal('eof but request body not done',0,$time);
	    $rqs->[0]{state} |= RQ_ERROR;
	    return $bytes;
	}

	return $bytes; # request body done
    }

    # create new request if no open request or last open request has the
    # request body already done (pipelining)
    if ( ! @$rqs or $rqs->[0]{state} & RQBDY_DONE ) {
	$DEBUG && $self->xdebug("create new request");
	my $obj = $self->new_request({
	    %{$self->{meta}},
	    time => $time,
	    reqid => ++$self->{lastreqid}
	});
	my %rq = (
	    obj      => $obj,
	    # bitmask what is done: rpbody|rphdr|rqerror|rqbody|rqhdr
	    state    => 0,
	    rqclen   => undef,   # open content-length request
	    rpclen   => undef,   # open content-length response
	    # chunked mode for request|response:
	    #   false - no chunking
	    #   1,r[qp]clen == 0 - next will be chunk size
	    #   1,r[qp]clen > 0  - inside chunk data, need *clen
	    #   2 - next will be chunk
	    #   3 - after last chunk, next will be chunk trailer
	    rqchunked => undef,  # chunked mode for request
	    rpchunked => undef,  # chunked mode for response
	    method   => undef,   # request method
	    upgrade  => undef,   # { websocket => sec-websocket-key }
	    expect   => undef,   # hash with expectations like "100-continue"
	    info     => '',      # debug info
	);
	lock_keys(%rq);
	unshift @$rqs, \%rq;
    }

    my $rq = $rqs->[0];
    my $obj = $rq->{obj};

    # read request header if not done
    if ( not $rq->{state} & RQHDR_DONE ) {
	# no request header yet, check if data contains it

	# leading newlines at beginning of request are legally ignored junk
	if ( $data =~s{\A([\r\n]+)}{} ) {
	    ($obj||$self)->in_junk(0,$1,0,$time);
	}

	$DEBUG && $self->xdebug("need to read request header");
	if ($data =~s{\A(\A.*?\n\r?\n)}{}s) {
	    $DEBUG && $self->xdebug("got request header");
	    my $hdr = $1;
	    my $n = length($hdr);
	    $self->{offset}[0] += $n;
	    $bytes += $n;
	    $rq->{state} |= RQHDR_DONE; # rqhdr done

	    my %hdr;
	    my $err = parse_reqhdr($hdr,\%hdr);
	    if ($err) {
		($obj||$self)->fatal($err,0,$time);
		$rq->{state} |= RQ_ERROR;
		return $bytes;
	    }

	    my $body_done;
	    if ($hdr{chunked}) {
		$rq->{rqchunked} = 1;
	    } elsif ($hdr{content_length}) {
		$rq->{rqclen} = $hdr{content_length};
		$self->{gap_upto}[0]= $self->{offset}[0] + $hdr{content_length};
	    } else {
		$body_done = $hdr{method} ne 'CONNECT';
	    }

	    $rq->{expect}  = $hdr{expect};
	    $rq->{method}  = $hdr{method};
	    $rq->{info}    = $hdr{info};
	    $rq->{upgrade} = $hdr{upgrade};

	    %TRACE && $hdr{junk} && ($obj||$self)->xtrace(
		"invalid request header data: $hdr{junk}");

	    $obj && $obj->in_request_header($hdr,$time,\%hdr);

	    if ($body_done) {
		$DEBUG && $self->xdebug("no content-length - request body done");
		$rq->{state} |= RQBDY_DONE;
		$obj && $obj->in_request_body('',1,$time);
	    }

	} elsif ( length($data) > $self->{hdr_maxsz}[0] ) {
	    ($obj||$self)->fatal('request header too big',0,$time);
	    $rq->{state} |= RQ_ERROR;
	    return $bytes;
	} elsif ( $eof ) {
	    ($obj||$self)->fatal('eof in request header',0,$time);
	    $rq->{state} |= RQ_ERROR;
	    return $bytes;
	} else {
	    # will be called on new data from upper flow
	    $DEBUG && $self->xdebug("need more bytes for request header");
	    return $bytes;
	}
    }

    # read request body if not done
    if ( $data ne '' and not $rq->{state} & RQBDY_DONE ) {
	# request body
	if ( my $want = $rq->{rqclen} ) {
	    my $l = length($data);
	    if ( $l>=$want) {
		# got all request body
		$DEBUG && $self->xdebug("need $want bytes, got all");
		my $body = substr($data,0,$rq->{rqclen},'');
		$self->{offset}[0] += $rq->{rqclen};
		$bytes += $rq->{rqclen};
		$rq->{rqclen} = 0;
		if ( ! $rq->{rqchunked} ) {
		    $rq->{state} |= RQBDY_DONE; # req body done
		    $obj && $obj->in_request_body($body,1,$time) 
		} else {
		    $obj && $obj->in_request_body($body,$eof,$time);
		    $rq->{rqchunked} = 2; # get CRLF after chunk
		}
	    } else {
		# only part
		$DEBUG && $self->xdebug("need $want bytes, got only $l");
		my $body = substr($data,0,$l,'');
		$self->{offset}[0] += $l;
		$bytes += $l;
		$rq->{rqclen} -= $l;
		$obj && $obj->in_request_body($body,0,$time);
	    }

	# Chunking: rfc2616, 3.6.1
	} else {
	    # [2] must get CRLF after chunk
	    if ( $rq->{rqchunked} == 2 ) {
		$DEBUG && $self->xdebug("want CRLF after chunk");
		if ( $data =~m{\A\r?\n}g ) {
		    my $n = pos($data);
		    $self->{offset}[0] += $n;
		    $bytes += $n;
		    substr($data,0,$n,'');
		    $rq->{rqchunked} = 1; # get next chunk header
		    $DEBUG && $self->xdebug("got CRLF after chunk");
		} elsif ( length($data)>=2 ) {
		    ($obj||$self)->fatal("no CRLF after chunk",0,$time);
		    $self->{error} = 1;
		    return $bytes;
		} else {
		    # need more
		    return $bytes;
		}
	    }

	    # [1] must read chunk header
	    if ( $rq->{rqchunked} == 1 ) {
		$DEBUG && $self->xdebug("want chunk header");
		if ( $data =~m{\A([\da-fA-F]+)[ \t]*(?:;.*)?\r?\n}g ) {
		    $rq->{rqclen} = hex($1);
		    my $chdr = substr($data,0,pos($data),'');
		    $self->{offset}[0] += length($chdr);
		    $bytes += length($chdr);

		    $self->{gap_upto}[0] = $self->{offset}[0] + $rq->{rqclen}
			if $rq->{rqclen};

		    $obj->in_chunk_header(0,$chdr,$time) if $obj;
		    $DEBUG && $self->xdebug(
			"got chunk header - want $rq->{rqclen} bytes");
		    if ( ! $rq->{rqclen} ) {
			# last chunk
			$rq->{rqchunked} = 3;
			$obj && $obj->in_request_body('',1,$time);
		    }
		} elsif ( $data =~m{\n} or length($data)>8192 ) {
		    ($obj||$self)->fatal("invalid chunk header",0,$time);
		    $self->{error} = 1;
		    return $bytes;
		} else {
		    # need more data
		    return $bytes;
		}
	    }

	    # [3] must read chunk trailer
	    if ( $rq->{rqchunked} == 3 ) {
		$DEBUG && $self->xdebug("want chunk trailer");
		if ( $data =~m{\A
		    (?:\w[\w\-]*:.*\r?\n(?:[\t\040].*\r?\n)* )*  # field:..+cont
		    \r?\n
		}xg) {
		    $DEBUG && $self->xdebug("got chunk trailer");
		    my $trailer = substr($data,0,pos($data),'');
		    $self->{offset}[0] += length($trailer);
		    $bytes += length($trailer);
		    $obj->in_chunk_trailer(0,$trailer,$time) if $obj;
		    $rq->{state} |= RQBDY_DONE; # request done
		} elsif ( $data =~m{\n\r?\n} 
		    or length($data) > $self->{hdr_maxsz}[2] ) {
		    ($obj||$self)->fatal("invalid chunk trailer",0,$time);
		    $self->{error} = 1;
		    return $bytes;
		} elsif ( $eof ) {
		    # not fatal, because we got all data
		    %TRACE && ($obj||$self)->xtrace(
			"eof before end of chunk trailer");
		    $self->{error} = 1;
		    return $bytes;
		} else {
		    # need more
		    $DEBUG && $self->xdebug("need more bytes for chunk trailer");
		    return $bytes
		}
	    }
	}
    }

    goto READ_DATA;
}



# process response data
sub _in1 {
    my ($self,$data,$eof,$time) = @_;

    my $rqs = $self->{requests};
    my $bytes = 0; # processed bytes

    if ( ref($data)) {
	# process gap in response data
	croak "unknown type $data->[0]" if $data->[0] ne 'gap';
	my $len = $data->[1];

	croak 'existing error in connection' if $self->{error};

	my $rqs = $self->{requests};
	croak 'no open response' if ! @$rqs;
	my $rq = $rqs->[-1];
	croak 'existing error in request' if $rq->{state} & RQ_ERROR;
	croak "gap too large" if $self->{gap_upto}[1]>=0
	    && $self->{gap_upto}[1] < $self->{offset}[1] + $len;

	$rq->{rpclen} -= $len if defined $rq->{rpclen};
	$self->{offset}[1] += $len;

	my $obj = $rq->{obj};
	if ($self->{upgrade}) {
	    $self->{upgrade}[1]([ gap => $len ],$eof,$time);
	} elsif ($rq->{rpclen}
	    or !defined $rq->{rpclen}
	    or $rq->{rpchunked}) {
	    $obj && $obj->in_response_body([ gap => $len ],$eof,$time);
	} else {
	    # done with request
	    pop(@$rqs);
	    $obj && $obj->in_response_body([ gap => $len ],1,$time);
	}
	return $len;
    }


    READ_DATA:

    return $bytes if $self->{error};
    return $bytes if $data eq '' && !$eof;

    if ($self->{upgrade}) {
	$self->{offset}[1] += length($data);
	$self->{upgrade}[1]($data,$eof,$time);
	return $bytes + length($data);
    }

    if ( $data eq '' ) {
	$DEBUG && $self->xdebug("no more data, eof=$eof bytes=$bytes");

	# handle EOF
	# check if we got response body for last request
	if ( @$rqs && $rqs->[-1]{state} & RPBDY_DONE_ON_EOF ) {
	    # response body done on eof
	    my $rq = pop(@$rqs);
	    $rq->{obj}->in_response_body('',1,$time) if $rq->{obj};
	    return $bytes;
	}
	if ( @$rqs ) {
	    # response body not done yet
	    my $rq = pop(@$rqs);
	    %TRACE && ($rq->{obj}||$self)->xtrace("response body not done but eof");
	    ($rq->{obj}||$self)->fatal('eof but response body not done', 1,$time);
	    return $bytes;
	}

	return $bytes; # done
    }

    if ( ! @$rqs ) {
	if ( $data =~s{\A([\r\n]+)}{} ) {
	    # skip newlines after request because newlines at beginning of
	    # new request are allowed, stupid
	    $bytes += length($1);
	    goto READ_DATA;
	}

	$self->fatal('data from server w/o request',1,$time);
	$self->{error} = 1;
	return $bytes;
    }

    my $rq = $rqs->[-1];
    my $obj = $rq->{obj};

    # read response header if not done
    if ( not $rq->{state} & RPHDR_DONE ) {
	$DEBUG && $self->xdebug("response header not read yet");

	# leading newlines at beginning of response are legally ignored junk
	if ( $data =~s{\A([\r\n]+)}{} ) {
	    ($obj||$self)->in_junk(1,$1,0,$time);
	}

	# no response header yet, check if data contains it
	if ( $data =~s{\A(.*?\n\r?\n)}{}s ) {
	    my $hdr = $1;
	    my $n = length($hdr);
	    $bytes += $n;
	    $self->{offset}[1] += $n;

	    my %hdr;
	    my $err = parse_rsphdr($hdr, {
		method  => $rq->{method},
		upgrade => $rq->{upgrade},
		expect  => $rq->{expect},
	    }, \%hdr);

	    goto error if $err;
	    $DEBUG && $self->xdebug("got response header");

	    %TRACE && $hdr{junk} && ($obj||$self)->xtrace(
		"invalid request header data: $hdr{junk}");

	    if ($hdr{preliminary}) {
		# Preliminary response. Wait for read real response.
		$obj && $obj->in_response_header($hdr,$time,\%hdr);
		goto READ_DATA;
	    }

	    $rq->{state} |= RPHDR_DONE; # response header done

	    if ($hdr{upgrade}) {
		# Reset length to undef since we need to read until eof.
		$rq->{rpclen} = undef;
		$self->{upgrade} = $Upgrade2Sub{$hdr{upgrade}}($self,$obj)
		or do {
		    $err = "invalid or unsupported connection upgrade";
		    goto error;
		};
		goto done;
	    }

	    # Forget any $rq->{upgrade} since we did not get 101 response.
	    # This might be due to authorization required etc.
	    $rq->{upgrade} = undef;

	    my $body_done;
	    if ($hdr{chunked}) {
		$rq->{rpchunked} = 1;
	    } elsif (defined $hdr{content_length}) {
		if (($rq->{rpclen} = $hdr{content_length})) {
		    # content_length > 0, can do gaps
		    $self->{gap_upto}[1]= $self->{offset}[1]
			+ $hdr{content_length};
		} else {
		    $body_done = 1;
		}
	    } else {
		# no length given but method supports body -> end with eof
		$rq->{state} |= RPBDY_DONE_ON_EOF; # body done when eof
		$self->{gap_upto}[1] = -1;
	    }

	    done:
	    $obj && $obj->in_response_header($hdr,$time,\%hdr);
	    if ($body_done) {
		$DEBUG && $self->xdebug("no response body");
		pop(@$rqs);
		$obj && $obj->in_response_body('',1,$time);
	    }
	    goto READ_DATA;

	    error:
	    $self->{error} = 1;
	    ($obj||$self)->fatal($err,1,$time);
	    return $bytes;

	} elsif ( $data =~m{[^\n]\r?\n\r?\n}g ) {
	    ($obj||$self)->fatal( sprintf("invalid response header syntax '%s'",
		substr($data,0,pos($data))),1,$time);
	    $self->{error} = 1;
	    return $bytes;
	} elsif ( length($data) > $self->{hdr_maxsz}[1] ) {
	    ($obj||$self)->fatal('response header too big',1,$time);
	    $self->{error} = 1;
	    return $bytes;
	} elsif ( $eof ) {
	    ($obj||$self)->fatal('eof in response header',1,$time);
	    $self->{error} = 1;
	    return $bytes;
	} else {
	    # will be called on new data from upper flow
	    $DEBUG && $self->xdebug("need more data for response header");
	    return $bytes;
	}
    }

    # read response body
    if ( $data ne '' ) {
	# response body
	$DEBUG && $self->xdebug("response body data");

	# have content-length or within chunk
	if ( my $want = $rq->{rpclen} ) {
	    # called for content-length or to read content from chunk
	    # with known length
	    my $l = length($data);
	    if ( $l >= $want ) {
		$DEBUG && $self->xdebug("need $want bytes, got all($l)");
		# got all response body
		my $body = substr($data,0,$want,'');
		$self->{offset}[1] += $want;
		$bytes += $want;
		$rq->{rpclen} = 0;
		if ( ! $rq->{rpchunked} ) {
		    # request done
		    pop(@$rqs);
		    $obj && $obj->in_response_body($body,1,$time);
		} else {
		    $obj->in_response_body($body,0,$time) if $obj;
		    $rq->{rpchunked} = 2; # get CRLF after chunk
		}
	    } else {
		# only part
		$DEBUG && $self->xdebug("need $want bytes, got only $l");
		my $body = substr($data,0,$l,'');
		$self->{offset}[1] += $l;
		$bytes += $l;
		$rq->{rpclen} -= $l;
		$obj->in_response_body($body,0,$time) if $obj;
	    }

	# no content-length, no chunk: must read until eof
	} elsif ( $rq->{state} & RPBDY_DONE_ON_EOF ) {
	    $DEBUG && $self->xdebug("read until eof");
	    $self->{offset}[1] += length($data);
	    $bytes += length($data);
	    pop(@$rqs) if $eof; # request done
	    $obj->in_response_body($data,$eof,$time) if $obj;
	    $data = '';
	    return $bytes;

	# Chunking: rfc2616, 3.6.1
	} elsif ( ! $rq->{rpchunked} ) {
	    # should not happen
	    die "no content-length and no chunked - why we are here?";
	} else {
	    # [2] must get CRLF after chunk
	    if ( $rq->{rpchunked} == 2 ) {
		$DEBUG && $self->xdebug("want CRLF after chunk");
		if ( $data =~m{\A\r?\n}g ) {
		    my $n = pos($data);
		    $self->{offset}[1] += $n;
		    $bytes += $n;
		    substr($data,0,$n,'');
		    $rq->{rpchunked} = 1; # get next chunk header
		    $DEBUG && $self->xdebug("got CRLF after chunk");
		} elsif ( length($data)>=2 ) {
		    ($obj||$self)->fatal("no CRLF after chunk",1,$time);
		    $self->{error} = 1;
		    return $bytes;
		} else {
		    # need more
		    return $bytes;
		}
	    }

	    # [1] must read chunk header
	    if ( $rq->{rpchunked} == 1 ) {
		$DEBUG && $self->xdebug("want chunk header");
		if ( $data =~m{\A([\da-fA-F]+)[ \t]*(?:;.*)?\r?\n}g ) {
		    $rq->{rpclen} = hex($1);
		    my $chdr = substr($data,0,pos($data),'');
		    $self->{offset}[1] += length($chdr);
		    $bytes += length($chdr);
		    $self->{gap_upto}[1] = $self->{offset}[1] + $rq->{rpclen}
			if $rq->{rpclen};

		    $obj->in_chunk_header(1,$chdr,$time) if $obj;
		    $DEBUG && $self->xdebug(
			"got chunk header - want $rq->{rpclen} bytes");
		    if ( ! $rq->{rpclen} ) {
			# last chunk
			$rq->{rpchunked} = 3;
			$obj && $obj->in_response_body('',1,$time);
		    }
		} elsif ( $data =~m{\n} or length($data)>8192 ) {
		    ($obj||$self)->fatal("invalid chunk header",1,$time);
		    $self->{error} = 1;
		    return $bytes;
		} else {
		    # need more data
		    return $bytes;
		}
	    }

	    # [3] must read chunk trailer
	    if ( $rq->{rpchunked} == 3 ) {
		$DEBUG && $self->xdebug("want chunk trailer");
		if ( $data =~m{\A
		    (?:\w[\w\-]*:.*\r?\n(?:[\t\040].*\r?\n)* )*  # field:..+cont
		    \r?\n
		}xg) {
		    $DEBUG && $self->xdebug("got chunk trailer");
		    my $trailer = substr($data,0,pos($data),'');
		    $self->{offset}[1] += length($trailer);
		    $bytes += length($trailer);
		    $obj->in_chunk_trailer(1,$trailer,$time) if $obj;
		    pop(@$rqs); # request done
		} elsif ( $data =~m{\n\r?\n} or 
		    length($data)>$self->{hdr_maxsz}[2] ) {
		    ($obj||$self)->fatal("invalid chunk trailer",1,$time);
		    $self->{error} = 1;
		    return $bytes;
		} else {
		    # need more
		    $DEBUG && $self->xdebug("need more bytes for chunk trailer");
		    return $bytes
		}
	    }
	}
    }

    goto READ_DATA;
}

# parse and normalize header
sub parse_hdrfields {
    my ($hdr,$fields) = @_;
    return '' if ! defined $hdr;
    my $bad = '';
    parse:
    while ( $hdr =~m{\G$token_value_cont}gc ) {
	if ($3 eq '') {
	    # no continuation line
            push @{$fields->{ lc($1) }},$2;
	} else {
	    # with continuation line
            my ($k,$v) = ($1,$2.$3);
	    # <space>value-part<space> -> ' ' + value-part
	    $v =~s{[\r\n]+[ \t](.*?)[ \t]*}{ $1}g;
            push @{$fields->{ lc($k) }},$v;
	}
    }
    if (pos($hdr)//0 != length($hdr)) {
        # bad line inside
	substr($hdr,0,pos($hdr)//0,'');
        $bad .= $1 if $hdr =~s{\A([^\n]*)\n}{};
        goto parse;
    }
    return $bad;
}

sub parse_reqhdr {
    my ($data,$hdr,$external_length) = @_;
    $data =~m{\A
	([A-Z]{2,20})[\040\t]+          # $1: method
	(\S+)[\040\t]+                  # $2: path/URI
	HTTP/(1\.[01])[\40\t]*          # $3: version
	\r?\n                           # (CR)LF
	([^\r\n].*?\n)?                 # $4: fields
	\r?\n                           # final (CR)LF
    \Z}sx or return "invalid request header";

    my $version = $3;
    my $method  = $1;
    %$hdr = (
	method    => $method,
	url       => $2,
	version   => $version,
	info      => "$method $2 HTTP/$version",
	# fields  -  hash of fields
	# junk    -  bad header fields
	# expect  -  expectations from expect header
	# upgrade -  { websocket => key }
	# content_length
	# chunked
    );

    my %kv;
    my $bad = parse_hdrfields($4,\%kv);
    $hdr->{junk} = $bad if $bad ne '';
    $hdr->{fields} = \%kv;

    if ($version>=1.1 and $kv{expect}) {
	for(@{$kv{expect}}) {
	    # ignore all but 100-continue
	    $hdr->{expect}{lc($1)} = 1 if m{\b(100-continue)\b}i
	}
    }

    # RFC2616 4.4.3:
    # chunked transfer-encoding takes preferece before content-length
    if ( $version >= 1.1 and
	grep { m{(?:^|[ \t,])chunked(?:$|[ \t,;])}i }
	    @{ $kv{'transfer-encoding'} || [] }
    ) {
	$hdr->{chunked} = 1;

    } elsif ( my $cl = $kv{'content-length'} ) {
	return "multiple different content-length header in request"
	    if @$cl>1 and do { my %x; @x{@$cl} = (); keys(%x) } > 1;
	return "invalid content-length '$cl->[0]' in request"
	    if $cl->[0] !~m{^(\d+)$};
	$hdr->{content_length} = $cl->[0];
    }

    if ( $METHODS_WITHOUT_RQBODY{$method} ) {
	# Complain if the client announced a body.
	return "no body allowed with $method"
	    if $hdr->{content_length} or $hdr->{chunked};

    } elsif ( $METHODS_WITH_RQBODY{$method} ) {
	return "content-length or transfer-encoding chunked must be given with method $method"
	    if ! $hdr->{chunked}
	    and ! defined $hdr->{content_length}
	    and ! $external_length;

    } elsif ( ! $hdr->{chunked} ) {
	# if not given content-length is considered 0
	$hdr->{content_length} ||= 0;
    }

    # Connection upgrade - currently only Websocket is supported
    if ($version >= 1.1 and $kv{upgrade}
	and grep m{\bWebSocket\b}i,@{$kv{upgrade}}) {
	# Websocket: RFC6455, Sec.4.1 Page 16ff
	my $wskey = $kv{'sec-websocket-key'} || [];
	if (@$wskey > 1) {
	    my %x;
	    $wskey = [ map { $x{$_}++ ? ():($_) } @$wskey ];
	}
	my $v;
	if ( @$wskey == 1
	    and $method eq 'GET'
	    # RFC6455 requires Connection upgrade on client site,
	    # while for RFC7230 it should be enough on server side.
	    and $v = $kv{connection} and grep m{\bUPGRADE\b}i, @$v
	    and $v = $kv{upgrade} and grep m{\bWebSocket\b}i, @$v
	    and $v = $kv{'sec-websocket-version'}
	    and ! grep { $_ ne '13' } @$v
	) {
	    $hdr->{upgrade} = { websocket => $wskey->[0] };
	} else {
	    return "invalid websocket upgrade request";
	}
    }
    return; # no error
}

sub parse_rsphdr {
    my ($data,$request,$hdr) = @_;
    $data =~ m{\A
	HTTP/(1\.[01])[\040\t]+          # $1: version
	(\d\d\d)                         # $2: code
	(?:[\040\t]+([^\r\n]*))?         # $3: reason
	\r?\n
	([^\r\n].*?\n)?                  # $4: fields
	\r?\n                            # empty line
    \Z}sx or return "invalid response header";

    my $version = $1;
    my $code = $2;
    %$hdr = (
	version   => $version,
	code      => $code,
	reason    => $3,
	# fields
	# junk
	# content_length
	# chunked
	# upgrade
	# preliminary
    );

    my %kv;
    my $bad = parse_hdrfields($4,\%kv);
    $hdr->{fields} = \%kv;
    $hdr->{junk} = $bad if $bad ne '';

    if ($code == 100 and $request->{expect}{'100-continue'}
	or $code == 102) {
	# Preliminary responses do not contain any body.
	# 100 should only happen with Expect: 100-continue from client
	$hdr->{preliminary} = 1;
	$hdr->{content_length} = 0;
    } elsif ($code != 101 and $code <= 199) {
	return "unexpected status code $code";
    }

    # Switching Protocols
    # Any upgrade must have both a "Connection: upgrade" and a
    # "Upgrade: newprotocol" header.
    if ($code == 101) {
	my %proto;
	if ($request->{upgrade}
	    and grep { m{\bUPGRADE\b}i } @{$kv{connection} || []}) {
	    for(@{$kv{upgrade} || []}) {
		$proto{lc($_)} = 1 for split(m{\s*[,;]\s*});
	    }
	}

	# Currently only Websocket is supported.
	if (keys(%proto) == 1
	    and $proto{websocket}
	    and my $wsk = $request->{upgrade}{websocket}
	    and my $wsa = $kv{'sec-websocket-accept'}) {
	    if ($wsa && @$wsa != 1) {
		my %x;
		$wsa = [ map { $x{$_}++ ? ():($_) } @$wsa ];
	    }
	    # beware its magic! see RFC6455 page 7
	    # sha1_base64 does no padding, so we need to add a single
	    # '=' (pad to 4*7 byte) at the end for comparison
	    if ( @$wsa != 1 or $wsa->[0] ne sha1_base64(
		$wsk.'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').'=') {
		return "invalid websocket upgrade response";
	    }
	    $hdr->{upgrade} = 'websocket';
	    return;

	} else {
	    return "invalid or unsupported connection upgrade";
	}
    }

    # successful response to CONNECT
    if ($request->{method} eq 'CONNECT' and $code >= 200 and $code < 300) {
	$hdr->{upgrade} = 'CONNECT';
	return;
    }

    # RFC2616 4.4.3:
    # chunked transfer-encoding takes preferece before content-length
    if ( $version >= 1.1 and
	grep { m{(?:^|[ \t,])chunked(?:$|[ \t,;])}i }
	    @{ $kv{'transfer-encoding'} || [] }
    ) {
	$hdr->{chunked} = 1;

    } elsif ( my $cl = $kv{'content-length'} ) {
	return "multiple different content-length header in response"
	    if @$cl>1 and do { my %x; @x{@$cl} = (); keys(%x) } > 1;
	return "invalid content-length '$cl->[0]' in response"
	    if $cl->[0] !~m{^(\d+)$};
	$hdr->{content_length} = $cl->[0];
    }

    if ($CODE_WITHOUT_RPBODY{$code}
	or $METHODS_WITHOUT_RPBODY{$request->{method}}) {
	# no content, even if specified
	$hdr->{content_length} = 0;
	delete $hdr->{chunked};
	return;
    }

    return;
}


sub new_request {
    my $self = shift;
    return $self->{upper_flow}->new_request(@_,$self)
}

# return open requests
sub open_requests {
    my $self = shift;
    my @rq = @_ ? @{$self->{requests}}[@_] : @{$self->{requests}};
    return wantarray 
	? map { $_->{obj} ? ($_->{obj}):() } @rq
	: 0 + @rq;
}

sub fatal {
    my ($self,$reason,$dir,$time) = @_;
    %TRACE && $self->xtrace($reason);
}

sub xtrace {
    my $self = shift;
    my $msg = shift;
    $msg = "$$.$self->{connid} $msg";
    unshift @_,$msg;
    goto &trace;
}

sub xdebug {
    $DEBUG or return;
    my $self = shift;
    my $msg = shift;
    $msg = "$$.$self->{connid} $msg";
    unshift @_,$msg;
    goto &debug;
}

sub dump_state {
    $DEBUG or defined wantarray or return;
    my $self = shift;
    my $m = $self->{meta};
    my $msg = sprintf("%s.%d -> %s.%d ",
	$m->{saddr},$m->{sport},$m->{daddr},$m->{dport});
    my $rqs = $self->{requests};
    for( my $i=0;$i<@$rqs;$i++) {
	$msg .= sprintf("request#$i state=%05b %s",
	    $rqs->[$i]{state},$rqs->[$i]{info});
    }
    return $msg if defined wantarray;
    $self->xdebug($msg);
}

sub upgrade_CONNECT {
    my ($self,$obj) = @_;
    my @sub;
    if ($obj) {
	weaken($obj);
	for my $dir (0,1) {
	    my $dir = $dir; # old $dir was alias only
	    $sub[$dir] = sub {
		my ($data,$eof,$time) = @_;
		$obj->in_data($dir,$data,$eof,$time);
		return ref($data) ? $data->[1] : length($data)
	    }
	};
    } else {
	$sub[0] = $sub[1] = sub {
	    my $data = shift;
	    return ref($data) ? $data->[1] : length($data)
	};
    }
    @{$self->{gap_upto}} = (-1,-1);
    return \@sub;
}

sub upgrade_websocket {
    my ($self,$obj) = @_;
    goto &upgrade_CONNECT if !$obj || !$obj->can('in_wsdata');

    weaken($obj);
    weaken($self);

    my @sub;
    for my $dir (0,1) {
	my $dir = $dir; # old $dir is only alias
	my $rbuf = '';

	# If $clen is defined we are inside a frame ($current_frame).
	# If $clen is not defined all other variables here do not matter.
	# Since control messages might be in-between fragmented data messages we
	# need to keep this information for an open data message.
	my ($clen,$clenhi,$current_frame,$data_frame,$ctl_frame,$got_close);

	$sub[$dir] = sub {
	    my ($data,$eof,$time) = @_;
	    my $err;

	    # Handle data gaps. These are only allowed inside data frames.
	    ############################################################
	    if (ref($data)) {
		croak "unknown type $data->[0]" if $data->[0] ne 'gap';
		my $gap = $data->[1];
		if (!defined $clen) {
		    $err = "gap outside websocket frame";
		    goto bad;
		}
		if (!$data_frame || $current_frame != $data_frame) {
		    $err = "gap inside control frame";
		    goto bad;
		}
		my $eom = 0; # end of message on end-of-frame + FIN frame
		while ($gap>0) {
		    if ($clen == 0) {
			if (!$clenhi) {
			    $err = "gap larger than frame size";
			    goto bad;
			}
			$clenhi--;
			$clen = 0xffffffff;
			$gap--;
			$current_frame->{mask_offset}
			    = (($current_frame->{mask_offset}||0) + 1) % 4;

		    } elsif ($gap > $clen) {
			$gap -= $clen;
			$current_frame->{mask_offset}
			    = (($current_frame->{mask_offset}||0) + $clen) % 4;
			$clen = 0;
		    } else { # $gap <= $clen
			$clen -= $gap;
			$current_frame->{mask_offset}
			    = (($current_frame->{mask_offset}||0) + $gap) % 4;
			$gap = 0;
		    }
		}
		if (!$clen && !$clenhi) {
		    # frame done
		    $eom = $data_frame->{fin} ? 1:0;
		    $clen = undef;
		}

		if (defined $clen) {
		    $data_frame->{bytes_left} = [$clenhi,$clen];
		} else {
		    delete $data_frame->{bytes_left};
		}
		$obj->in_wsdata($dir,$data,$eom,$time,$data_frame);
		if ($eom) {
		    $data_frame = $current_frame = undef;
		    $self->{gap_upto}[$dir] = 0;
		} else {
		    delete $data_frame->{init};
		    delete $data_frame->{header};
		}
		return;
	    }

	    $rbuf .= $data;

	    PARSE_DATA:

	    # data for existing frame
	    ############################################################
	    if (defined $clen) {
		my $size = length($rbuf);
		if (!$size and $clen || $clenhi) {
		    goto done if ! $eof;
		    $err = "eof inside websocket frame";
		    goto bad;
		}
		my $fwd = '';
		my $eom = 0;
		while ($size>0) {
		    if ($clen == 0) {
			last if !$clenhi;
			$clenhi--;
			$clen = 0xffffffff;
			$size--;
			$fwd .= substr($rbuf,0,1,'');
		    } elsif ($size > $clen) {
			$size -= $clen;
			$fwd .= substr($rbuf,0,$clen,'');
			$clen = 0;
		    } else {  # $size < $clen
			$clen -= $size;
			$size = 0;
			$fwd .= $rbuf;
			$rbuf = '';
		    }
		}
		if (!$clen && !$clenhi) {
		    # frame done
		    $eom = $current_frame->{fin} ? 1:0;
		    $clen = undef;
		}
		if ($data_frame && $current_frame == $data_frame) {
		    if (defined $clen) {
			$data_frame->{bytes_left} = [$clenhi,$clen];
		    } else {
			delete $data_frame->{bytes_left};
		    }
		    $obj->in_wsdata($dir,$fwd,$eom,$time,$data_frame);
		    if ($eom) {
			$data_frame = undef;
		    } else {
			delete $data_frame->{init};
			delete $data_frame->{header};
			$current_frame->{mask_offset}
			    = (($current_frame->{mask_offset}||0) + length($fwd)) % 4
			    if defined $clen;
		    }
		} else {
		    die "expected to read full control frame" if defined $clen;
		    if ($current_frame->{opcode} == 0x8) {
			# extract status + reason for close
			if ($fwd eq '') {
			    $current_frame->{status} = 1005; # RFC6455, 7.1.5
			} elsif (length($fwd) < 2) {
			    # if payload it must be at least 2 byte for status
			    $err = "invalid length for close control frame";
			    goto bad;
			} else {
			    ($current_frame->{status},$current_frame->{reason})
				= unpack("na*",$current_frame->unmask($fwd));
			}
		    }
		    $obj->in_wsctl($dir,$fwd,$time,$current_frame);
		}
		goto done if !$size;
		goto PARSE_DATA;
	    }

	    # start of new frame: read frame header
	    ############################################################
	    goto hdr_need_more if length($rbuf)<2;

	    (my $flags,$clen) = unpack("CC",$rbuf);
	    my $mask = $clen & 0x80;
	    $clen &= 0x7f;
	    $clenhi = 0;
	    my $off = 2;

	    if ($clen == 126) {
		goto hdr_need_more if length($rbuf)<4;
		($clen) = unpack("xxn",$rbuf);
		goto bad_length if $clen<126;
		$off = 4;
	    } elsif ($clen == 127) {
		goto hdr_need_more if length($rbuf)<10;
		($clenhi,$clen) = unpack("xxNN",$rbuf);
		goto bad_length if !$clenhi && $clen<2**16;
		$off = 10;
	    }
	    if ($mask) {
		goto hdr_need_more if length($rbuf)<$off+4;
		($mask) = unpack("x${off}a4",$rbuf);
		$off+=4;
	    } else {
		$mask = undef;
	    }

	    my $opcode = $flags & 0b00001111;
	    my $fin    = $flags & 0b10000000;
	    goto reserved_flag if $flags & 0b01110000;

	    if ($opcode >= 0x8) {
		# control frame
		goto reserved_opcode if $opcode >= 0xb;
		if (!$fin) {
		    $err = "fragmented control frames are forbidden";
		    goto bad;
		}
		if ($clenhi || $clen>125) {
		    $err = "control frames should be <= 125 bytes";
		    goto bad;
		}
		# We like to forward control frames as a single entity, so make
		# sure we get the whole (small) frame at once.
		goto hdr_need_more if $off+$clen > length($rbuf);

		$current_frame = $ctl_frame
		    ||= Net::Inspect::L7::HTTP::_WSFrame->new;
		%$current_frame = (
		    opcode => $opcode,
		    defined($mask) ? ( mask => $mask ):()
		);
		$got_close = 1 if $opcode == 0x8;

	    } elsif ($opcode>0) {
		# data frame, but no continuation
		goto reserved_opcode if $opcode >= 0x3;
		if ($got_close) {
		    $err = "data frame after close";
		    goto bad;
		}
		$current_frame = $data_frame
		    ||= Net::Inspect::L7::HTTP::_WSFrame->new;
		%$current_frame = (
		    opcode => $opcode,
		    $fin ? ( fin => 1 ):(),
		    init => 1,  # initial data
		    defined($mask) ? ( mask => $mask ):()
		);

	    } else {
		# continuation frame
		if (!$data_frame) {
		    $err = "continuation frame without previous data frame";
		    goto bad;
		}
		$current_frame = $data_frame;
		%$current_frame = (
		    opcode => $data_frame->{opcode},
		    $fin ? ( fin => 1 ):(),
		    defined($mask) ? ( mask => $mask ):()
		);
	    }

	    # done with frame header
	    $current_frame->{header} = substr($rbuf,0,$off,'');
	    goto PARSE_DATA;

	    # Done
	    ############################################################

	    hdr_need_more:
	    $clen = undef; # re-read from start if frame next time

	    done:
	    if (defined $clen) {
		# Processed all inside rbuf we want more (data frame)
		$self->{gap_upto}[$dir] = $self->{offset}[$dir] + (
		    ! $clenhi ? $clen :           # len <=32 bit
		    1 << 32 == 1 ? 0xffffffff :   # platform 32bit only
		    ($clenhi << 32) + $clen       # full 64 bit
		);
	    }
	    if ($eof) {
		# forward eof as special wsctl with no frame
		$obj->in_wsctl($dir,'',$time);
	    }
	    return;

	    bad_length:
	    $err ||= "non-minimal length representation in websocket frame";
	    reserved_flag:
	    $err ||= "extensions using reserved flags are not supported";
	    reserved_opcode:
	    $err ||= "no support for opcode $opcode";

	    bad:
	    $self->{error} = 1;
	    $obj->fatal($err,$dir,$time);
	    return;
	};
    }
    return \@sub;
}

{
    package Net::Inspect::L7::HTTP::_WSFrame;
    sub new { bless {}, shift };
    sub unmask {
	my ($self,$data) = @_;
	return $data if $data eq '' or ! $self->{mask};
	my $l = length($data);
	$data ^= substr($self->{mask} x int($l/4+2),$self->{mask_offset}||0,$l);
	return $data;
    };
}


1;

__END__

=head1 NAME

Net::Inspect::L7::HTTP - guesses and handles HTTP traffic

=head1 SYNOPSIS

 my $req = Net::Inspect::L7::HTTP::Request::Simple->new(..);
 my $http = Net::Inspect::L7::HTTP->new($req);
 my $guess = Net::Inspect::L5::GuessProtocol->new;
 $guess->attach($http);
 ...

=head1 DESCRIPTION

This class extracts HTTP requests from TCP connections.
It provides all hooks required for C<Net::Inspect::L4::TCP> and is usually used
together with it.
It provides the C<guess_protocol> hook so it can be used with
C<Net::Inspect::L5::GuessProtocol>.

Attached flow is usually a C<Net::Inspect::L7::HTTP::Request::*> object.

Hooks provided:

=over 4

=item guess_protocol($guess,$dir,$data,$eof,$time,$meta)

=item new_connection($meta,%args) 

This returns an object for the connection.
With C<$args{header_maxsize}> the maximum size of the message headers can be
given, that is:

  $args{header_maxsize}[0] - request header, default 64k
  $args{header_maxsize}[1] - response header, default 16k
  $args{header_maxsize}[2] - chunked header, default 2k

=item $connection->in($dir,$data,$eof,$time)

Processes new data and returns number of bytes processed.
Any data not processed must be sent again with the next call.

C<$data> are the data as string.
In some cases $data can be C<< [ 'gap' => $len ] >>, e.g. only the information,
that there would be C<$len> bytes of data w/o submitting the data. These
should only be submitted in request and response bodies and only if the 
attached layer can handle these gaps in the C<in_request_body> and 
C<in_response_body> methods. 

Gaps on other places are not allowed, because all other data are needed 
for interpreting the placement of request, response and data inside the
connection.

=item $connection->fatal($reason,$dir,$time)

=back

Hooks called:

=over 4

=item new_request(\%meta,$conn)

This should return an request object. The reference to the connection object is
given in case the request object likes to call C<fatal> to end the connection.

The function should not get hold of $conn, e.g. only store a weak reference,
otherwise memory might leak.

=item $request->in_request_header($header,$time,\%hdr_meta)

Called when the full request header is read.
$header is the string of the header.

%hdr_meta contains information extracted from the header:

=over 8

=item method - method of request

=item url - url, as given in request

=item version - version of HTTP spoken in request

=item info - first line of request (method url version)

=item fields - (key => \@values) hash of header fields

=item junk - invalid data found in header fields part

=item content_length - length of request body

=item chunked - true if body uses transfer encoding chunked

=item upgrade - contains hash when protocol upgrade was requested

Currently this hash contains the key C<websocket> with the value of the
C<sec-websocket-key> if a valid request for a Websocket upgrade was detected.

=item expect - contains hash for expectations from Expect header

Currently the only possible key is C<100-continue>.

=back


=item $request->in_response_header($header,$time,\%hdr_meta)

Called when the full response header is read.
$header is the string of the header.

%hdr_meta contains information extracted from the header:

=over 8

=item version - version of HTTP spoken in response

=item code - status code from response

=item reason - reason given for response code

=item fields - (key => \@values) hash of header fields

=item junk - invalid data found in header fields part

=item content_length - length of request body if known, else undef

=item chunked - true if body uses transfer encoding chunked

=item upgrade - new protocol when switching protocols, e.g. 'websocket'

=item preliminary - true if this is a preliminary response

=back

=item $request->in_request_body($data,$eobody,$time)

Called for a chunk of data of the request body.
$eobody is true if this is the last chunk of the request body.
If the request body is empty the method will be called once with C<''>.
If no body exists because of CONNECT or HTTP Upgrade C<in_data> or the websocket
functions will be called, not C<in_request_body>.

$data can be C<< [ 'gap' => $len ] >> if the input to this
layer were gaps.

=item $request->in_response_body($data,$eobody,$time)

Called for a chunk of data of the response body.
$eof is true if this is the last chunk of the connection.
$eobody is true if this is the last chunk of the response body.
If the response body is empty the method will be called once with C<''>.
If no body exists because of CONNECT or HTTP Upgrade C<in_data> or the websocket
functions will be called, not C<in_response_body>.

$data can be C<< [ 'gap' => $len ] >> if the input to this
layer were gaps.

=item $request->in_chunk_header($dir,$header,$time)

will be called with the chunk header for chunked encoding.
Usually one is not interested in the chunk framing, only in the content so that
this method will be empty.
Will be called before the chunk data.

=item $request->in_chunk_trailer($dir,$trailer,$time)

will be called with the chunk trailer for chunked encoding.
Usually one is not interested in the chunk framing, only in the content so that
this method will be empty.
Will be called after in_response_body/in_request_body got called with eof true.

=item $request->in_data($dir,$data,$eof,$time)

Will be called for any data after successful CONNECT or Upgrade.
If no websocket functions are defined in the request object it will also be used
for Websockets.
C<$dir> is 0 for data from client, 1 for data from server.

=item $request->in_wsctl($dir,$data,$time,$frameinfo)

This will be called after a Websocket upgrade when receiving a control frame.
C<$dir> is 0 for data from client, 1 for data from server.
C<$data> is the unmasked payload of the frame.
C<$frameinfo> is a blessed hash reference which contains the C<opcode> of the
frame, the C<mask> (binary) and C<header> for the frame header.
For a close frame it will also contain the extracted C<status> code and the
C<reason>.

To get the unmasked payload call C<< $frameinfo->unmask($masked_data) >>.

C<in_wsctl> will be called on connection close with C<$data> of C<''> and no
C<\%frameinfo> (i.e. no hash reference).

=item $request->in_wsdata($dir,$data,$eom,$time,$frameinfo)

This will be called after a Websocket upgrade when receiving data inside a data
frame. Contrary to (the short) control frames the data frame must not be read
fully before calling C<in_wsdata>.

C<$dir> is 0 for data from client, 1 for data from server.
C<$data> is the unmasked payload of the frame.
C<$eom> is true if the message is done with this call, that is if the data frame
is done and the FIN bit was set on the frame.
C<$frameinfo> is a blessed hash reference which contains the data type as
C<opcode>. This will be the original opcode of the starting frame in case of
fragmented transfer. It will also contain the C<mask> (binary) of the current
frame. 

If this is the initial part of the data (i.e. initial frame in possibly
fragmented data and initial data inside this frame) it will also have C<init>
set to true inside C<$frameinfo>.

If there are still unread data within the frame C<$frameinfo> will contain
C<bytes_left> as C<<[hi,low]>> where C<hi> and C<low> are the upper and lower
32 bit parts of the number of outstanding bytes.

If this call to C<in_wsdata> was caused by the start of a new frame and not
further data in the same frame C<header> will be set to the header of this new
frame. In all other cases C<header> is not set.

To get the unmasked payload call C<< $frameinfo->unmask($masked_data) >>.

=item $request->in_junk($dir,$data,$eof,$time)

Will be called for legally ignored junk (empty lines) in front of request or 
response body.  C<$dir> is 0 for data from client, 1 for data from server.

=item $request->fatal($reason,$dir,$time)

will be called on fatal errors, mostly protocol iregularities.

=back

Methods suitable for overwriting:

=over 4

=item new_request(\%meta)

default implementation will just call new_request from the attached flow

=back

Helpful methods

=over 4

=item $connection->dump_state

collects the state of the open connections.
If defined wantarray it will return a message, otherwise output it via xdebug

=item $connection->offset(@dir)

returns the current offset(s) in the data stream, that is the position
behind the within the in_* methods forwarded data.

=item $connection->gap_offset(@dir)

If the next bytes of the input stream are not needed to interpret the HTTP
protocol (i.e. plain body data) this gives the offsets up to which data are
"gapable". If no gaps are possible at the current state C<0> will be returned.
If everything can be gaps (usually because end of body is caused by end of
connection) C<-1> will be returned.

=item $connection->gap_diff(@dir)

This is similar to C<gap_offset> but will return the difference from the current
position, i.e. how large the next gap can be. C<-1> again means an unlimited
gap.

=item $connection->open_requests(@index)

in array context returns the objects for the open requests, in scalar
context the number of open requests.
If index is given only the specified objects will be returned, e.g.
index -1 is the object currently receiving response data while index 0
specifies the object currently receiving request data (both are the
same unless pipelining is used)

=back

=head1 exportable utility functions and constants

=over 4

=item METHODS_WITHOUT_RQBODY

This constant is an array reference of all request methods which will not have a
request body, i.e. which have an implicit and non-changeble content-length of 0.

=item METHODS_WITH_RQBODY

This constant is an array reference of all request methods which must have a
specified request body, even if the content-lenth is explicitly set to 0.

Methods which are not in METHODS_WITH_RQBODY or METHODS_WITHOUT_RQBODY might
have a request body, that is if no content-length is explicitly given (or
chunked transfer encoding is used) it is assumed that they don't have a body.

=item METHODS_WITHOUT_RPBODY

This constant is an array reference of all request methods which don't require a
response body, i.e. which have an implicit and non-changeble content-length of 0.

=item CODE_WITHOUT_RPBODY

This constant is an array reference of all response codes which will not have a
response body, i.e. which have an implicit and non-changeble content-length of 0.

=item parse_hdrfields($header,\%fields) -> $bad_lines

This function parses the given message header (without request or status line!)
and extracts the C<key:value> pairs into C<%fields>. Each key in C<%fields> is
the lower-case representation of the key from the HTTP message and the value in
C<%fields> is a list with all values, i.e. a list with a single element if the
specific key was only used once the header, but with multiple elements if the
key was used multiple times.
Any continuation lines will be transformed into a single line.

It will return any remaining data in C<$header> which could not be interpreted
as proper C<key:value> pairs. If the message contains no errors it will thus
return C<''>.

=item parse_reqhdr($string,\%header,[$external_length]) -> $bad_header

This will parse the given C<$string> as a request header and extract information
into \%header. These information then later will be given to
C<in_request_header>. See there for more details about the contents of the hash.

If C<$external_length> is true it will not complain if a content-length is
required but not defined.

=item parse_rsphdr($string,\%request,\%header) -> $bad_header

This will parse the given C<$string> as a response header and extract
information into \%header. These information then later will be given to
C<in_request_header>. See there for more details about the contents of the
hash.

C<%request> contains information about the request. One might simple use the
hash filled by C<parse_reqhdr> here. If not at least the information about
C<method>, C<expect> and C<upgrade> must be provided because they are needed to
interpret the response correctly.

=back

=head1 LIMITS

C<100 Continue>, C<101 Upgrade> are not yet implemented.
