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
use Carp 'croak';
use fields (
    'replay',   # collected and replayed in guess_protocol
    'meta',     # meta data from connection
    'requests', # list of open requests, see _in0 for fields
    'error',    # connection has error like server sending data w/o request
    'upgrade',  # true if got upgrade, CONNECT, WebSockets..
    'connid',   # connection id
    'lastreqid',# id of last request
    'offset',   # offset in data stream 
);


use constant {
    RQHDR_DONE => 0b00001,
    RQBDY_DONE => 0b00010,
    RQ_ERROR   => 0b00100,
    RPHDR_DONE => 0b01000,
    RPBDY_DONE => 0b10000, # will be done on EOF
};

# rfc2616, 3.6
#  token          = 1*<any CHAR except CTLs or separators>
#  separators     = "(" | ")" | "<" | ">" | "@"
#                 | "," | ";" | ":" | "\" | <">
#                 | "/" | "[" | "]" | "?" | "="
#                 | "{" | "}" | SP | HT

my $token = qr{[^()<>@,;:\\"/\[\]?={}\x00-\x20\x7f-\xff]+};
my $token_value_cont = qr{
    ($token):                      # key:
    [\040\t]*([^\r\n]*?)[\040\t]*  # <space>value<space>
    ((?:\r?\n[\040\t][^\r\n]*)*)   # continuation lines
    \r?\n                          # (CR)LF
}x;

# common error: "Last Modified" instead of "Last-Modified"
# squid seems to just strip invalid headers, try the same
my $xtoken = qr{[^()<>@,;:\\"/\[\]?={}\x00-\x20\x7f-\xff][^:[:^print:]]*};

my %METHODS_WITHOUT_RQBODY = map { ($_,1) } qw( GET HEAD DELETE CONNECT );
my %METHODS_WITH_RQBODY = map { ($_,1) } qw( POST PUT );
my %CODE_WITHOUT_RPBODY = map { ($_,1) } (100..199, 204, 205, 304);
my %METHODS_WITHOUT_RPBODY = map { ($_,1) } qw(HEAD);

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
    sub new_connection {
	my ($self,$meta) = @_;
	my $obj = $self->new;
	$obj->{meta} = $meta;
	$obj->{requests} = [];
	$obj->{connid} = ++$connid;
	$obj->{lastreqid} = 0;
	$obj->{offset} = [0,0];
	return $obj;
    }
}

sub in {
    my ($self,$dir,$data,$eof,$time) = @_;
    $DEBUG && $self->xdebug("got %d bytes from %d, eof=%d",length($data),$dir,$eof//0);
    my $bytes = $dir == 0
	? _in0($self,$data,$eof,$time)
	: _in1($self,$data,$eof,$time);
    #$self->dump_state if $DEBUG;
    return $bytes;
}

sub offset {
    my ($self,$dir) = @_;
    return $self->{offset}[$dir];
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
	croak 'upgraded connections do not support gaps' if $self->{upgrade};

	my $rqs = $self->{requests};
	croak 'no open request' if ! @$rqs or $rqs->[0]{state} & RQBDY_DONE;
	croak 'existing error in request' if $rqs->[0]{state} & RQ_ERROR;
	croak "gap wider than request body" if $rqs->[0]{rqclen} < $len;
	if ( my $obj = $rqs->[0]{obj} ) {
	    $obj->in_request_body([ gap => $len ],$eof,$time);
	}
	$rqs->[0]{rqclen} -= $len;
	if ( ! $rqs->[0]{rqclen} && ! $rqs->[0]{rqchunked} ) {
	    $rqs->[0]{state} |= RQBDY_DONE;
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
	if ( my $obj = $rqs->[0]{obj} ) {
	    $obj->in_data(0,$data,$eof,$time);
	}
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
	    rpclen   => undef,   # open content-length respone
	    # chunked mode for request|response:
	    #   false - no chunking
	    #   1,r[qp]clen == 0 - next will be chunk size
	    #   1,r[qp]clen > 0  - inside chunk data, need *clen
	    #   2 - next will be chunk
	    #   3 - after last chunk, next will be chunk trailer
	    rqchunked => undef,  # chunked mode for request
	    rpchunked => undef,  # chunked mode for response
	    method   => undef,   # request method
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
	    ($obj|$self)->in_junk(0,$1,0,$time);
	}

	$DEBUG && $self->xdebug("need to read request header");
	if ( $data =~s{( \A
	    ([A-Z]{2,20})[\040\t]+          # method
	    (\S+)[\040\t]+                  # path/URI
	    HTTP/(1\.[01])[\40\t]*          # version
	    \r?\n                           # (CR)LF
	    ([^\r\n].*?\n)?                 # fields
	    \r?\n                           # final (CR)LF
	)}{}sxi ) {
	    my $hdr = $1;
	    $rq->{method} = uc($2);
	    my $url = $3;
	    my $version = $4;
	    $rq->{info} = "\U$2\E $3 HTTP/$4";
	    $DEBUG && $self->xdebug("got request header $rq->{info}");

	    my %kv;
	    my $bad = _parse_hdrfields($5,\%kv);
	    %TRACE && ($obj||$self)->xtrace("invalid request header data: $bad") 
		if $bad ne '';

	    my $n = length($hdr);
	    $self->{offset}[0] += $n;
	    $bytes += $n;
	    $rq->{state} |= RQHDR_DONE; # rqhdr done

	    if ( my $cl = $kv{'content-length'} ) {
		if ( @$cl>1 and do { my %x; @x{@$cl} = (); keys(%x) } > 1 ) {
		    ($obj||$self)->fatal(
			"multiple different content-length header in request",
			0,$time);
		    $rq->{state} |= RQ_ERROR;
		    return $bytes;
		}
		$rq->{rqclen} = $cl->[0];
		$DEBUG && $self->xdebug(
		    "set content-length to $rq->{rqclen} from header");
	    }

	    if ( $version >= 1.1 and 
		grep { lc($_) eq 'chunked' } @{ $kv{'transfer-encoding'} || [] } ) {
		$rq->{rqchunked} = 1;
		if ( defined $rq->{rqclen} ) {
		    # RFC2616 4.4.3: if both given ignore content-length
		    %TRACE && ($obj||$self)->xtrace(
			"request content-length and chunked given");
		    $rq->{rqclen} = undef;
		}
	    }

	    if ( $METHODS_WITHOUT_RQBODY{ $rq->{method} } ) {
		if ( $rq->{rqclen} ) {
		    ($obj||$self)->fatal(
			"no body allowed with method $rq->{method}",0,$time);
		    $rq->{state} |= RQ_ERROR;
		    return $bytes;
		}
		$rq->{rqclen} = ( $rq->{method} eq 'CONNECT' ) ? undef : 0;
		$rq->{rqchunked} = undef;
	    } elsif ( $METHODS_WITH_RQBODY{ $rq->{method} } ) {
		if ( ! defined $rq->{rqclen} && ! $rq->{rqchunked} ) {
		    ($obj||$self)->fatal(
			"content-length or transfer-encoding chunked must be given with method $rq->{method}",
			0,$time);
		    $rq->{state} |= RQ_ERROR;
		    return $bytes;
		}
	    } elsif ( ! $rq->{rqchunked} ) {
		# if not given content-length is considered 0
		$rq->{rqclen} ||= 0;
	    }

	    $obj && $obj->in_request_header($hdr,$time, { 
		content_length => $rq->{rqclen},
		$rq->{rqchunked} ? ( chunked => 1 ):(),
		method => $rq->{method},
		url => $url,
		version => $version,
		fields => \%kv,
		$bad eq '' ? () : ( junk => $bad ),
	    });

	    if ( ! $rq->{rqchunked} and 
		defined $rq->{rqclen} and $rq->{rqclen} == 0 ) {
		$DEBUG && $self->xdebug("no content-length - request body done");
		# no clen - body done
		$rq->{state} |= RQBDY_DONE;
		$obj && $obj->in_request_body('',1,$time);
	    }

	} elsif ( $data =~m{[^\n]\r?\n\r?\n}g ) {
	    ($obj||$self)->fatal( sprintf("invalid request header syntax '%s'",
		substr($data,0,pos($data))),0,$time);
	    $rq->{state} |= RQ_ERROR;
	    return $bytes;
	} elsif ( length($data) > 2**16 ) {
	    ($obj||$self)->fatal('request header too big',0,$time);
	    $rq->{state} |= RQ_ERROR;
	    return $bytes;
	} elsif ( $eof ) {
	    ($obj||$self)->fatal('eof in request header',0,$time);
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
		    $obj && $obj->in_request_body($body,1,$time) if $obj;
		} else {
		    $obj && $obj->in_request_body($body,0,$time) if $obj;
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
		    $obj->in_chunk_header(0,$chdr,$time) if $obj;
		    $DEBUG && $self->xdebug(
			"got chunk header - want $rq->{rqclen} bytes");
		    if ( ! $rq->{rqclen} ) {
			# last chunk
			$rq->{rqchunked} = 3;
			$obj->in_request_body('',1,$time) if $obj;
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
		    $self->{offset}[1] += length($trailer);
		    $bytes += length($trailer);
		    $obj->in_chunk_trailer(0,$trailer,$time) if $obj;
		    $rq->{state} |= RQBDY_DONE; # request done
		} elsif ( $data =~m{\n\r?\n} or length($data)>2**16 ) {
		    ($obj||$self)->fatal("invalid chunk trailer",0,$time);
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
	croak 'upgraded connections do not support gaps' if $self->{upgrade};

	my $rqs = $self->{requests};
	croak 'no open response' if ! @$rqs;
	croak 'existing error in request' if $rqs->[-1]{state} & RQ_ERROR;
	if ( ! defined $rqs->[-1]{rpclen} ) {
	    croak "not in body-til-eof"  if not $rqs->[-1]{state} & RPBDY_DONE;
	} elsif ( $rqs->[-1]{rpclen} < $len ) {
	    croak "gap ($len) wider than response body (chunk) $rqs->[-1]{rpclen}";
	} elsif ( my $obj = $rqs->[-1]{obj} ) {
	    $obj->in_response_body([ gap => $len ],$eof,$time);
	}
	$rqs->[-1]{rpclen} -= $len;
	if ( ! $rqs->[-1]{rpclen} && ! $rqs->[-1]{rpchunked} ) {
	    $rqs->[-1]{state} |= RPBDY_DONE;
	}
	return $len;
    }


    READ_DATA:

    return $bytes if $self->{error};

    if ($self->{upgrade}) {
	$self->{offset}[1] += length($data);
	if ( my $obj = $rqs->[0]{obj} ) {
	    $obj->in_data(1,$data,$eof,$time);
	}
	return $bytes + length($data);
    }

    if ( $data eq '' ) {
	$DEBUG && $self->xdebug("no more data, eof=$eof bytes=$bytes");
	return $bytes if ! $eof; # need more data

	# handle EOF
	# check if we got response body for last request
	if ( @$rqs && $rqs->[-1]{state} & RPBDY_DONE ) {
	    # response body done on eof
	    $rqs->[-1]{obj}->in_response_body('',1,$time) if $rqs->[-1]{obj};
	    pop(@$rqs);
	    return $bytes;
	}
	if ( @$rqs ) {
	    # response body not done yet
	    %TRACE && ($rqs->[-1]{obj}||$self)->xtrace("response body not done but eof");
	    ($rqs->[-1]{obj}||$self)->fatal('eof but response body not done',
		1,$time);
	    pop(@$rqs);
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
	    ($obj|$self)->in_junk(1,$1,0,$time);
	}

	# no response header yet, check if data contains it
	if ( $data =~s{( \A
	    HTTP/(1\.[01])[\040\t]+          # version
	    (\d\d\d)                         # code
	    (?:[\040\t]+([^\r\n]*))?         # reason
	    \r?\n
	    ([^\r\n].*?\n)?                  # fields
	    \r?\n                            # empty line
	)}{}sxi) {
	    my ($hdr,$version,$code,$reason) = ($1,$2,$3,$4);
	    my %kv;
	    my $bad = _parse_hdrfields($5,\%kv);
	    %TRACE && ($obj||$self)->xtrace("invalid response header data: $bad") 
		if $bad ne '';

	    my $n = length($hdr);
	    $bytes += $n;
	    $self->{offset}[1] += $n;

	    if ( $code >= 100 and $code <= 199 ) {
		# preliminary response, we are not done!
		$DEBUG && $self->xdebug("got preliminary response");
		$obj && $obj->in_response_header($hdr,$time,{
		    content_length => 0,
		    version => $version,
		    code => $code,
		    reason => $reason,
		    fields => \%kv,
		    $bad eq '' ? () : ( junk => $bad ),
		});

		# preliminary responses do not contain any body
		goto READ_DATA;
	    }

	    $rq->{state} |= RPHDR_DONE; # response header done

	    if ( my $cl = $kv{'content-length'} ) {
		if ( @$cl>1 and do { my %x; @x{@$cl} = (); keys(%x) } > 1 ) {
		    ($obj||$self)->fatal(
			"multiple different content-length header in request",
			1,$time);
		    $self->{error} = 1;
		    return $bytes;
		}
		$rq->{rpclen} = $cl->[0];
	    }

	    if ( $version >= 1.1 and 
		grep { lc($_) eq 'chunked' } @{ $kv{'transfer-encoding'} || [] } ) {
		$rq->{rpchunked} = 1;
	    }

	    if ( $rq->{method} eq 'CONNECT' and $code =~m{^2} ) {
		$self->{upgrade} = 1;
		$rq->{rpclen} = $rq->{rpchunked} = undef;
	    } elsif ( $METHODS_WITHOUT_RPBODY{ $rq->{method} }
		or $CODE_WITHOUT_RPBODY{$code} ) {
		# no content, even if specified
		$rq->{rpclen} = 0;
		$rq->{rpchunked} = undef;
	    }

	    if ( $rq->{rpchunked} and defined $rq->{rpclen} ) {
		# RFC2616 4.4.3: if both given ignore content-length
		%TRACE && ($obj||$self)->xtrace(
		    "response content-length and chunked given");
		$rq->{rpclen} = undef;
	    }

	    $DEBUG && $self->xdebug("got response header");
	    $obj && $obj->in_response_header($hdr,$time,{
		content_length => $rq->{rpclen},
		$rq->{rpchunked} ? ( chunked => 1 ):(),
		version => $version,
		code => $code,
		reason => $reason,
		fields => \%kv,
		$bad eq '' ? () : ( junk => $bad ),
	    });

	    # if no body invoke hook with empty body and eof
	    if ( defined $rq->{rpclen} and $rq->{rpclen} == 0 ) {
		# clen == 0 -> body done
		$DEBUG && $self->xdebug("no response body");
		$obj && $obj->in_response_body('',1,$time);
		pop(@$rqs);
		goto READ_DATA;
	    }

	    if ( ! $rq->{rpchunked} && ! $rq->{rpclen} ) {
		$rq->{state} |= RPBDY_DONE; # body done when eof
	    }

	} elsif ( $data =~m{[^\n]\r?\n\r?\n}g ) {
	    ($obj||$self)->fatal( sprintf("invalid response header syntax '%s'",
		substr($data,0,pos($data))),1,$time);
	    $self->{error} = 1;
	    return $bytes;
	} elsif ( length($data) > 2**16 ) {
	    ($obj||$self)->fatal('response header too big',1,$time);
	    $self->{error} = 1;
	    reurn $bytes;
	} elsif ( $eof ) {
	    ($obj||$self)->fatal('eof in response header',1,$time);
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
		    $obj->in_response_body($body,1,$time) if $obj;
		    pop(@$rqs);
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
	} elsif ( ! $rq->{rpchunked} ) {
	    $DEBUG && $self->xdebug("read until eof");
	    $self->{offset}[1] += length($data);
	    $bytes += length($data);
	    $obj->in_response_body($data,$eof,$time) if $obj;
	    $data = '';
	    pop(@$rqs) if $eof; # request done
	    return $bytes;

	# Chunking: rfc2616, 3.6.1
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
		    $obj->in_chunk_header(1,$chdr,$time) if $obj;
		    $DEBUG && $self->xdebug(
			"got chunk header - want $rq->{rpclen} bytes");
		    if ( ! $rq->{rpclen} ) {
			# last chunk
			$rq->{rpchunked} = 3;
			$obj->in_response_body('',1,$time) if $obj;
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
		} elsif ( $data =~m{\n\r?\n} or length($data)>2**16 ) {
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
sub _parse_hdrfields {
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
        substr($hdr,0,pos($hdr),'');
        $bad .= $1 if $hdr =~s{\A([^\n]*)\n}{};
        goto parse;
    }
    return $bad;
}


sub new_request {
    my $self = shift;
    return $self->{upper_flow}->new_request(@_,$self)
}

# return number of open requests
sub open_requests {
    my $self = shift;
    return 0 + @{$self->{requests}};
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
    $DEBUG or return;
    my $self = shift;
    my $m = $self->{meta};
    $self->xdebug("%s.%d -> %s.%d",
	$m->{saddr},$m->{sport},$m->{daddr},$m->{dport});
    my $rqs = $self->{requests};
    for( my $i=0;$i<@$rqs;$i++) {
	$self->xdebug("request#$i state=%05b %s",
	    $rqs->[$i]{state},$rqs->[$i]{info});
    }
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

=item new_connection($meta) - this returns an object for the connection

=item $connection->in($dir,$data,$eof,$time)

Processes new data and returns number of bytes processed.

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

=item fields - (key => \@values) hash of header fields

=item junk - invalid data found in header fields part

=item content_length - length of request body

=item chunked - true if body uses transfer encoding chunked

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

=back

=item $request->in_request_body($data,$eof,$time)

Called for a chunk of data of the request body.
$eof is true if this is the last chunk.
If no request body is given it will be once called with '' as data,
except for CONNECT, Upgrade etc where there cannot be a body.

$data can be C<< [ 'gap' => $len ] >> if the input to this
layer were gaps.

=item $request->in_response_body($data,$eof,$time)

Called for a chunk of data of the response body.
$eof is true if this is the last chunk.
It will be called with data '' and eof true if no body is given or if the last
chunk of chunked encoding was found, except for CONNECT, Upgrade etc where there
cannot be a body.

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

Will be called for any data after successful CONNECT or Upgrade, Websockets...
C<$dir> is 0 for data from client, 1 for data from server.

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

dumps the state of the open connections via xdebug

=item $connection->offset($dir)

returns the current offset in the data stream, that is the position
behind the within the in_* methods forwarded data.

=item $connection->open_requests

returns the number of open requests, if any.

=back

=head1 LIMITS

C<100 Continue>, C<101 Upgrade> are not yet implemented.
