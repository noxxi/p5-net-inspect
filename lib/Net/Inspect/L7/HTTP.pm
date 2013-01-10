############################################################################
# finds HTTP requests + responses in tcp connection
# chunked HTTP responses are supported
############################################################################
use strict;
use warnings;
package Net::Inspect::L7::HTTP;
use base 'Net::Inspect::Flow';
use Net::Inspect::Debug qw(:DEFAULT $DEBUG);
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

# common error: "Last Modified" instead of "Last-Modified"
# squid seems to just strip invalid headers, try the same
my $xtoken = qr{[^()<>@,;:\\"/\[\]?={}\x00-\x20\x7f-\xff][^:[:^print:]]*};

sub guess_protocol {
    my ($self,$guess,$dir,$data,$eof,$time,$meta) = @_;

    if ( $dir == 0 ) {
	my $rp = $self->{replay} ||= [];
	push @$rp,[$data,$eof,$time];
	my $buf = join('',map { $_->[0] } @$rp);
	if ( $buf =~m{
	    \A[\r\n]*
	    [A-Z]{2,20}\040{1,3}\S+\040{1,3}HTTP/1\.[01]\r?\n # request
	    (?:$xtoken:.*\r?\n(?:[\t\040].*\r?\n)* )*       # field:..+cont
	    \r?\n                                             # empty line
	}x) {
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
    $self->xdebug("got %d bytes from %d, eof=%d",length($data),$dir,$eof);
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
	$rqs->[0]{state} |= RQBDY_DONE if ! $rqs->[0]{rqclen};
	return $len;
    }

    READ_DATA:

    if ($self->{error}) {
	$self->xdebug("no more data because of server side error");
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
	$self->xdebug("no more data because of client side error");
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
	$self->xtrace("eat empty lines before request header");
    }

    if ( $data eq '' ) {
	$self->xdebug("no data, eof=$eof, bytes=$bytes");
	return $bytes if ! $eof; # need more data

	# handle EOF
	# check if we got request body for last request
	if ( @$rqs and not $rqs->[0]{state} & RQBDY_DONE ) {
	    # request body not done yet
	    ($rqs->[0]{obj}||$self)->xtrace("request body not done but eof");
	    ($rqs->[0]{obj}||$self)->fatal('eof but request body not done',0,$time);
	    $rqs->[0]{state} |= RQ_ERROR;
	    return $bytes;
	}

	return $bytes; # request body done
    }

    # create new request if no open request or last open request has the
    # request body already done (pipelining)
    if ( ! @$rqs or $rqs->[0]{state} & RQBDY_DONE ) {
	$self->xdebug("create new request");
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
	    rpchunked => undef,  # chunked mode for response: undef|1|2|3
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

	$self->xdebug("need to read request header");
	if ( $data =~m{ \A
	    (([A-Z]{2,20})\040{1,3}(\S+)\040{1,3}HTTP/(1\.[01])\r?\n) # request
	    ((?:$xtoken:.*\r?\n(?:[\t\040].*\r?\n)* )*)               # field:..+cont
	    (\r?\n)                                                   # empty line
	}xg) {
	    my ($first,$kv,$empty) = ($1,$5,$6);
	    $rq->{method} = $2;
	    $rq->{info} = "$2 $3 HTTP/$4";
	    $self->xdebug("got request header $rq->{info}");
	    my $n = pos($data);
	    $self->{offset}[0] += $n;
	    $bytes += $n;
	    substr($data,0,$n,'');
	    $rq->{state} |= RQHDR_DONE; # rqhdr done

	    my %kv = _parse_hdrfields(\$kv,$obj||$self);
	    my $hdr = $first.$kv.$empty;

	    if ( my $cl = $kv{'content-length'} ) {
		if ( @$cl>1 and do { my %x; @x{@$cl} = (); keys(%x) } > 1 ) {
		    ($obj||$self)->fatal(
			"multiple different content-length header in request",
			0,$time);
		    $rq->{state} |= RQ_ERROR;
		    return $bytes;
		}
		$rq->{rqclen} = $cl->[0];
		$self->xdebug(
		    "set content-length to $rq->{rqclen} from header");
	    }

	    if ( $rq->{method} =~m{^(?:HEAD|GET|CONNECT)$} ) {
		if ( $rq->{rqclen} ) {
		    ($obj||$self)->fatal(
			"no body allowed with method $rq->{method}",0,$time);
		    $rq->{state} |= RQ_ERROR;
		    return $bytes;
		}
		$rq->{rqclen} = ( $rq->{method} eq 'CONNECT' ) ? undef : 0;
	    } else {
		# if not given content-length is considered 0
		# TODO support chunked encoding from client to server
		$rq->{rqclen} ||= 0;
	    }

	    $obj->in_request_header($hdr,$time) if $obj;

	    if ( defined $rq->{rqclen} and $rq->{rqclen} == 0 ) {
		$self->xdebug("no content-length - request body done");
		# no clen - body done
		$rq->{state} |= RQBDY_DONE;
		$obj->in_request_body('',1,$time) if $obj;
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
	    $self->xdebug("need more bytes for request header");
	    return $bytes;
	}
    }

    # read request body if not done
    if ( $data ne '' and not $rq->{state} & RQBDY_DONE ) {
	# request body
	my $l = length($data);
	if ( $l >= $rq->{rqclen} ) {
	    $self->xdebug(
		"got all request body data $l >= $rq->{rqclen} obj=$obj");
	    # got all request body
	    my $body = substr($data,0,$rq->{rqclen},'');
	    $self->{offset}[0] += $rq->{rqclen};
	    $bytes += $rq->{rqclen};
	    $rq->{rqclen} = 0;
	    $rq->{state} |= RQBDY_DONE; # req body done
	    $obj->in_request_body($body,1,$time) if $obj;
	} else {
	    $self->xdebug("got part of request body data $l < $rq->{rqclen}");
	    # only part
	    my $body = substr($data,0,$l,'');
	    $self->{offset}[0] += $l;
	    $bytes += $l;
	    $rq->{rqclen} -= $l;
	    $obj->in_request_body($body,0,$time) if $obj;
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
	$rqs->[-1]{rqclen} -= $len;
	if ( ! $rqs->[-1]{rqclen} && !  $rqs->[-1]{rpchunked} ) {
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
	$self->xdebug("no more data, eof=$eof bytes=$bytes");
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
	    ($rqs->[-1]{obj}||$self)->xtrace("response body not done but eof");
	    ($rqs->[-1]{obj}||$self)->fatal('eof but response body not done',
		1,$time);
	    pop(@$rqs);
	    return $bytes;
	}

	return $bytes; # done
    }

    if ( ! @$rqs ) {
	$self->fatal('data from server w/o request',1,$time);
	$self->{error} = 1;
	return $bytes;
    }

    my $rq = $rqs->[-1];
    my $obj = $rq->{obj};

    # read response header if not done
    if ( not $rq->{state} & RPHDR_DONE ) {
	$self->xdebug("response header not read yet");

	# leading newlines at beginning of response are legally ignored junk
	if ( $data =~s{\A([\r\n]+)}{} ) {
	    ($obj|$self)->in_junk(1,$1,0,$time);
	}

	# no response header yet, check if data contains it
	if ( $data =~m{ \A[\r\n]*
	    (HTTP/1\.[01]\040{1,3}(\d\d\d).*\n)             # HTTP/1.0 200 ..
	    ((?:$xtoken:.*\r?\n(?:[\t\040].*\r?\n)* )*)     # field:..+cont
	    (\r?\n)                                         # empty line
	}xg) {
	    my ($first,$code,$kv,$empty) = ($1,$2,$3,$4);
	    my $n = pos($data);
	    $bytes += $n;
	    $self->{offset}[1] += $n;
	    substr($data,0,$n,'');
	    $rq->{state} |= RPHDR_DONE; # response header done

	    my %kv = _parse_hdrfields(\$kv,$obj||$self);
	    my $hdr = $first.$kv.$empty;

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

	    if ( grep { m{\bchunked\b} } @{ $kv{'transfer-encoding'} || [] } ) {
		$rq->{rpchunked} = 1;
	    }

	    if ( $rq->{method} eq 'CONNECT' and $code =~m{^2} ) {
		$self->{upgrade} = 1;
		undef $rq->{rpchunked};
		$rq->{rpclen} = undef;
	    } elsif ( $rq->{method} eq 'HEAD'
		or $code =~m{^(?:204|205|304)$} ) {
		# no content, even if specified
		$rq->{rpclen} = 0;
		undef $rq->{rpchunked};
	    }

	    if ( $rq->{rpchunked} and defined $rq->{rpclen} ) {
		# RFC2616 4.4.3: if both given ignore content-length
		($obj||$self)->xtrace("content-length and chunked given");
		$rq->{rpclen} = undef;
	    }

	    $self->xdebug("got response header");
	    $obj->in_response_header($hdr,$time) if $obj;

	    # if no body invoke hook with empty body and eof
	    if ( defined $rq->{rpclen} and $rq->{rpclen} == 0 ) {
		# clen == 0 -> body done
		$self->xdebug("no response body");
		$obj->in_response_body('',1,$time) if $obj;
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
	    $self->xdebug("need more data for response header");
	    return $bytes;
	}
    }

    # read response body
    if ( $data ne '' ) {
	# response body
	$self->xdebug("response body data");

	# have content-length or within chunk
	if ( my $want = $rq->{rpclen} ) {
	    # called for content-length or to read content from chunk
	    # with known length
	    my $l = length($data);
	    if ( $l >= $want ) {
		$self->xdebug("need $want bytes, got all($l)");
		# got all response body
		my $body = substr($data,0,$want,'');
		$self->{offset}[1] += $want;
		$bytes += $want;
		$rq->{rpclen} = 0;
		if ( ! $rq->{rpchunked} ) {
		    # request done
		    $obj->in_response_body($body,1,$time) if $obj;
		    pop(@$rqs);
		    goto READ_DATA;
		} else {
		    $obj->in_response_body($body,0,$time) if $obj;
		    $rq->{rpchunked} = 2; # get CRLF after chunk
		}
	    } else {
		# only part
		$self->xdebug("need $want bytes, got only $l");
		my $body = substr($data,0,$l,'');
		$self->{offset}[1] += $l;
		$bytes += $l;
		$rq->{rpclen} -= $l;
		$obj->in_response_body($body,0,$time) if $obj;
	    }

	# no content-length, no chunk: must read until eof
	} elsif ( ! $rq->{rpchunked} ) {
	    $self->xdebug("read until eof");
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
		$self->xdebug("want CRLF after chunk");
		if ( $data =~m{\A\r?\n}g ) {
		    my $n = pos($data);
		    $self->{offset}[1] += $n;
		    $bytes += $n;
		    substr($data,0,$n,'');
		    $rq->{rpchunked} = 1; # get next chunk header
		    $self->xdebug("got CRLF after chunk");
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
		$self->xdebug("want chunk header");
		if ( $data =~m{\A([\da-fA-F]+)[ \t]*(?:;.*)?\r?\n}g ) {
		    $rq->{rpclen} = hex($1);
		    my $chdr = substr($data,0,pos($data),'');
		    $self->{offset}[1] += length($chdr);
		    $bytes += length($chdr);
		    $obj->in_chunk_header($chdr,$time) if $obj;
		    $self->xdebug(
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
		$self->xdebug("want chunk trailer");
		if ( $data =~m{\A
		    (?:\w[\w\-]*:.*\r?\n(?:[\t\040].*\r?\n)* )*  # field:..+cont
		    \r?\n
		}xg) {
		    $self->xdebug("got chunk trailer");
		    my $trailer = substr($data,0,pos($data),'');
		    $self->{offset}[1] += length($trailer);
		    $bytes += length($trailer);
		    $obj->in_chunk_trailer($trailer,$time) if $obj;
		    pop(@$rqs); # request done
		    goto READ_DATA;
		} elsif ( $data =~m{\n\r?\n} or length($data)>2**16 ) {
		    ($obj||$self)->fatal("invalid chunk trailer",1,$time);
		    $self->{error} = 1;
		    return $bytes;
		} else {
		    # need more
		    $self->xdebug("need more bytes for chunk trailer");
		    return $bytes
		}
	    }
	}
    }

    goto READ_DATA;
}

# parse and normalize header
sub _parse_hdrfields {
    my ($rkv,$obj) = @_;
    my @kv = $$rkv =~m{\G($xtoken)(:)(.*\r?\n(?:[\t\040].*\r?\n)*)}g;
    my %kv;
    for(my $i=0;$i<@kv;$i+=3) {
	if ( $kv[$i] !~ m{^$token$} ) {
	    $obj->xtrace("invalid header field '$kv[$i]'");
	    splice(@kv,$i,3);
	    $$rkv = join('',@kv);
	    redo;
	}
	my $v = $kv[$i+2];
	$v =~s{[\r\n]+}{ };
	$v =~s{^\s+}{};
	$v =~s{\s+$}{};
	push @{ $kv{lc($kv[$i])} }, $v;
    }
    return %kv;
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
    $self->xtrace($reason);
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

=item $request->in_request_header($header,$time)

Called when the full request header is read.
$header is the string of the header.

=item $request->in_response_header($header,$time)

Called when the full response header is read.
$header is the string of the header.

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

=item $request->in_chunk_header($header,$time)

will be called with the chunk header for chunked encoding.
Usually one is not interested in the chunk framing, only in the content so that
this method will be empty.
Will be called before the chunk data.

=item $request->in_chunk_trailer($trailer,$time)

will be called with the chunk trailer for chunked encoding.
Usually one is not interested in the chunk framing, only in the content so that
this method will be empty.
Will be called after in_response_body got called with eof true.

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
