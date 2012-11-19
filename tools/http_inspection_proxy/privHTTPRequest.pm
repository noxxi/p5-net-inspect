
############################################################################
# Request
############################################################################

use strict;
use warnings;

package privHTTPRequest;
use base 'Net::Inspect::L7::HTTP::Request::InspectChain';
use fields (
    'connected',  # is upstream already connected?
    'chunked',    # set if we do chunked output
    'acct',       # some accounting data
    'imp_filter',
);
use Net::Inspect::Debug qw(debug $DEBUG);


sub new_request {
    my ($self,$meta,$conn) = @_;
    my $obj = $self->SUPER::new_request($meta,$conn);
    $obj->{acct} = { Id => $obj->id };
    if ( my $factory = $conn->{imp_factory} ) {
	$obj->{imp_filter} = $factory->new_analyzer( $obj,$meta);
    }
    return $obj;
}

sub DESTROY {
    my $self = shift;
    my $relay = $self->{conn}{relay} or return;
    $relay->account(%{ $self->{meta}}, %{ $self->{acct}});
}

sub in_request_header {
    my $self = shift;

    # if we we have an open request inside this connection defer
    # the call and disable reading from client
    if ( my $spool = $self->{conn}{spool} ) {
	push @$spool,['in_request_header',@_];
	$self->{conn}{relay}->mask(0,r=>0);
	return 1;
    }

    my ($hdr,$time) = @_;
    my ($method) = $hdr =~m{^(\w+)};
    if ( $method !~ m{^(?:GET|POST|PUT|DELETE|TRACE|OPTIONS|CONNECT)$} ) {
	$self->fatal("cannot handle method $method");
	return 1;
    }

    $self->{acct}{start} = $time;

    $self->add_hooks({
	name => 'fwd-data',
	request_header => \&_inrqhdr_connect_upstream,
	request_body => sub {
	    my ($self,$data,$eof,$time) = @_;
	    _send_and_remove($self,1,$data,$time) if $$data ne '';
	    return '';
	},
	response_header => sub {
	    my ($self,$hdr,$time) = @_;
	    $self->{acct}{code} = $1 if $$hdr =~m{\AHTTP/1\.\d\s+(\d+)};
	    _send($self,0,$$hdr,$time);
	    return 0;
	},
	response_body => sub {
	    my ($self,$data,$eof,$time) = @_;
	    $self->xdebug("response_body len=".length($$data));
	    _send_and_remove($self,0,$data,$time) if $$data ne '';
	    return '';
	},
	chunk_header => sub {
	    my ($self,$hdr,$time) = @_;
	    return if $$hdr eq '';
	    # add chunk-end CRLF unless it is the first chunk header
	    _send($self,0, $self->{chunked}++ ? "\r\n$$hdr" : $$hdr );
	    return 1;
	},
	chunk_trailer => sub {
	    my ($self,$trailer,$time) = @_;
	    return if $$trailer eq '';
	    _send($self,0,$$trailer,$time);
	    return 1;
	},
    });

    $self->{conn}{spool} ||= [];
    return $self->SUPER::in_request_header($hdr,$time);
}

sub in_request_body {
    my $self = shift;
    my $conn = $self->{conn};

    # defer call if we have another open request or if the current request
    # has no connected upstream yet
    my $spool = $conn->{spool} ||= ! $self->{connected} && [];
    if ($spool) {
	$self->xdebug("spooling request body");
	$conn->{relay}->mask(0,r=>0) if $_[1] ne ''; # data given
	push @$spool,['in_request_body',@_];
	return 1;
    }

    return $self->SUPER::in_request_body(@_);
}

sub in_data {
    my ($self,$from,$data,$eof,$time) = @_;
    # forward data to other side
    my $to = $from?0:1;
    $self->xdebug("%s bytes from %s to %s",length($data),$from,$to);
    _send($self,$to,$data) if $data ne '';
    if ($eof) {
	$self->{conn}{relay}->shutdown($from,0);
	# the first shutdown might cause the relay to close
	$self->{conn}{relay}->shutdown($to,1) if $self->{conn}{relay};
    }
    return length($data);
}

sub fatal {
    my ($self,$reason) = @_;
    my $conn = $self->{conn};
    warn "[fatal] ".$self->id." $reason\n";
    $self->{conn}{relay}->close if $self->{conn};
}

sub in_response_body {
    my ($self,$data,$eof,$time) = @_;
    $self->xdebug("in_response_body len=".length($data));
    my $rv = $self->SUPER::in_response_body($data,$eof,$time);
    if ( $eof ) {
	$self->xdebug("got eof in response");
	my $rphdr = $self->response_header;
	if ( ! defined $rphdr->content_length and
	    ($rphdr->header('Transfer-Encoding')||'') !~m{\bchunked\b} ) {
	    # no content-length given and not chunked
	    # request need to be closed with eof
	    $self->{conn}{relay}->close;
	    return $rv;
	}

	# any more spooled requests (pipelining)?
	_call_spooled($self);
    }
    return $rv
}


sub _inrqhdr_connect_upstream {
    my ($self,$hdr,$time) = @_;
    my $req = $self->request_header;
    my $method = $req->method;
    my $uri = $req->uri;

    $self->{acct}{method} = $method;
    $self->{acct}{uri} = $uri;

    my $hdr_changed = 0;
    my ($proto,$host,$port,$page);
    if ( $method eq 'CONNECT' ) {
	($host,$port) = $uri =~m{^(.*?)(?:\:(\d+))?$};
	$port ||= 443;
	$host =~s{^\[(.*)\]$}{$1};
	$proto = 'https';
	$page = '';
	# dont' forward anything, but don't change header :)
	$hdr = \( '' );
    } else {
	($proto,$host,$port,$page) = ($1,$2,$3||80,$4)
	    if $uri =~m{^(?:(\w+)://([^/\s]+?)(?::(\d+))?)?(/.*|$)};
	($proto,$host,$port) = ('http',$2,$3||80)
	    if ! $proto and
	    $req->header('Host') =~m{^(\S+?)(?:(\d+))?$};
	$proto or return $self->fatal('bad request: '.$$hdr),undef;
	return $self->fatal("bad proto: $proto"),undef
	    if $proto ne 'http';

	# rewrite method://host/page to /page
	$hdr_changed = 1 if $$hdr =~s{\A(\w+[ \t]+)(\w+://[^/]+)}{$1};
    }

    $self->xdebug("new request $method $proto://$host:$port$page");
    my $connect_cb = sub {
	$self->{connected} = 1;
	$self->{acct}{ctime} = AnyEvent->now - $time;
	if ($$hdr ne '') {
	    _send($self,1,$$hdr);
	} else {
	    # successful Upgrade, CONNECT.. - send OK to client
	    # fake that it came from server so that the state gets
	    # maintained in Net::Inspect::L7::HTTP
	    $self->{conn}->in(1,"HTTP/1.0 200 OK\r\n\r\n",0,$time);
	}
	$self->{conn}{relay}->mask(1,r=>1);
	_call_spooled($self, { in_request_body => 1 });
    };
    $self->{conn}{relay}->connect(1,$host,$port,$connect_cb);
    return $hdr_changed;
}

sub _call_spooled {
    my ($self,$filter) = @_;
    my $spool = $self->{conn}{spool} or return;
    $self->{conn}{spool} = undef;

    while ( @$spool and ! $self->{conn}{spool} ) {
	my ($method,@arg) = @{ $spool->[0] };
	if ( ! $filter or $filter->{$method} ) {
	    shift(@$spool);
	    $self->$method(@arg);
	} else {
	    last;
	}
    }

    # put unfinished requests back into spool
    unshift @{ $self->{conn}{spool} }, @$spool if @$spool;

    # enable read on client side again if nothing in spool
    $self->{conn}{relay}->mask(0,r=>1) if ! $self->{conn}{spool};
}



sub _send {
    my ($self,$to,$data) = @_;
    my $from = $to ? 0:1;
    if ( my $filter = $self->{imp_filter} ) {
	$filter->data($from,$data);
    } else {
	forward($self,$from,$data,$to);
    }
}

sub _send_and_remove {
    my ($self,$to,$dataref) = @_;
    _send($self,$to,$$dataref);
    $$dataref = '';
}

sub forward {
    my ($self,$from,$data,$to) = @_;
    $to //= $from ? 0:1;
    $self->{acct}{"out$to"} += length($data);
    $self->{conn}{relay}->forward($from,$to,$data);
}

sub acct {
    my ($self,$k,$v) = @_;
    $self->{acct}{$k} = $v
}

1;

